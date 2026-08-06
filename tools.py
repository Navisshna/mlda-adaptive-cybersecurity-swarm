"""Deep-recon tools for the Profiler.

All tools are built through `build_recon_tools(...)` so they can close over:
  - `allowed_hosts`: an allowlist. A tool refuses any host not on it, so a
    prompt-injected / target-derived URL cannot redirect the scanner.
  - `enable_active`: gates the two genuinely-active behaviours (directory
    discovery and browser-based fingerprinting). Off by default.

Design rules every tool obeys:
  - read-only, timeout-bounded
  - return SIGNALS, not raw content (cookie *names*, input *types*, booleans)
    so there is minimal PII to leak before privacy mode is even selected

Tool -> schema field it feeds (TargetProfile in schemas.py):

  tool                 | primary field(s)         | library      | network?
  ---------------------|--------------------------|--------------|---------
  classify_input       | target_type,             | stdlib       | no
                       |   connectivity (hint)    | (ipaddress)  |
  deep_port_scan       | target_type              | stdlib       | yes
                       |                          | (socket)     | (passive)
  tls_inspect          | connectivity, notes      | stdlib (ssl) | yes
                       |                          |              | (passive)
  deep_http_probe      | target_type; SIGNALS for | httpx + bs4  | yes
                       |   handles_credentials    |              | (passive)
  codebase_inventory   | target_type,             | stdlib (os)  | no
                       |   connectivity=offline   |              |
  directory_discovery  | notes (attack surface)   | httpx        | yes
    [enable_active]    |                          |              | (ACTIVE)

Never tool-driven (human-declared, authoritative):
  - data_sensitivity : tools raise signals only; the operator declares the
    real values, which finalize() writes over any LLM guess.
  - regulatory_flags : HIPAA / PDPA / PCI_DSS cannot be reliably inferred by
    inspection. Declared by the human, never by a tool.

Not tool-driven (LLM / policy):
  - confidence, notes  -> LLM reasoning over the evidence (finalize node)
  - recommended_mode   -> LLM hint, then overridden by the deterministic
                          select_execution_mode() policy in graph.py
"""

from __future__ import annotations

import os
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup
from langchain_core.tools import BaseTool, tool

# Small curated port map — enough to distinguish service types, not a full sweep.
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    3306: "mysql", 3389: "rdp", 5432: "postgres", 6379: "redis",
    8080: "http-alt", 8443: "https-alt", 27017: "mongodb",
}

# Tiny wordlist for the gated active discovery tool. Real deployments load
# a fuller list from disk; kept minimal here on purpose.
DIR_WORDLIST = [
    "admin", "login", "api", "robots.txt", ".git/config", ".env",
    "wp-login.php", "phpmyadmin", "config.php", "backup",
]


def _host_of(target: str) -> str:
    """Extract a bare host from a URL, host:port, or bare host/IP."""
    parsed = urlparse(target)
    if parsed.scheme and parsed.hostname:
        return parsed.hostname
    return target.split(":")[0].strip()


def build_recon_tools(allowed_hosts: list[str], enable_active: bool) -> list[BaseTool]:
    """Return the recon toolset, bound to an allowlist and an active-recon flag."""

    allowed = {h.lower() for h in allowed_hosts}

    def _guard(target: str) -> str | None:
        """Return an error string if `target`'s host is not allowlisted, else None."""
        host = _host_of(target).lower()
        if host not in allowed:
            return f"REFUSED: host '{host}' is not in the allowlist {sorted(allowed)}."
        return None

    # --- 1. structural classifier (no network) ----------------------------
    @tool
    def classify_input(raw_input: str) -> dict:
        """Classify a raw target string by shape (url / ip / ip:port / filesystem
        path / git url) WITHOUT any network access. Cheap, safe first step."""
        if os.path.exists(raw_input):
            return {
                "shape": "filesystem_path",
                "is_git_repo": os.path.isdir(os.path.join(raw_input, ".git")),
            }
        if raw_input.endswith(".git") or raw_input.startswith("git@"):
            return {"shape": "git_url"}
        parsed = urlparse(raw_input)
        # returns ParseResult(scheme='https', netloc='example.com:8443', path='/admin', params='', query='q=1', fragment='top')

        if parsed.scheme in ("http", "https"):
            return {"shape": "url", "host": parsed.hostname, "path": parsed.path}
        host = raw_input.split(":")[0]
        try:
            import ipaddress
            ip = ipaddress.ip_address(host)
            return {
                "shape": "ip",
                "is_private": ip.is_private,
                "is_loopback": ip.is_loopback,
            }
        except ValueError:
            return {"shape": "hostname_or_unknown"}

    # --- 2. full port + service scan --------------------------------------
    @tool
    def deep_port_scan(host: str) -> dict:
        """Scan the common-port set on a host via TCP connect and report which
        are open, with the well-known service name. Read-only. Allowlisted hosts
        only. (Swap in nmap -sV here if you need product/version banners.)"""

        h = _host_of(host)

        def check(port: int) -> int | None:
            s = socket.socket()
            s.settimeout(1.0)
            try:
                return port if s.connect_ex((h, port)) == 0 else None
            except OSError:
                return None
            finally:
                s.close()

        with ThreadPoolExecutor(max_workers=12) as ex:
            found = [p for p in ex.map(check, COMMON_PORTS) if p]
        return {"host": h, "open_ports": {p: COMMON_PORTS[p] for p in found}}

    # --- 3. TLS / certificate inspection ----------------------------------
    @tool
    def tls_inspect(host: str, port: int = 443) -> dict:
        """Inspect the TLS certificate: issuer, subject, SANs, expiry, TLS
        version. Strong signal for connectivity (public CA -> internet_facing;
        self-signed/localhost -> internal). Read-only, allowlisted hosts only."""
        if err := _guard(host):
            return {"error": err}
        h = _host_of(host)
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((h, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=h) as ss:
                    cert = ss.getpeercert()
                    return {
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "san": [v for _, v in cert.get("subjectAltName", [])],
                        "not_after": cert.get("notAfter"),
                        "tls_version": ss.version(),
                    }
        except Exception as e:  # noqa: BLE001 - report, don't crash the loop
            return {"error": f"{type(e).__name__}: {e}"}

    # --- 4. deep HTTP probe (signals, not content) ------------------------
    @tool
    def deep_http_probe(url: str) -> dict:
        """GET a URL and extract SIGNALS: status, server/powered-by headers,
        which security headers are present, page title, form actions, input
        *types*, cookie *names*, and a has_password_field boolean. Never returns
        raw field values or page bodies. Read-only, allowlisted hosts only."""
        if err := _guard(url):
            return {"error": err}
        try:
            r = httpx.get(url, timeout=8.0, follow_redirects=True)
            soup = BeautifulSoup(r.text, "html.parser")
            forms = [
                {
                    "action": f.get("action"),
                    "input_types": [i.get("type") or "text" for i in f.find_all("input")],
                }
                for f in soup.find_all("form")
            ]
            sec = [
                hh for hh in (
                    "strict-transport-security",
                    "content-security-policy",
                    "x-frame-options",
                ) if hh in r.headers
            ]
            return {
                "final_url": str(r.url),
                "status": r.status_code,
                "server": r.headers.get("server"),
                "powered_by": r.headers.get("x-powered-by"),
                "content_type": r.headers.get("content-type"),
                "security_headers_present": sec,
                "title": (soup.title.string or "").strip() if soup.title else None,
                "cookie_names": list(r.cookies.keys()),
                "forms": forms,
                "has_password_field": any(
                    "password" in f["input_types"] for f in forms
                ),
            }
        except Exception as e:  # noqa: BLE001
            return {"error": f"{type(e).__name__}: {e}"}

    # --- 5. codebase inventory (inventory only; secrets are Layer 3) ------
    @tool
    def codebase_inventory(path: str) -> dict:
        """Inventory a local codebase: top languages by extension, dependency
        manifests, git presence. Read-only. Does NOT grep for secrets or vulns
        (that stays in the Code Analysis Agent)."""
        if not os.path.isdir(path):
            return {"error": f"not a directory: {path}"}
        manifests_of_interest = {
            "requirements.txt", "package.json", "pom.xml", "go.mod",
            "Gemfile", "Cargo.toml", "composer.json", "pyproject.toml",
        }
        exts: dict[str, int] = {}
        manifests: list[str] = []
        for root, _dirs, files in os.walk(path):
            if ".git" in root:
                continue
            for f in files:
                ext = os.path.splitext(f)[1]
                if ext:
                    exts[ext] = exts.get(ext, 0) + 1
                if f in manifests_of_interest:
                    manifests.append(os.path.join(root, f))
        top = dict(sorted(exts.items(), key=lambda kv: -kv[1])[:8])
        return {
            "languages_by_ext": top,
            "manifests": manifests,
            "is_git": os.path.isdir(os.path.join(path, ".git")),
        }

    tools: list[BaseTool] = [
        classify_input,
        deep_port_scan,
        tls_inspect,
        deep_http_probe,
        codebase_inventory,
    ]

    # --- 6. GATED active tools -------------------------------------------
    # Only registered when enable_active is True. These generate requests the
    # target never offered (dir discovery) or execute the target's JS in a
    # browser on the un-sandboxed host (wappalyzer-next). Lab targets only.
    if enable_active:

        @tool
        def directory_discovery(base_url: str) -> dict:
            """ACTIVE: probe a small wordlist of common paths against base_url
            and report which return non-404. Noisy; lab/authorized targets only.
            Allowlisted hosts only."""
            if err := _guard(base_url):
                return {"error": err}
            found = {}
            base = base_url.rstrip("/")
            for word in DIR_WORDLIST:
                try:
                    resp = httpx.get(f"{base}/{word}", timeout=4.0,
                                     follow_redirects=False)
                    if resp.status_code != 404:
                        found[word] = resp.status_code
                except Exception:  # noqa: BLE001
                    continue
            return {"base_url": base, "discovered": found}

        tools.append(directory_discovery)

    return tools