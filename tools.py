import os
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
import ipaddress


import httpx
from bs4 import BeautifulSoup

from langchain.tools import tool

COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    3306: "mysql", 3389: "rdp", 5432: "postgres", 6379: "redis",
    8080: "http-alt", 8443: "https-alt", 27017: "mongodb"}


def _host_of(target: str) -> str:
    """Extract a bare host from a URL, host:port, or bare host/IP."""
    parsed = urlparse(target)
    if parsed.scheme and parsed.hostname:
        return parsed.hostname
    return target.split(":")[0].strip()


@tool
def classify_input(raw_input: str) -> dict:
        """Classify a raw target string by shape (url / ip / ip:port / filesystem
        path / git url) WITHOUT any network access. Cheap, safe first step."""



        #CASE 1: normal file path on disk, with checks if its a gitrepo

        if os.path.exists(raw_input):
            return {
                "shape": "filesystem_path",
                "is_git_repo": os.path.isdir(os.path.join(raw_input, ".git")),
            }

        #CASE 2 : git url
        if raw_input.endswith(".git") or raw_input.startswith("git@"):
            return {"shape": "git_url"}

        #CASE 3: URL
        parsed = urlparse(raw_input)
        # returns ParseResult(scheme='https', netloc='example.com:8443', path='/admin', params='', query='q=1', fragment='top')

        if parsed.scheme in ("http", "https"):
            out= {"shape": "url", "host": parsed.hostname, "path": parsed.path}
           
            try:
                ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
                out["is_private"] = ip.is_private
                out["is_loopback"] = ip.is_loopback
            except (ValueError, OSError, TypeError):
                pass


            return out


        #CASE: IP IPV-4 case only

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

@tool
def deep_port_scan(host: str) -> dict:
        """Scan the common-port set on a host via TCP connect and report which
        are open, with the well-known service name. Read-only. Allowlisted hosts
        only. (Swap in nmap -sV here if you need product/version banners.)"""

        # open (somoneone is listening and accepts the connection), close(instant reply with 'go away'), filtered (no reply at all)
        h = _host_of(host)

        def check(port: int) -> int | None:
            #socket establishes TCP connection
            s = socket.socket()
            s.settimeout(1.0)
            try:
                return port if s.connect_ex((h, port)) == 0 else None
            except OSError:
                return None
            finally:
                s.close()

        with ThreadPoolExecutor(max_workers=12) as ex:
            #map here returns iterator
            found = [p for p in ex.map(check, COMMON_PORTS) if p]
        return {"host": h, "open_ports": {p: COMMON_PORTS[p] for p in found}}

    # --- 3. TLS / certificate inspection ----------------------------------
@tool
def tls_inspect(host: str, port: int = 443) -> dict:
        """Inspect the TLS certificate: issuer, subject, SANs, expiry, TLS
        version. Strong signal for connectivity (public CA -> internet_facing;
        self-signed/localhost -> internal)."""
  
        h = _host_of(host)
        try:
            #ssl.SSLObject
            ctx = ssl.create_default_context()
            with socket.create_connection((h, port), timeout=5) as sock:
                #takes an exisiting standard network socket and upgrades to TLS socket
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
       
            "requirements.txt" , #py
            "pyproject.toml", #py
             "package.json",#js
              "pom.xml",#java
               "go.mod", #go
            "Gemfile", #ruby
             "Cargo.toml", #rust
              "composer.json"         #php
              }
        exts: dict[str, int] = {}
        #It's a language/dependency detector 
        # the manifest files are proxies for "what does this project depend on and what stack is it built with.
        manifests: list[str] = []
        for root, _dirs, files in os.walk(path):
            if ".git" in root:
                continue
            for f in files:
                #get the extension eg.py or md
                ext = os.path.splitext(f)[1]
                if ext:
                    exts[ext] = exts.get(ext, 0) + 1
                if f in manifests_of_interest:
                    manifests.append(os.path.join(root, f))
        #sort by decending
        top = dict(sorted(exts.items(), key=lambda kv: -kv[1])[:8])
        return {
            "languages_by_ext": top,
            "manifests": manifests,
            "is_git": os.path.isdir(os.path.join(path, ".git")),
        }

tools= [
        classify_input,
        deep_port_scan,
        tls_inspect,
        deep_http_probe,
        codebase_inventory,
    ]

