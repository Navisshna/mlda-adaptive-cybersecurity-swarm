"""Input security validator module for Profiler Agent.

Provides deterministic pre-execution threat screening against target inputs
and metadata for Threat Categories 1, 2, 4, and 7.
"""

from __future__ import annotations

import re
from urllib.parse import unquote, urlparse

# Unsafe schemes forbidden for profiling tools (Category 4)
UNSAFE_SCHEMES = {
    "file",
    "gopher",
    "dict",
    "javascript",
    "data",
    "ftp",
    "ldap",
    "php",
    "expect",
    "tftp",
    "sftp",
}

# Sensitive OS system path indicators (Category 2)
RESTRICTED_SYSTEM_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/proc/",
    "/sys/",
    "/dev/",
    "c:\\windows",
    "c:/windows",
    "system32",
    "c:\\boot.ini",
    "c:/boot.ini",
]

# Prompt injection keywords/patterns (Category 7)
PROMPT_INJECTION_PATTERNS = [
    re.compile(r"(?i)ignore\s+(all\s+)?(previous|prior)\s+instructions"),
    re.compile(r"(?i)override\s+(system\s+)?prompt"),
    re.compile(r"(?i)disregard\s+(all\s+)?above"),
    re.compile(r"(?i)system\s*:\s*set\s+"),
    re.compile(r"(?i)output\s+recommended_mode\s*="),
]


def validate_input(
    raw_input: str,
    declared_regulatory: list[str] | None = None,
) -> tuple[bool, str | None]:
    """Screen target input and declared metadata for malicious patterns.

    Returns:
        (is_malicious, block_reason)
        If clean: (False, None)
        If malicious: (True, "Explanation of threat")
    """
    if not raw_input or not isinstance(raw_input, str):
        return False, None

    cleaned_input = raw_input.strip()
    decoded_input = unquote(cleaned_input)

    # --- 1. Category 7: Prompt Injection Check (Metadata & raw_input) ---
    all_texts_to_check = [cleaned_input, decoded_input]
    if declared_regulatory:
        for reg in declared_regulatory:
            if isinstance(reg, str):
                all_texts_to_check.append(reg)

    for text in all_texts_to_check:
        for pat in PROMPT_INJECTION_PATTERNS:
            if pat.search(text):
                return (
                    True,
                    f"Prompt injection attempt detected in input/metadata: '{text[:80]}'",
                )

    # --- 2. Category 4: Unsafe URL Schemes ---
    parsed = urlparse(cleaned_input)
    if parsed.scheme:
        scheme = parsed.scheme.lower()
        if scheme in UNSAFE_SCHEMES:
            return (
                True,
                f"Unsafe URL scheme '{scheme}://' is forbidden for security profiling.",
            )
        if len(scheme) > 1 and scheme not in ("http", "https"):
            # Non-http(s) scheme check (ignoring 1-character Windows drive letters like C:\)
            return (
                True,
                f"Unsupported or unsafe scheme '{scheme}://' provided.",
            )

    # --- 3. Category 2: Directory / Path Traversal & System File Access ---
    lower_decoded = decoded_input.lower()
    lower_raw = cleaned_input.lower()

    # Traversal patterns
    if "../" in lower_decoded or "..\\" in lower_decoded or "..%2f" in lower_raw or "..%5c" in lower_raw:
        return (
            True,
            "Directory traversal payload ('../' or '..\\') detected in target input.",
        )

    # System file paths
    for res_path in RESTRICTED_SYSTEM_PATHS:
        if res_path in lower_decoded or res_path in lower_raw:
            return (
                True,
                f"Access to restricted system path '{res_path}' is blocked.",
            )

    # --- 4. Category 1: Command Injection Payload Check ---
    # Check for shell metacharacters: ;, |, $(), `, newlines, command substitution, redirection
    cmd_injection_patterns = [
        re.compile(r";\s*[a-zA-Z]"),           # e.g., ; cat, ; rm, ; id
        re.compile(r"\|\s*[a-zA-Z]"),           # e.g., | nc, | bash
        re.compile(r"`[^`]+`"),                  # e.g., `whoami`
        re.compile(r"\$\([^\)]+\)"),             # e.g., $(whoami)
        re.compile(r"[\r\n]\s*(cat|rm|ls|id|whoami|curl|nc|bash|sh)"), # Multiline payload
        re.compile(r">\s*/dev/null"),
    ]

    for pat in cmd_injection_patterns:
        if pat.search(cleaned_input) or pat.search(decoded_input):
            return (
                True,
                "Command injection payload detected in target input string.",
            )

    # Additional strict check for host/IP/path raw inputs with trailing shell commands
    if not parsed.scheme:
        # Bare input (not a URL) - check for shell metacharacters ;, |, `, $(), >
        if re.search(r"[;&|`>]|\$\(", cleaned_input):
            return (
                True,
                "Command injection characters (';', '|', '&', '`', '$()', '>') detected in target string.",
            )

    return False, None
