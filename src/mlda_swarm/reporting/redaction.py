from __future__ import annotations

import re
from typing import Any


REDACTED = "[REDACTED]"


# Fields whose values should always be hidden.
SENSITIVE_KEYS = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "client_secret",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "session_token",
    "auth_token",
    "authorization",
    "cookie",
    "session_cookie",
    "private_key",
}


def _normalize_key(key: str) -> str:
    """
    Normalize JSON/dictionary field names.

    Examples:
        API-Key -> api_key
        access-token -> access_token
    """
    return re.sub(
        r"[^a-z0-9]+",
        "_",
        key.lower(),
    ).strip("_")


def _is_sensitive_key(key: str) -> bool:
    """
    Check whether a dictionary/JSON field is sensitive.
    """
    normalized = _normalize_key(key)

    if normalized in SENSITIVE_KEYS:
        return True

    # Also catch names such as:
    # database_password
    # github_access_token
    # user_session_cookie
    sensitive_suffixes = (
        "_password",
        "_passwd",
        "_secret",
        "_api_key",
        "_access_token",
        "_refresh_token",
        "_session_token",
        "_auth_token",
        "_cookie",
        "_private_key",
    )

    return normalized.endswith(sensitive_suffixes)
SENSITIVE_PATTERNS = {
    "password": re.compile(
        r"(?i)"
        r"(\b(?:password|passwd|pwd)\b\s*[:=]\s*)"
        r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
    ),

    "api_key": re.compile(
        r"(?i)"
        r"(\bapi[_-]?key\b\s*[:=]\s*)"
        r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
    ),

    "secret": re.compile(
        r"(?i)"
        r"(\b(?:client[_-]?secret|secret)\b\s*[:=]\s*)"
        r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
    ),

    "bearer_token": re.compile(
        r"(?i)(\bbearer\s+)"
        r"[A-Za-z0-9._~+/=-]+"
    ),

    "jwt": re.compile(
        r"\beyJ[A-Za-z0-9_-]*\."
        r"[A-Za-z0-9_-]+\."
        r"[A-Za-z0-9_-]+\b"
    ),

    "private_key": re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
        r"[\s\S]*?"
        r"-----END [A-Z0-9 ]*PRIVATE KEY-----"
    ),
}
def redact_text(text: str) -> tuple[str, list[str]]:
    """
    Remove sensitive values from free text.

    Returns:
        tuple:
            sanitized text
            list of detected sensitive-data types
    """

    detected: list[str] = []

    # password=...
    if SENSITIVE_PATTERNS["password"].search(text):
        detected.append("password")
        text = SENSITIVE_PATTERNS["password"].sub(
            lambda match: match.group(1) + REDACTED,
            text,
        )

    # api_key=...
    if SENSITIVE_PATTERNS["api_key"].search(text):
        detected.append("api_key")
        text = SENSITIVE_PATTERNS["api_key"].sub(
            lambda match: match.group(1) + REDACTED,
            text,
        )

    # secret=...
    if SENSITIVE_PATTERNS["secret"].search(text):
        detected.append("secret")
        text = SENSITIVE_PATTERNS["secret"].sub(
            lambda match: match.group(1) + REDACTED,
            text,
        )

    # Bearer token
    if SENSITIVE_PATTERNS["bearer_token"].search(text):
        detected.append("bearer_token")
        text = SENSITIVE_PATTERNS["bearer_token"].sub(
            lambda match: match.group(1) + REDACTED,
            text,
        )

    # JWT
    if SENSITIVE_PATTERNS["jwt"].search(text):
        detected.append("jwt")
        text = SENSITIVE_PATTERNS["jwt"].sub(
            "[REDACTED:JWT]",
            text,
        )

    # Private key
    if SENSITIVE_PATTERNS["private_key"].search(text):
        detected.append("private_key")
        text = SENSITIVE_PATTERNS["private_key"].sub(
            "[REDACTED:PRIVATE_KEY]",
            text,
        )

    # Remove duplicates while keeping the order
    detected = list(dict.fromkeys(detected))

    return text, detected
def sanitize_data(
    data: Any,
    key: str | None = None,
) -> tuple[Any, list[str]]:
    """
    Recursively sanitize structured data.

    Supports:
        dictionaries
        lists
        tuples
        strings
        Pydantic models
        normal scalar values
    """

    detected: list[str] = []

    # If the current field name itself is sensitive,
    # hide the complete value.
    if key is not None and _is_sensitive_key(key):
        return REDACTED, [_normalize_key(key)]

    # Pydantic model support
    if hasattr(data, "model_dump"):
        data = data.model_dump(mode="json")

    # Dictionary / JSON object
    if isinstance(data, dict):
        safe_dict = {}

        for child_key, value in data.items():
            safe_value, child_detected = sanitize_data(
                value,
                key=str(child_key),
            )

            safe_dict[child_key] = safe_value
            detected.extend(child_detected)

        detected = list(dict.fromkeys(detected))
        return safe_dict, detected

    # List
    if isinstance(data, list):
        safe_list = []

        for item in data:
            safe_item, child_detected = sanitize_data(item)

            safe_list.append(safe_item)
            detected.extend(child_detected)

        detected = list(dict.fromkeys(detected))
        return safe_list, detected

    # Tuple
    if isinstance(data, tuple):
        safe_items = []

        for item in data:
            safe_item, child_detected = sanitize_data(item)

            safe_items.append(safe_item)
            detected.extend(child_detected)

        detected = list(dict.fromkeys(detected))
        return tuple(safe_items), detected

    # Free text
    if isinstance(data, str):
        return redact_text(data)

    # Integers, floats, booleans, None, etc.
    return data, detected

