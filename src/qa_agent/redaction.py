# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Local redaction used by the new engines before evidence is persisted.

The autonomous agent keeps its own central layer in ``core.redaction``. This
module exists so the installable ``qa_agent`` package never depends on the
repository root layout, and so new evidence paths share one implementation.
"""

from __future__ import annotations

import re
from typing import Mapping
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

__all__ = ["REDACTED", "redact_headers", "redact_text", "redact_url"]

REDACTED = "[REDACTED]"

_SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs)_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{12,}"),
    re.compile(r"(?i)\b(api[_-]?key|access[_-]?token|secret|password|authorization)\b\s*[:=]\s*['\"]?[^\s,;'\"&?#]{4,}"),
)

_SENSITIVE_KEYS = frozenset(
    {"token", "access_token", "id_token", "api_key", "apikey", "key", "secret", "password", "auth", "authorization", "session", "sid"}
)


def redact_text(value: str) -> str:
    redacted = value
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub(REDACTED, redacted)
    return redacted


def redact_url(value: str) -> str:
    """Redact secret-shaped query values while preserving the URL shape."""
    try:
        parts = urlsplit(value)
    except ValueError:
        return redact_text(value)
    if not parts.query:
        return redact_text(value)
    pairs = [
        (
            key,
            REDACTED
            if key.lower() in _SENSITIVE_KEYS
            or key.lower().endswith(("_key", "_token", "_secret"))
            or "token" in key.lower()
            else item,
        )
        for key, item in parse_qsl(parts.query, keep_blank_values=True)
    ]
    return redact_text(urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), parts.fragment)))


def redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
    sensitive = {"authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization"}
    return {
        str(key): REDACTED if str(key).lower() in sensitive else redact_text(str(value))
        for key, value in headers.items()
    }
