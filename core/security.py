# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Sensitive data redaction for logs, findings, reports, and exports.

Redaction is applied BEFORE anything is persisted or emitted. This module is
intentionally small and deterministic.
"""

from __future__ import annotations

import re
from typing import Any

from core.models import RedactionPolicy


def redact_sensitive_data(value: Any) -> Any:
    policy = RedactionPolicy()
    if isinstance(value, str):
        return policy.redact(value)
    if isinstance(value, dict):
        return {key: redact_sensitive_data(val) for key, val in value.items()}
    if isinstance(value, list):
        return [redact_sensitive_data(item) for item in value]
    return value


def redact_dict_sensitive_keys(payload: dict[str, Any]) -> dict[str, Any]:
    """Redact whole values for keys that look sensitive."""
    if not isinstance(payload, dict):
        return payload
    out: dict[str, Any] = {}
    lowered = {key.lower(): key for key in payload.keys()}
    sensitive_marker = next(
        (original for lowered_key, original in lowered.items() if any(token in lowered_key for token in ("authorization", "cookie", "set-cookie", "password", "passwd", "token", "api_key", "apikey", "secret"))),
        None,
    )
    for key, value in payload.items():
        if key == sensitive_marker or any(token in key.lower() for token in ("authorization", "cookie", "set-cookie", "password", "passwd", "token", "api_key", "apikey", "secret")):
            out[key] = "[REDACTED]"
        else:
            out[key] = redact_sensitive_data(value)
    return out


def sanitize_log_line(line: str) -> str:
    return RedactionPolicy().redact(line)


_HTTP_HEADER_SENSITIVE_RE = re.compile(r"(?i)(authorization|cookie|set-cookie|token|api[-_]?key|secret)", re.IGNORECASE)


def redact_headers(headers: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(headers, dict):
        return headers
    out: dict[str, Any] = {}
    for key, value in headers.items():
        if _HTTP_HEADER_SENSITIVE_RE.search(str(key)):
            out[key] = "[REDACTED]"
        else:
            out[key] = redact_sensitive_data(value)
    return out
