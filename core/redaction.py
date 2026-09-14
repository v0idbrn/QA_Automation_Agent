# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
CENTRAL SENSITIVE-DATA REDACTION WRITE-PATH.

Every log line, finding field, report section, evidence blob, and manifest
value that contains user-controlled data MUST pass through one of the
functions in this module BEFORE being persisted or emitted.

This module delegates regex matching to `core.models.RedactionPolicy` for
the heavy lifting, and adds:
  * recursive walker for dict/list/tuple/dataclass-ish structures
  * sensitive-key-name whole-value redaction
  * HTTP-header specific logic
  * scheme-preserving URL credential scrubbing
"""

from __future__ import annotations

import dataclasses
import re
from typing import Any

from core.models import RedactionPolicy


_DEFAULT_POLICY = RedactionPolicy()

_SENSITIVE_KEY_RE = re.compile(
    r"(?i)(password|passwd|pwd|token|api[-_ ]?key|apikey|secret|authorization|auth|cookie|set[-_ ]?cookie|session[-_ ]?id|jwt|bearer|private[-_ ]?key|connection[-_ ]?string|credential)",
)
_HEADER_SENSITIVE_RE = re.compile(
    r"(?i)(authorization|cookie|set-cookie|proxy-authorization|x-api-key|x-auth-token|x-session-token)",
)


def _should_redact_key(key: Any) -> bool:
    if not isinstance(key, str):
        return False
    return bool(_SENSITIVE_KEY_RE.search(key))


def _should_redact_header(key: Any) -> bool:
    if not isinstance(key, str):
        return False
    return bool(_HEADER_SENSITIVE_RE.search(key))


# ---------------------------------------------------------------------------
# Public API — every write-path calls one of these.
# ---------------------------------------------------------------------------


def redact(value: Any, *, policy: RedactionPolicy | None = None) -> Any:
    """Redact a value of arbitrary shape.

    * str -> regex pattern replacement (policy.redact)
    * dict -> sensitive keys become "[REDACTED]" wholesale; values recurse
    * list/tuple/set -> elementwise recursion
    * dataclass -> asdict() -> recurse
    * other -> returned as-is (no-op for int/bool/float/None etc.)
    """
    pol = policy or _DEFAULT_POLICY
    if value is None:
        return None
    if isinstance(value, str):
        return pol.redact(value)
    if isinstance(value, (bytes, bytearray)):
        try:
            decoded = value.decode("utf-8", errors="ignore")
            return pol.redact(decoded)
        except Exception:
            return "[REDACTED:binary]"
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if _should_redact_key(k):
                out[str(k)] = "[REDACTED]"
            else:
                out[str(k)] = redact(v, policy=pol)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        seq = [redact(item, policy=pol) for item in value]
        return type(value)(seq) if type(value) is not frozenset else tuple(seq)
    if dataclasses.is_dataclass(value):
        return redact(dataclasses.asdict(value), policy=pol)
    return value


def redact_text(text: str, *, policy: RedactionPolicy | None = None) -> str:
    """String-only fast-path. Guarantee str output for log lines."""
    if not isinstance(text, str):
        text = str(text)
    pol = policy or _DEFAULT_POLICY
    return pol.redact(text)


def redact_headers(headers: Any, *, policy: RedactionPolicy | None = None) -> Any:
    """Redact HTTP headers (dict-like). Sensitive header names → value scrubbed."""
    if not isinstance(headers, dict):
        return headers
    pol = policy or _DEFAULT_POLICY
    out: dict[str, Any] = {}
    for k, v in headers.items():
        if _should_redact_header(k) or _should_redact_key(k):
            out[str(k)] = "[REDACTED]"
        else:
            out[str(k)] = redact(v, policy=pol)
    return out


def redact_url(url: str, *, policy: RedactionPolicy | None = None) -> str:
    """Fast URL scrubber. Delegates to policy regex which preserves scheme."""
    if not isinstance(url, str):
        return url
    return redact_text(url, policy=policy)


def redact_dict_sensitive_keys(payload: Any, *, policy: RedactionPolicy | None = None) -> Any:
    """Backward-compat alias. Preferred API is `redact()` (handles recursively)."""
    return redact(payload, policy=policy)


def sanitize_log_line(line: str) -> str:
    """Single-purpose sanitizer for structured logger emit paths."""
    return redact_text(line)


def scrub(value: Any) -> Any:
    """Short alias used by evidence / manifest writers."""
    return redact(value)
