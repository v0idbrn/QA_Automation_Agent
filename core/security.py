# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Re-export bridge.

Old code imported from `core.security`. We now centralize in
`core.redaction`; this file keeps those imports working unchanged.
"""

from core.redaction import (
    redact,
    redact_text,
    redact_url,
    redact_headers,
    redact_dict_sensitive_keys,
    sanitize_log_line,
    scrub,
)
from core.models import RedactionPolicy

# Legacy alias: the historical public entry point for string redaction.
redact_sensitive_data = redact_text

__all__ = [
    "redact",
    "redact_sensitive_data",
    "redact_text",
    "redact_url",
    "redact_headers",
    "redact_dict_sensitive_keys",
    "sanitize_log_line",
    "scrub",
    "RedactionPolicy",
]
