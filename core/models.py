# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Unified finding model for the QA Automation Agent.

Every engine should be able to emit findings through a shared, typed contract
so downstream components such as the analyzer, evidence manager, and report
builder can treat them consistently.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class FindingCategory(str, Enum):
    CRAWL = "crawl"
    HTTP = "http"
    CONSOLE = "console"
    FORM = "form"
    ACCESSIBILITY = "accessibility"
    API = "api"
    TEST = "test"
    ENVIRONMENT = "environment"
    NETWORK = "network"
    TIMEOUT = "timeout"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(BaseModel):
    id: str
    category: FindingCategory
    severity: Severity
    title: str
    description: str
    evidence: str | None = None
    location: str | None = None
    expected: str | None = None
    actual: str | None = None
    reproduction: str | None = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    source: str = "unknown"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)

    def model_dump_safe(self, redaction: "RedactionPolicy | None" = None) -> dict[str, Any]:
        data = self.model_dump()
        if redaction is not None:
            for key in ("evidence", "description", "actual", "expected", "reproduction", "location"):
                if isinstance(data.get(key), str):
                    data[key] = redaction.redact(data[key])
        return data


class RedactionPolicy:
    """Simple centralised redaction for sensitive values before logging or exporting."""

    patterns: tuple[str, ...] = (
        "authorization",
        "cookie",
        "set-cookie",
        "password",
        "passwd",
        "token",
        "api_key",
        "apikey",
        "secret",
        "bearer",
    )

    def redact(self, value: str) -> str:
        if not isinstance(value, str):
            return value
        lower = value.lower()
        if any(pattern in lower for pattern in self.patterns):
            return "[REDACTED]"
        return value
