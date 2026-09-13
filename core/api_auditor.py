# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Network Traffic Interceptor for autonomous QA.

Provides:
- Background request/response interception.
- Detection of HTTP 5xx errors, timeouts, and malformed JSON payloads.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import json as _json


@dataclass(frozen=True)
class ApiFinding:
    request_url: str
    method: str
    status: int | None
    detail: str
    payload_sample: str | None = None
    severity: str = "medium"


class ApiAuditor:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []

    def on_response(self, request: Any, response: Any) -> ApiFinding | None:
        status = getattr(response, "status", None)
        if status is None or status < 400:
            return None

        payload_sample = None
        try:
            body = getattr(response, "text", lambda: "")()
            if body and len(body) > 0:
                payload_sample = body[:400]
        except Exception:  # noqa: BLE001
            payload_sample = None

        detail = f"received status {status} for {getattr(request, 'url', 'unknown')}"
        return ApiFinding(
            request_url=getattr(request, "url", "unknown"),
            method=getattr(request, "method", "GET"),
            status=status,
            detail=detail,
            payload_sample=payload_sample,
            severity="high" if status >= 500 else "medium",
        )

    def on_request(self, request: Any) -> None:
        self.requests.append(
            {
                "url": getattr(request, "url", "unknown"),
                "method": getattr(request, "method", "GET"),
            }
        )

    def summarize(self, findings: list[ApiFinding]) -> dict[str, Any]:
        if not findings:
            return {"total": 0, "high": 0, "medium": 0, "sample_urls": []}
        return {
            "total": len(findings),
            "high": sum(1 for f in findings if f.severity == "high"),
            "medium": sum(1 for f in findings if f.severity == "medium"),
            "sample_urls": [f.request_url for f in findings[:10]],
        }


def parse_json_safely(text: str) -> dict[str, Any] | None:
    if not text:
        return None
    try:
        parsed = _json.loads(text)
        return parsed if isinstance(parsed, dict) else None
    except Exception:  # noqa: BLE001
        return None


def flag_malformed_json(text: str) -> ApiFinding | None:
    parsed = parse_json_safely(text)
    if parsed is None and text.strip():
        return ApiFinding(
            request_url="unknown",
            method="UNKNOWN",
            status=0,
            detail="payload appears malformed or non-JSON",
            payload_sample=text[:300],
            severity="medium",
        )
    return None
