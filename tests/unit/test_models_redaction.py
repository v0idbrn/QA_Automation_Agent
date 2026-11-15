# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Unit tests for the shared Workhorse contracts and local redaction."""

from __future__ import annotations

import pytest

from qa_agent.models import Finding, Severity, normalize_severity, severity_counts, sort_findings
from qa_agent.redaction import REDACTED, redact_headers, redact_text, redact_url


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("critical", Severity.CRITICAL),
        ("HIGH", Severity.HIGH),
        ("Medium", Severity.MEDIUM),
        (Severity.LOW, Severity.LOW),
        ("unknown", Severity.INFO),
        ("", Severity.INFO),
    ],
)
def test_normalize_severity(raw: object, expected: Severity) -> None:
    assert normalize_severity(raw) == expected


def test_finding_normalizes_severity_and_serializes() -> None:
    finding = Finding(title="T", severity="high", category="c", description="d")
    payload = finding.to_dict()
    assert payload["severity"] == "high"
    assert payload["title"] == "T"
    assert set(payload) >= {"title", "severity", "category", "evidence", "recommendation", "metadata"}


def test_severity_counts_cover_every_level() -> None:
    findings = [
        Finding("a", Severity.CRITICAL, "x"),
        Finding("b", "critical", "x"),
        Finding("c", "low", "x"),
    ]
    counts = severity_counts(findings)
    assert counts["critical"] == 2
    assert counts["low"] == 1
    assert counts["info"] == 0
    assert list(counts) == ["critical", "high", "medium", "low", "info"]


def test_sort_findings_orders_by_severity_then_category() -> None:
    findings = [
        Finding("low", "low", "z"),
        Finding("crit-b", "critical", "b"),
        Finding("crit-a", "critical", "a"),
        Finding("high", "high", "a"),
    ]
    ordered = sort_findings(findings)
    assert [item.title for item in ordered] == ["crit-a", "crit-b", "high", "low"]


@pytest.mark.parametrize(
    "secret",
    [
        "sk-abcdefghijklmnop",
        "ghp_abcdefghijklmnopqrstuvwxyz0123",
        "AKIAIOSFODNN7EXAMPLE",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk",
        "Bearer abcdefghijklmno",
        "password=hunter2",
        "api_key: supersecret",
    ],
)
def test_redact_text_masks_secret_shapes(secret: str) -> None:
    redacted = redact_text(f"value {secret} end")
    assert REDACTED in redacted
    assert secret not in redacted


def test_redact_text_keeps_normal_text() -> None:
    assert redact_text("Cart total is 42 USD") == "Cart total is 42 USD"


def test_redact_url_masks_token_parameters() -> None:
    url = redact_url("https://app.example.com/callback?access_token=abc123&page=2")
    assert "abc123" not in url
    assert "page=2" in url
    assert REDACTED.replace("[", "%5B").replace("]", "%5D") in url or "REDACTED" in url


def test_redact_url_masks_secret_like_key_names() -> None:
    url = redact_url("https://app.example.com/?session_key=abcd&x=1")
    assert "abcd" not in url


def test_redact_url_keeps_clean_query() -> None:
    assert redact_url("https://app.example.com/search?q=shoes") == "https://app.example.com/search?q=shoes"


def test_redact_url_handles_invalid_input() -> None:
    assert redact_text("https://[broken") in redact_url("https://[broken")


def test_redact_headers_masks_auth_and_cookies() -> None:
    headers = {"Authorization": "Bearer token", "Cookie": "a=b", "X-Api-Key": "k", "Accept": "json"}
    redacted = redact_headers(headers)
    assert redacted["Authorization"] == REDACTED
    assert redacted["Cookie"] == REDACTED
    assert redacted["X-Api-Key"] == REDACTED
    assert redacted["Accept"] == "json"


def test_redact_headers_redacts_values_but_keeps_names() -> None:
    redacted = redact_headers({"X-Trace": "password=secretvalue"})
    assert "secretvalue" not in redacted["X-Trace"]
