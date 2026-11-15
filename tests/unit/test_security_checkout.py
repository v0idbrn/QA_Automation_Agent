# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Unit tests for passive security headers/cookies/secrets and checkout integrity."""

from __future__ import annotations

import httpx
import pytest

from qa_agent.security_checkout import (
    SecurityAuditor,
    SecurityReport,
    analyze_checkout,
    analyze_totals,
    audit_cookies,
    audit_security_headers,
    audit_sourcemaps,
    audit_stacktrace,
    check_idempotency,
    parse_cookie,
    scan_text_for_secrets,
)

SECURE_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}


def categories(findings: list) -> set[str]:
    return {finding.category for finding in findings}


def test_secure_headers_pass() -> None:
    assert audit_security_headers(SECURE_HEADERS) == []


@pytest.mark.parametrize(
    ("headers", "category"),
    [
        ({}, "security-csp"),
        ({"Content-Security-Policy": "default-src *"}, "security-csp"),
        ({"Content-Security-Policy": "script-src 'unsafe-inline'"}, "security-csp"),
        ({"Content-Security-Policy": "script-src 'unsafe-eval'"}, "security-csp"),
        ({"Strict-Transport-Security": "max-age=600"}, "security-hsts"),
        ({"Strict-Transport-Security": "max-age=31536000"}, "security-clickjacking"),
        ({"X-Frame-Options": "DENY", "Strict-Transport-Security": "max-age=31536000"}, "security-mime-sniffing"),
        (
            {"X-Content-Type-Options": "nosniff", "Strict-Transport-Security": "max-age=31536000", "X-Frame-Options": "DENY"},
            "security-referrer",
        ),
    ],
)
def test_header_gaps_are_reported(headers: dict, category: str) -> None:
    findings = audit_security_headers(headers)
    assert category in categories(findings)


def test_missing_hsts_is_high_severity() -> None:
    findings = audit_security_headers({"Content-Security-Policy": "default-src 'self'", "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"})
    hsts = next(finding for finding in findings if finding.category == "security-hsts")
    assert hsts.severity.value == "high"


def test_frame_ancestors_suppresses_xfo_finding() -> None:
    headers = {**SECURE_HEADERS, "Content-Security-Policy": "frame-ancestors 'self'"}
    headers.pop("X-Frame-Options")
    findings = audit_security_headers(headers)
    assert not any(finding.category == "security-clickjacking" for finding in findings)


def test_cors_wildcard_with_credentials_is_critical() -> None:
    findings = audit_security_headers({"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"})
    cors = [finding for finding in findings if finding.category == "security-cors"]
    assert cors and cors[0].severity.value == "critical"


def test_cors_wildcard_without_credentials_is_low() -> None:
    findings = audit_security_headers({"Access-Control-Allow-Origin": "*"})
    cors = [finding for finding in findings if finding.category == "security-cors"]
    assert cors and cors[0].severity.value == "low"


def test_headers_are_case_insensitive() -> None:
    findings = audit_security_headers({key.lower(): value for key, value in SECURE_HEADERS.items()})
    assert findings == []


def test_header_findings_redact_url() -> None:
    findings = audit_security_headers({}, "https://app.example.com/?token=abc")
    assert findings and all("abc" not in finding.url for finding in findings)


@pytest.mark.parametrize(
    ("raw", "name", "secure", "http_only", "same_site"),
    [
        ("session=abc; Secure; HttpOnly; SameSite=Lax", "session", True, True, "Lax"),
        ("theme=dark; Path=/", "theme", False, False, ""),
        ("auth=1; secure; httponly; samesite=strict", "auth", True, True, "strict"),
    ],
)
def test_parse_cookie(raw: str, name: str, secure: bool, http_only: bool, same_site: str) -> None:
    cookie = parse_cookie(raw)
    assert (cookie.name, cookie.secure, cookie.http_only, cookie.same_site) == (name, secure, http_only, same_site)


def test_parse_cookie_marks_session_like() -> None:
    assert parse_cookie("session_id=1").session_like is True
    assert parse_cookie("theme=dark").session_like is False


def test_cookie_flags_missing() -> None:
    findings = audit_cookies(["session=abc; Path=/"])
    assert {"security-cookie"} == categories(findings)
    assert len(findings) == 3


def test_cookie_secure_and_httponly_missing_same_site_only() -> None:
    findings = audit_cookies(["session=abc; Secure; HttpOnly"])
    assert [finding.title for finding in findings] == ["Cookie without SameSite"]


def test_cookie_session_missing_flags_is_high() -> None:
    findings = audit_cookies(["auth_token=abc"])
    secure_flags = [finding for finding in findings if "SameSite" not in finding.title]
    assert secure_flags and all(finding.severity.value == "high" for finding in secure_flags)


def test_cookie_non_session_missing_flags_is_medium() -> None:
    findings = audit_cookies(["theme=dark; SameSite=Lax"])
    assert findings and all(finding.severity.value == "medium" for finding in findings)


def test_sourcemap_detection() -> None:
    findings = audit_sourcemaps(["https://app.example.com/app.js.map", "https://app.example.com/app.js"])
    assert len(findings) == 1
    assert findings[0].category == "security-sourcemap"


def test_sourcemap_query_string_still_detected() -> None:
    assert len(audit_sourcemaps(["https://app.example.com/app.js.map?v=1"])) == 1


def test_sourcemap_lookalike_ignored() -> None:
    assert audit_sourcemaps(["https://app.example.com/mapping.js"]) == []


@pytest.mark.parametrize(
    "secret",
    [
        "sk-abcdefghijklmnopqrstuvwx",
        "pk_live_abcdefghijkl",
        "ghp_abcdefghijklmnopqrstuvwxyz0123",
        "AKIAIOSFODNN7EXAMPLE",
        "AIzaabcdefghijklmnopqrstuvwxyz012345",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijk",
        "-----BEGIN PRIVATE KEY-----",
    ],
)
def test_scan_text_finds_client_secrets(secret: str) -> None:
    findings = scan_text_for_secrets(f"const config = '{secret}';", "app.js")
    assert findings
    assert all(finding.category == "security-client-secret" for finding in findings)
    assert all(secret not in finding.evidence for finding in findings)


def test_scan_text_clean_bundle() -> None:
    assert scan_text_for_secrets("const apiBase = '/api'; export default apiBase;") == []


def test_scan_text_reports_each_kind_once() -> None:
    findings = scan_text_for_secrets("sk-abcdefghijklmnopqrstuvwx AKIAIOSFODNN7EXAMPLE")
    assert len(findings) == 2


@pytest.mark.parametrize(
    "body",
    [
        "Traceback (most recent call last): File /app/x.py",
        "at Object.<anonymous> (/src/index.js:1)",
        'File "/app/main.py", line 4',
        "SQLSTATE[42000] syntax error",
        '{"stacktrace": "..."}',
    ],
)
def test_stacktrace_markers_detected(body: str) -> None:
    findings = audit_stacktrace(body)
    assert findings and findings[0].category == "security-stacktrace"


def test_stacktrace_clean_body() -> None:
    assert audit_stacktrace('{"error": "not_found"}') == []


def test_security_report_gate_and_serialization() -> None:
    report = SecurityReport(url="https://app.example.com/?token=abc", findings=audit_security_headers({}))
    payload = report.to_dict()
    assert payload["passed"] is False
    assert "abc" not in payload["url"]


def test_security_auditor_returns_transport_finding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        report = SecurityAuditor().audit("http://target.invalid/", client=client)
    assert report.findings and report.findings[0].category == "security-transport"


def test_security_auditor_scans_html_and_cookies() -> None:
    body = '<html><body><script src="/app.js.map"></script></body></html>'

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "text/html", "set-cookie": "session=x"}, text=body)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        report = SecurityAuditor().audit("https://app.example.com/", client=client)
    assert report.status == 200
    found = categories(report.findings)
    assert "security-sourcemap" in found
    assert "security-cookie" in found


def test_security_auditor_flags_mixed_content_html() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "text/html"}, text='<img src="http://cdn.example.com/a.png">')

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        report = SecurityAuditor().audit("https://app.example.com/", client=client)
    assert any(finding.category == "security-mixed-content" for finding in report.findings)


def test_security_auditor_flags_stacktrace_on_500() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, headers={"content-type": "application/json"}, text='{"stacktrace": "Traceback (most recent call last)"}')

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        report = SecurityAuditor().audit("https://app.example.com/", client=client)
    assert any(finding.category == "security-stacktrace" for finding in report.findings)


@pytest.mark.parametrize(
    ("kwargs", "code"),
    [
        ({"quantity": -1}, "negative-quantity"),
        ({"quantity": 0}, "zero-quantity"),
        ({"quantity": 1.5}, "fractional-quantity"),
        ({"quantity": 101}, "quantity-upper-bound"),
        ({"price": -5.0}, "negative-price"),
        ({"price": 0.0}, "zero-price"),
        ({"price": 9.999}, "float-precision"),
        ({"currency": "EUR"}, "currency-mismatch"),
        ({"currency": "BTC"}, "unsupported-currency"),
    ],
)
def test_checkout_edge_cases(kwargs: dict, code: str) -> None:
    payload = {"quantity": 1, "price": 9.99, **kwargs}
    issues = analyze_checkout(**payload)
    assert code in {issue.code for issue in issues}


def test_checkout_clean_line_item() -> None:
    assert analyze_checkout(quantity=2, price=9.99, currency="USD") == []


def test_checkout_issue_becomes_finding() -> None:
    issue = analyze_checkout(quantity=-1, price=9.99)[0]
    finding = issue.to_finding()
    assert finding.category == "checkout-negative-quantity"
    assert finding.severity.value == "critical"


def test_checkout_total_mismatch() -> None:
    issues = analyze_totals([{"price": 10.0, "quantity": 2, "claimed_total": 10.0}])
    assert [issue.code for issue in issues] == ["total-mismatch"]


def test_checkout_total_matches_with_tax() -> None:
    issues = analyze_totals([{"price": 10.0, "quantity": 2, "claimed_total": 21.0}], tax_rate=0.05)
    assert issues == []


def test_checkout_total_without_claim_is_not_flagged() -> None:
    assert analyze_totals([{"price": 5.0, "quantity": 1}]) == []


def test_idempotency_consistent_replay_passes() -> None:
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        assert request.headers["Idempotency-Key"] == "key-1"
        return httpx.Response(201, json={"order_id": "ord-1"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = check_idempotency(client, "http://api.test/checkout", {"quantity": 1}, key="key-1")
    assert result.passed is True
    assert calls["count"] == 2
    assert result.to_finding() is None


def test_idempotency_divergent_replay_fails() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        handler.calls += 1  # type: ignore[attr-defined]
        return httpx.Response(201, json={"order_id": f"ord-{handler.calls}"})  # type: ignore[attr-defined]

    handler.calls = 0  # type: ignore[attr-defined]
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = check_idempotency(client, "http://api.test/checkout", {"quantity": 1})
    assert result.passed is False
    finding = result.to_finding()
    assert finding is not None
    assert finding.category == "checkout-idempotency"


def test_idempotency_transport_error_is_structured() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = check_idempotency(client, "http://api.test/checkout", {})
    assert result.passed is False
    assert result.first_status == 0
    assert "transport error" in result.first_body
