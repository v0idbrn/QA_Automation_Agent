# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Passive security and checkout-integrity auditing.

Security checks here are strictly non-destructive: they read response headers,
cookies, and already-served HTML/JS. Nothing is injected into the target.
Checkout checks validate *behaviour of an endpoint you point them at* (usually
a staging environment or the local fixture) and are likewise read-only except
for the caller-supplied checkout request.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

import httpx

from qa_agent.models import Finding, Severity
from qa_agent.redaction import REDACTED, redact_text, redact_url

__all__ = [
    "CheckoutIssue",
    "CookieInfo",
    "IdempotencyResult",
    "SecurityAuditor",
    "SecurityReport",
    "analyze_checkout",
    "audit_cookies",
    "audit_security_headers",
    "audit_sourcemaps",
    "audit_stacktrace",
    "check_idempotency",
    "parse_cookie",
    "scan_text_for_secrets",
]


_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b")),
    ("stripe-key", re.compile(r"\b(?:pk|sk)_(?:live|test)_[A-Za-z0-9]{10,}\b")),
    ("github-token", re.compile(r"\b(?:ghp|gho|ghu|ghs)_[A-Za-z0-9]{20,}\b")),
    ("aws-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google-key", re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
)

_STACKTRACE_MARKERS = (
    "Traceback (most recent call last)",
    "at Object.<anonymous>",
    "File \"/app/",
    "File \"C:\\",
    "org.springframework.beans",
    "SQLSTATE[",
    "SequelizeDatabaseError",
    "stack_trace",
    "stacktrace",
)


def _finding(
    title: str,
    severity: Severity,
    category: str,
    description: str,
    evidence: str = "",
    recommendation: str = "",
    url: str = "",
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        category=category,
        description=description,
        url=redact_url(url) if url else "",
        evidence=redact_text(evidence),
        recommendation=recommendation,
    )


# ---------------------------------------------------------------------------
# Header, cookie, bundle checks
# ---------------------------------------------------------------------------


def audit_security_headers(headers: Mapping[str, str], url: str = "") -> list[Finding]:
    """Passive checks over already-received response headers."""
    lowered = {str(key).lower(): str(value) for key, value in headers.items()}
    findings: list[Finding] = []

    csp = lowered.get("content-security-policy", "")
    if not csp:
        findings.append(
            _finding(
                "Missing Content-Security-Policy",
                Severity.HIGH,
                "security-csp",
                "No CSP is served, so injected scripts are not constrained.",
                "content-security-policy header absent",
                "Serve a restrictive CSP and roll it out in report-only mode first.",
                url,
            )
        )
    else:
        weak = [token for token in ("unsafe-inline", "unsafe-eval", "*") if token in csp]
        if weak:
            findings.append(
                _finding(
                    "Weak Content-Security-Policy",
                    Severity.MEDIUM,
                    "security-csp",
                    "The CSP allows directives that defeat most of its protection.",
                    f"tokens={','.join(weak)} policy={csp[:160]}",
                    "Remove unsafe-inline/unsafe-eval and wildcard sources; use nonces or hashes.",
                    url,
                )
            )

    hsts = lowered.get("strict-transport-security", "")
    if not hsts:
        findings.append(
            _finding(
                "Missing Strict-Transport-Security",
                Severity.HIGH,
                "security-hsts",
                "Browsers are not told to stay on HTTPS for this host.",
                "strict-transport-security header absent",
                "Serve HSTS with max-age >= 31536000 and includeSubDomains.",
                url,
            )
        )
    elif (match := re.search(r"max-age=(\d+)", hsts)) and int(match.group(1)) < 15_768_000:
        findings.append(
            _finding(
                "Short HSTS max-age",
                Severity.LOW,
                "security-hsts",
                "HSTS is present but expires too quickly to protect users.",
                f"max-age={match.group(1)}",
                "Raise max-age to at least 15552000 (six months).",
                url,
            )
        )

    if "x-frame-options" not in lowered and "frame-ancestors" not in csp.lower():
        findings.append(
            _finding(
                "Missing clickjacking protection",
                Severity.MEDIUM,
                "security-clickjacking",
                "Neither X-Frame-Options nor CSP frame-ancestors blocks framing.",
                "x-frame-options absent",
                "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
                url,
            )
        )

    if lowered.get("x-content-type-options", "").strip().lower() != "nosniff":
        findings.append(
            _finding(
                "Missing X-Content-Type-Options",
                Severity.LOW,
                "security-mime-sniffing",
                "Browsers may sniff content types and execute unexpected payloads.",
                f"x-content-type-options={lowered.get('x-content-type-options', 'absent')}",
                "Serve X-Content-Type-Options: nosniff.",
                url,
            )
        )

    if not lowered.get("referrer-policy"):
        findings.append(
            _finding(
                "Missing Referrer-Policy",
                Severity.LOW,
                "security-referrer",
                "Referrer information may leak full URLs to third parties.",
                "referrer-policy header absent",
                "Serve Referrer-Policy: strict-origin-when-cross-origin.",
                url,
            )
        )

    allow_origin = lowered.get("access-control-allow-origin", "")
    allow_credentials = lowered.get("access-control-allow-credentials", "").lower() == "true"
    if allow_origin.strip() == "*" and allow_credentials:
        findings.append(
            _finding(
                "Permissive CORS with credentials",
                Severity.CRITICAL,
                "security-cors",
                "A wildcard origin combined with credentials exposes authenticated data.",
                "access-control-allow-origin=* + credentials=true",
                "Reflect only allow-listed origins and never combine '*' with credentials.",
                url,
            )
        )
    elif allow_origin.strip() == "*":
        findings.append(
            _finding(
                "Wildcard CORS origin",
                Severity.LOW,
                "security-cors",
                "Any origin may read unauthenticated responses.",
                "access-control-allow-origin=*",
                "Restrict the origin list to trusted applications.",
                url,
            )
        )

    return findings


@dataclass(frozen=True)
class CookieInfo:
    name: str
    secure: bool
    http_only: bool
    same_site: str = ""
    session_like: bool = False


def parse_cookie(raw: str) -> CookieInfo:
    parts = [part.strip() for part in str(raw).split(";") if part.strip()]
    name = parts[0].split("=", 1)[0].strip() if parts else ""
    lowered = {part.lower() for part in parts[1:]}
    same_site = next((part.split("=", 1)[1] for part in parts[1:] if part.lower().startswith("samesite=")), "")
    return CookieInfo(
        name=name,
        secure="secure" in lowered,
        http_only="httponly" in lowered,
        same_site=same_site,
        session_like=any(token in name.lower() for token in ("session", "auth", "token", "sid")),
    )


def audit_cookies(set_cookie_headers: Sequence[str], url: str = "") -> list[Finding]:
    findings: list[Finding] = []
    for raw in set_cookie_headers:
        cookie = parse_cookie(raw)
        if not cookie.secure:
            findings.append(
                _finding(
                    "Cookie without Secure flag",
                    Severity.HIGH if cookie.session_like else Severity.MEDIUM,
                    "security-cookie",
                    "The cookie may be sent over plain HTTP.",
                    f"cookie={cookie.name}",
                    "Add the Secure attribute to every cookie.",
                    url,
                )
            )
        if not cookie.http_only:
            findings.append(
                _finding(
                    "Cookie without HttpOnly flag",
                    Severity.HIGH if cookie.session_like else Severity.MEDIUM,
                    "security-cookie",
                    "JavaScript can read this cookie, widening XSS impact.",
                    f"cookie={cookie.name}",
                    "Add HttpOnly to cookies that do not need script access.",
                    url,
                )
            )
        if not cookie.same_site:
            findings.append(
                _finding(
                    "Cookie without SameSite",
                    Severity.LOW,
                    "security-cookie",
                    "Cross-site requests may include this cookie.",
                    f"cookie={cookie.name}",
                    "Set SameSite=Lax or Strict.",
                    url,
                )
            )
    return findings


def audit_sourcemaps(js_urls: Iterable[str], url: str = "") -> list[Finding]:
    return [
        _finding(
            "Exposed JavaScript source map",
            Severity.MEDIUM,
            "security-sourcemap",
            "A source map is publicly reachable, exposing original source code.",
            redact_url(js_url),
            "Do not deploy .map files to production or restrict them to internal networks.",
            url,
        )
        for js_url in js_urls
        if str(js_url).split("?", 1)[0].lower().endswith(".map")
    ]


def scan_text_for_secrets(text: str, source: str = "", url: str = "") -> list[Finding]:
    """Detect client-side credentials. Matched values are never echoed."""
    findings: list[Finding] = []
    content = text or ""
    for label, pattern in _SECRET_PATTERNS:
        match = pattern.search(content)
        if not match:
            continue
        findings.append(
            _finding(
                f"Client-side secret: {label}",
                Severity.CRITICAL,
                "security-client-secret",
                "A credential-shaped value ships in client-readable content.",
                f"{source or 'bundle'} -> {REDACTED}",
                "Remove the secret from the client, rotate it, and proxy the call server-side.",
                url,
            )
        )
    return findings


def audit_stacktrace(body: str, url: str = "") -> list[Finding]:
    content = body or ""
    for marker in _STACKTRACE_MARKERS:
        if marker in content:
            return [
                _finding(
                    "Stacktrace leaked in response",
                    Severity.HIGH,
                    "security-stacktrace",
                    "An error response exposes implementation details.",
                    f"marker={marker}",
                    "Return a generic error envelope and log details server-side only.",
                    url,
                )
            ]
    return []


@dataclass
class SecurityReport:
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    status: int | None = None

    @property
    def passed(self) -> bool:
        return not any(finding.severity in {Severity.CRITICAL, Severity.HIGH} for finding in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": redact_url(self.url),
            "status": self.status,
            "passed": self.passed,
            "findings": [finding.to_dict() for finding in self.findings],
        }


class SecurityAuditor:
    """Fetch a URL once and run every passive check over the response."""

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout

    def audit(self, url: str, client: httpx.Client | None = None) -> SecurityReport:
        report = SecurityReport(url=url)
        owned = client is None
        http = client or httpx.Client(follow_redirects=True, timeout=self.timeout)
        try:
            try:
                response = http.get(url)
            except httpx.HTTPError as exc:
                report.findings.append(
                    _finding(
                        "Target unreachable during security audit",
                        Severity.MEDIUM,
                        "security-transport",
                        "The security audit could not retrieve the target.",
                        f"{type(exc).__name__}",
                        "Confirm the target is reachable before the engagement.",
                        url,
                    )
                )
                return report
            body = response.text
            report.status = response.status_code
            report.headers = dict(response.headers)
            report.findings.extend(audit_security_headers(response.headers, url))
            report.findings.extend(audit_cookies(response.headers.get_list("set-cookie"), url))
            if response.status_code >= 500:
                report.findings.extend(audit_stacktrace(body, url))
            if "html" in response.headers.get("content-type", ""):
                report.findings.extend(_script_checks(body, url))
            report.findings.extend(scan_text_for_secrets(body, "response body", url))
            return report
        finally:
            if owned:
                http.close()


def _script_checks(html: str, url: str) -> list[Finding]:
    findings: list[Finding] = []
    lowered = html.lower()
    if "http://" in lowered and url.lower().startswith("https://"):
        findings.append(
            _finding(
                "Insecure resource on HTTPS page",
                Severity.HIGH,
                "security-mixed-content",
                "The document references plain HTTP resources.",
                "http:// reference found in HTML",
                "Load every subresource over HTTPS.",
                url,
            )
        )
    for match in re.finditer(r"<script[^>]+src=['\"]([^'\"]+\.map(?:\?[^'\"]*)?)['\"]", html, re.IGNORECASE):
        findings.extend(audit_sourcemaps([match.group(1)], url))
    return findings


# ---------------------------------------------------------------------------
# Checkout integrity
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CheckoutIssue:
    code: str
    severity: Severity
    message: str
    evidence: str = ""

    def to_finding(self) -> Finding:
        return Finding(
            title=f"Checkout integrity: {self.code}",
            severity=self.severity,
            category=f"checkout-{self.code}",
            description=self.message,
            evidence=redact_text(self.evidence),
            recommendation=_CHECKOUT_RECOMMENDATIONS.get(self.code, "Validate the value server-side."),
        )


_CHECKOUT_RECOMMENDATIONS = {
    "negative-quantity": "Reject quantity < 1 with a 4xx validation error.",
    "zero-quantity": "Reject quantity 0 unless the UI explicitly supports removal.",
    "fractional-quantity": "Require an integer quantity for discrete goods.",
    "negative-price": "Never trust client-supplied prices; recompute server-side.",
    "zero-price": "Recompute price server-side and reject zero for paid products.",
    "float-precision": "Compute money in integer minor units or Decimal.",
    "currency-mismatch": "Reject carts whose currency does not match the price book.",
    "unsupported-currency": "Validate the currency against an allow-list.",
}


def analyze_checkout(
    *,
    quantity: float,
    price: float,
    currency: str = "USD",
    expected_currency: str = "USD",
    allowed_currencies: Sequence[str] = ("USD", "EUR", "GBP"),
    integer_quantity: bool = True,
    max_quantity: int = 100,
) -> list[CheckoutIssue]:
    """Pure edge-case analysis for a cart line item."""
    issues: list[CheckoutIssue] = []
    if quantity < 0:
        issues.append(CheckoutIssue("negative-quantity", Severity.CRITICAL, "A negative quantity was accepted.", f"quantity={quantity}"))
    elif quantity == 0:
        issues.append(CheckoutIssue("zero-quantity", Severity.HIGH, "A zero quantity was accepted for a paid line item.", f"quantity={quantity}"))
    if integer_quantity and float(quantity) != int(quantity):
        issues.append(CheckoutIssue("fractional-quantity", Severity.MEDIUM, "A fractional quantity was accepted.", f"quantity={quantity}"))
    if quantity > max_quantity:
        issues.append(CheckoutIssue("quantity-upper-bound", Severity.MEDIUM, "Quantity above the business maximum was accepted.", f"quantity={quantity} > {max_quantity}"))
    if price < 0:
        issues.append(CheckoutIssue("negative-price", Severity.CRITICAL, "A negative price was accepted.", f"price={price}"))
    elif price == 0:
        issues.append(CheckoutIssue("zero-price", Severity.HIGH, "A zero price was accepted for a paid product.", f"price={price}"))
    if isinstance(price, float) and round(price, 2) != price:
        issues.append(CheckoutIssue("float-precision", Severity.MEDIUM, "Price carries more than two decimal places.", f"price={price!r}"))
    currency = currency.upper().strip()
    expected_currency = expected_currency.upper().strip()
    if currency != expected_currency:
        issues.append(CheckoutIssue("currency-mismatch", Severity.HIGH, "Cart currency does not match the price book.", f"{currency} != {expected_currency}"))
    if currency not in {code.upper() for code in allowed_currencies}:
        issues.append(CheckoutIssue("unsupported-currency", Severity.MEDIUM, "Currency is outside the supported allow-list.", currency))
    return issues


def analyze_totals(lines: Sequence[Mapping[str, Any]], *, tax_rate: float = 0.0, currency: str = "USD") -> list[CheckoutIssue]:
    """Recompute a cart total in minor units and compare with the claimed total."""
    issues: list[CheckoutIssue] = []
    computed = 0
    for line in lines:
        price = float(line.get("price", 0))
        quantity = float(line.get("quantity", 0))
        computed += round(price * 100) * int(quantity)
    with_tax = round(computed * (1 + tax_rate))
    claimed = lines[0].get("claimed_total") if lines else None
    if claimed is not None and round(float(claimed) * 100) != with_tax:
        issues.append(
            CheckoutIssue(
                "total-mismatch",
                Severity.CRITICAL,
                "The client-visible total does not match a server-side recomputation.",
                f"claimed={claimed} computed={with_tax / 100:.2f} {currency}",
            )
        )
    return issues


@dataclass(frozen=True)
class IdempotencyResult:
    url: str
    key: str
    first_status: int
    second_status: int
    consistent: bool
    first_body: str = ""
    second_body: str = ""

    @property
    def passed(self) -> bool:
        return self.consistent and self.first_status == self.second_status

    def to_finding(self) -> Finding | None:
        if self.passed:
            return None
        return Finding(
            title="Checkout is not idempotent",
            severity=Severity.HIGH,
            category="checkout-idempotency",
            description="Replaying the same Idempotency-Key created a different result.",
            url=redact_url(self.url),
            evidence=f"status {self.first_status} -> {self.second_status}; body diff={self.first_body[:120] != self.second_body[:120]}",
            recommendation="Persist the idempotency key and replay the original response for repeats.",
        )


def check_idempotency(
    client: httpx.Client,
    url: str,
    payload: Mapping[str, Any],
    *,
    key: str = "qa-idempotency-key",
    headers: Mapping[str, str] | None = None,
) -> IdempotencyResult:
    """POST the same payload twice with one idempotency key and compare results."""
    request_headers = {"Idempotency-Key": key, **(headers or {})}
    try:
        first = client.post(url, json=payload, headers=request_headers)
        second = client.post(url, json=payload, headers=request_headers)
    except httpx.HTTPError as exc:
        return IdempotencyResult(url, key, 0, 0, False, f"transport error: {type(exc).__name__}", "")
    return IdempotencyResult(
        url=url,
        key=key,
        first_status=first.status_code,
        second_status=second.status_code,
        consistent=first.text.strip() == second.text.strip(),
        first_body=redact_text(first.text),
        second_body=redact_text(second.text),
    )
