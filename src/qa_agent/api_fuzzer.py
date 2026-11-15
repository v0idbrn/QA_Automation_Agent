# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""REST/GraphQL contract fuzzing and latency SLA profiling.

Fuzzing is intentionally non-destructive: payloads are the classic validation
probes (empty strings, Unicode, type confusion, SQL/XSS metacharacters) and the
assertion is behavioural - a clean 4xx is a pass, a 500 or a reflected payload
is a defect. Oversized bodies are capped so a run stays bounded.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import httpx

from qa_agent.models import Finding, Severity
from qa_agent.redaction import redact_text, redact_url

__all__ = [
    "ApiFuzzer",
    "Endpoint",
    "FuzzCase",
    "FuzzReport",
    "FuzzResult",
    "LatencyStats",
    "SLABreach",
    "analyze_latency",
    "build_cases",
    "classify_result",
    "endpoints_from_openapi",
    "graphql_alias_batch",
    "graphql_depth_query",
    "graphql_error_leak",
    "graphql_introspection_exposed",
    "load_openapi",
    "percentile",
]

MAX_OVERSIZE = 50_000

EMPTY_PAYLOADS = ["", "   ", "\t\n"]
UNICODE_PAYLOADS = ["日本語テスト", "😀🔥💥", "مرحبا بالعالم", "a\x00b", "é" * 200]
SQL_PAYLOADS = ["' OR '1'='1", "'; DROP TABLE users;--", "1 UNION SELECT NULL--", "admin'--"]
XSS_PAYLOADS = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', "javascript:alert(document.cookie)"]
TYPE_CONFUSION_PAYLOADS: list[Any] = [None, [], {}, 0, "string", True, -1, 1.5]

PAYLOAD_KINDS: dict[str, list[Any]] = {
    "empty": EMPTY_PAYLOADS,
    "unicode": UNICODE_PAYLOADS,
    "sql": SQL_PAYLOADS,
    "xss": XSS_PAYLOADS,
    "type": TYPE_CONFUSION_PAYLOADS,
    "oversize": ["x" * MAX_OVERSIZE],
}


@dataclass(frozen=True)
class Endpoint:
    method: str
    path: str
    field: str = "input"
    requires_auth: bool = False
    content_type: str = "json"

    def __post_init__(self) -> None:
        object.__setattr__(self, "method", self.method.upper())
        if not self.path.startswith("/"):
            object.__setattr__(self, "path", "/" + self.path)


@dataclass(frozen=True)
class FuzzCase:
    endpoint: Endpoint
    payload_kind: str
    payload: Any


def build_cases(endpoint: Endpoint, kinds: Iterable[str] = PAYLOAD_KINDS.keys()) -> list[FuzzCase]:
    return [FuzzCase(endpoint, kind, payload) for kind in kinds for payload in PAYLOAD_KINDS.get(kind, ())]


# ---------------------------------------------------------------------------
# OpenAPI
# ---------------------------------------------------------------------------


def load_openapi(source: str | Path | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(source, Mapping):
        return dict(source)
    text = Path(source).read_text(encoding="utf-8")
    return json.loads(text)


def endpoints_from_openapi(spec: Mapping[str, Any], max_endpoints: int = 25) -> list[Endpoint]:
    """Derive request-body endpoints from an OpenAPI 3 document."""
    endpoints: list[Endpoint] = []
    for path, operations in (spec.get("paths") or {}).items():
        if not isinstance(operations, Mapping):
            continue
        for method, operation in operations.items():
            if str(method).lower() not in {"post", "put", "patch"} or not isinstance(operation, Mapping):
                continue
            field_name = "input"
            request_body = operation.get("requestBody") or {}
            content = (request_body.get("content") or {}) if isinstance(request_body, Mapping) else {}
            schema = ((content.get("application/json") or {}).get("schema") or {}) if isinstance(content, Mapping) else {}
            properties = schema.get("properties") if isinstance(schema, Mapping) else None
            if isinstance(properties, Mapping) and properties:
                field_name = str(next(iter(properties)))
            endpoints.append(
                Endpoint(
                    method=str(method),
                    path=str(path),
                    field=field_name,
                    requires_auth=bool(operation.get("security")),
                )
            )
            if len(endpoints) >= max_endpoints:
                return endpoints
    return endpoints


# ---------------------------------------------------------------------------
# Result classification
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FuzzResult:
    endpoint: Endpoint
    payload_kind: str
    status: int | None
    verdict: str
    body_excerpt: str = ""
    duration_ms: float = 0.0

    @property
    def passed(self) -> bool:
        return self.verdict in {"rejected-clean", "accepted"}


def classify_result(case: FuzzCase, status: int | None, body: str = "") -> str:
    if status is None:
        return "transport-error"
    if status >= 500:
        return "server-error"
    if 400 <= status < 500:
        return "rejected-clean"
    if case.payload_kind in {"sql", "xss"}:
        if str(case.payload) and str(case.payload) in (body or ""):
            return "reflected-payload"
        return "accepted"
    return "accepted"


def _finding_for(result: FuzzResult, url: str) -> Finding | None:
    if result.passed:
        return None
    severity = Severity.HIGH
    category = "api-server-error"
    title = f"Unhandled {result.status or 'transport'} response on fuzz input"
    recommendation = "Validate the input and return a documented 4xx envelope; never leak a 500."
    if result.payload_kind in {"sql", "xss"}:
        severity = Severity.CRITICAL
        title = f"Potential injection ({result.payload_kind}) reached the server"
        recommendation = "Reject metacharacters at the boundary and parameterize every query."
    if result.verdict == "reflected-payload":
        severity = Severity.CRITICAL
        category = "api-xss-reflection"
        title = "User input reflected unescaped"
        recommendation = "Encode output for its context and validate input server-side."
    elif result.verdict == "transport-error":
        severity = Severity.MEDIUM
        category = "api-transport"
        title = "Request failed before a response"
        recommendation = "Check availability, timeouts, and request shape."
    return Finding(
        title=title,
        severity=severity,
        category=category,
        description=f"{result.endpoint.method} {result.endpoint.path} returned {result.status} for a {result.payload_kind} payload.",
        url=redact_url(url),
        evidence=redact_text(f"status={result.status} verdict={result.verdict} body={result.body_excerpt[:200]}"),
        reproduction=redact_text(f"{result.endpoint.method} {url} with a {result.payload_kind} payload"),
        recommendation=recommendation,
    )


# ---------------------------------------------------------------------------
# Latency
# ---------------------------------------------------------------------------


def percentile(values: Sequence[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(0, min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1)))))
    return float(ordered[rank])


@dataclass(frozen=True)
class LatencyStats:
    count: int
    p50_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float
    throughput_rps: float
    sla_ms: float = 0.0

    @property
    def sla_violations(self) -> int:
        return 0 if self.sla_ms <= 0 else sum(1 for value in (self.p50_ms, self.p95_ms, self.p99_ms) if value > self.sla_ms)

    @property
    def passed(self) -> bool:
        return self.p95_ms <= self.sla_ms if self.sla_ms > 0 else True

    def to_dict(self) -> dict[str, Any]:
        return {
            "count": self.count,
            "p50_ms": round(self.p50_ms, 2),
            "p95_ms": round(self.p95_ms, 2),
            "p99_ms": round(self.p99_ms, 2),
            "max_ms": round(self.max_ms, 2),
            "throughput_rps": round(self.throughput_rps, 2),
            "sla_ms": self.sla_ms,
            "sla_violations": self.sla_violations,
            "passed": self.passed,
        }


def analyze_latency(samples_ms: Sequence[float], sla_ms: float = 0.0, duration_s: float | None = None) -> LatencyStats:
    values = [float(value) for value in samples_ms]
    total = sum(values)
    duration = duration_s if duration_s and duration_s > 0 else (total / 1000.0 or 1e-9)
    return LatencyStats(
        count=len(values),
        p50_ms=percentile(values, 0.50),
        p95_ms=percentile(values, 0.95),
        p99_ms=percentile(values, 0.99),
        max_ms=max(values) if values else 0.0,
        throughput_rps=len(values) / duration,
        sla_ms=sla_ms,
    )


@dataclass(frozen=True)
class SLABreach:
    metric: str
    measured_ms: float
    limit_ms: float
    severity: Severity = Severity.HIGH


def analyze_sla(stats: LatencyStats) -> list[SLABreach]:
    if stats.sla_ms <= 0:
        return []
    breaches: list[SLABreach] = []
    for metric, value in (("p50", stats.p50_ms), ("p95", stats.p95_ms), ("p99", stats.p99_ms)):
        if value > stats.sla_ms:
            breaches.append(SLABreach(f"{metric}_latency", value, stats.sla_ms))
    return breaches


# ---------------------------------------------------------------------------
# GraphQL
# ---------------------------------------------------------------------------


def graphql_introspection_exposed(payload: Mapping[str, Any]) -> bool:
    data = payload.get("data")
    if not isinstance(data, Mapping):
        return False
    types = (data.get("__schema") or {}).get("types") if isinstance(data.get("__schema"), Mapping) else None
    return bool(types)


def graphql_error_leak(payload: Mapping[str, Any]) -> bool:
    errors = payload.get("errors")
    if not isinstance(errors, list):
        return False
    markers = ("Traceback", "SQLSTATE", "/app/", "at resolve", "node_modules", "stacktrace")
    for error in errors:
        text = json.dumps(error, default=str)
        if any(marker in text for marker in markers):
            return True
    return False


def graphql_depth_query(field: str = "user", depth: int = 8) -> str:
    depth = max(1, min(depth, 30))
    node = f"{field} {{ id "
    return "query QA { " + node * depth + "}" * depth + " }"


def graphql_alias_batch(count: int = 50, field: str = "user") -> str:
    aliases = " ".join(f"a{index}: {field}(id: {index}) {{ id }}" for index in range(max(1, count)))
    return "query QA { " + aliases + " }"


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

GRAPHQL_CASES: tuple[tuple[str, str], ...] = (
    ("introspection", "query QA { __schema { types { name } } }"),
    ("deep-query", graphql_depth_query()),
    ("alias-batch", graphql_alias_batch()),
    ("broken-query", "query QA { nonexistentField { id } }"),
)


@dataclass
class FuzzReport:
    base_url: str
    results: list[FuzzResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    latency: LatencyStats | None = None
    graphql_findings: list[Finding] = field(default_factory=list)
    duration_ms: float = 0.0

    @property
    def passed(self) -> bool:
        return not any(finding.severity in {Severity.CRITICAL, Severity.HIGH} for finding in self.findings + self.graphql_findings)

    @property
    def server_error_count(self) -> int:
        return sum(1 for result in self.results if result.verdict == "server-error")

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_url": redact_url(self.base_url),
            "passed": self.passed,
            "results": len(self.results),
            "server_errors": self.server_error_count,
            "findings": [finding.to_dict() for finding in self.findings],
            "graphql_findings": [finding.to_dict() for finding in self.graphql_findings],
            "latency": None if self.latency is None else self.latency.to_dict(),
            "duration_ms": round(self.duration_ms, 2),
        }


class ApiFuzzer:
    """Bounded fuzzing against a base URL, optionally with an auth header."""

    def __init__(
        self,
        *,
        timeout: float = 10.0,
        auth_header: tuple[str, str] | None = None,
        sla_ms: float = 0.0,
        max_cases: int = 120,
    ) -> None:
        self.timeout = timeout
        self.auth_header = auth_header
        self.sla_ms = sla_ms
        self.max_cases = max(1, max_cases)

    def _headers(self, endpoint: Endpoint, include_auth: bool = True) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if include_auth and self.auth_header:
            headers[self.auth_header[0]] = self.auth_header[1]
        return headers

    def run(
        self,
        base_url: str,
        endpoints: Sequence[Endpoint],
        *,
        client: httpx.Client | None = None,
        graphql_path: str | None = None,
        include_missing_auth: bool = True,
    ) -> FuzzReport:
        started = time.perf_counter()
        report = FuzzReport(base_url=base_url)
        owned = client is None
        http = client or httpx.Client(timeout=self.timeout, follow_redirects=False)
        samples: list[float] = []
        try:
            cases: list[FuzzCase] = []
            for endpoint in endpoints:
                cases.extend(build_cases(endpoint))
            for case in cases[: self.max_cases]:
                result = self._execute(http, base_url, case)
                report.results.append(result)
                if result.duration_ms:
                    samples.append(result.duration_ms)
                finding = _finding_for(result, f"{base_url}{case.endpoint.path}")
                if finding is not None:
                    report.findings.append(finding)
            if include_missing_auth and self.auth_header:
                for endpoint in endpoints:
                    if not endpoint.requires_auth:
                        continue
                    case = FuzzCase(endpoint, "missing-auth", {"id": 1})
                    result = self._execute(http, base_url, case, include_auth=False)
                    report.results.append(result)
                    if result.verdict != "rejected-clean":
                        report.findings.append(
                            Finding(
                                title="Authenticated endpoint accepted an anonymous request",
                                severity=Severity.CRITICAL,
                                category="api-auth-bypass",
                                description="A request without credentials was not rejected with a 4xx.",
                                url=redact_url(f"{base_url}{endpoint.path}"),
                                evidence=f"status={result.status}",
                                recommendation="Enforce authentication server-side and return 401/403.",
                            )
                        )
            if graphql_path:
                report.graphql_findings.extend(self._probe_graphql(http, base_url, graphql_path))
            report.latency = analyze_latency(samples, self.sla_ms)
            for breach in analyze_sla(report.latency):
                report.findings.append(
                    Finding(
                        title=f"Latency SLA breached ({breach.metric})",
                        severity=breach.severity,
                        category="api-latency-sla",
                        description=f"{breach.metric} latency exceeds the declared SLA.",
                        url=redact_url(base_url),
                        evidence=f"{breach.measured_ms:.1f}ms > {breach.limit_ms:.1f}ms",
                        recommendation="Profile the slow endpoint and add caching or indexing.",
                    )
                )
            return report
        finally:
            if owned:
                http.close()
            report.duration_ms = (time.perf_counter() - started) * 1000.0

    def _execute(self, client: httpx.Client, base_url: str, case: FuzzCase, include_auth: bool = True) -> FuzzResult:
        url = base_url.rstrip("/") + case.endpoint.path
        body: Any = case.payload if case.payload_kind != "missing-auth" else {}
        if case.endpoint.content_type == "json":
            target_field = case.endpoint.field
            if isinstance(body, Mapping) and target_field in body:
                payload: Any = body
            else:
                payload = {target_field: body}
            kwargs: dict[str, Any] = {"json": payload}
        else:
            payload = str(body).encode("utf-8", "ignore")
            kwargs = {"content": payload}
        started = time.perf_counter()
        try:
            response = client.request(
                case.endpoint.method,
                url,
                headers=self._headers(case.endpoint, include_auth),
                **kwargs,
            )
        except httpx.HTTPError as exc:
            return FuzzResult(case.endpoint, case.payload_kind, None, "transport-error", type(exc).__name__, (time.perf_counter() - started) * 1000)
        duration = (time.perf_counter() - started) * 1000
        return FuzzResult(
            endpoint=case.endpoint,
            payload_kind=case.payload_kind,
            status=response.status_code,
            verdict=classify_result(case, response.status_code, response.text),
            body_excerpt=redact_text(response.text[:300]),
            duration_ms=duration,
        )

    def _probe_graphql(self, client: httpx.Client, base_url: str, path: str) -> list[Finding]:
        findings: list[Finding] = []
        url = base_url.rstrip("/") + (path if path.startswith("/") else "/" + path)
        for label, query in GRAPHQL_CASES:
            try:
                response = client.post(url, json={"query": query}, headers=self._headers(Endpoint("POST", path)))
            except httpx.HTTPError:
                continue
            try:
                payload = response.json()
            except ValueError:
                payload = {}
            if not isinstance(payload, Mapping):
                payload = {}
            if label == "introspection" and graphql_introspection_exposed(payload):
                findings.append(
                    Finding(
                        title="GraphQL introspection is publicly enabled",
                        severity=Severity.MEDIUM,
                        category="graphql-introspection",
                        description="Production introspection reveals the full schema.",
                        url=redact_url(url),
                        evidence="__schema.types returned",
                        recommendation="Disable introspection outside development.",
                    )
                )
            if label in {"deep-query", "alias-batch"} and response.status_code < 500 and not payload.get("errors"):
                findings.append(
                    Finding(
                        title=f"GraphQL accepted an unbounded {label}",
                        severity=Severity.MEDIUM,
                        category="graphql-complexity",
                        description="No depth or alias limit rejected an abusive query.",
                        url=redact_url(url),
                        evidence=f"query={label} status={response.status_code}",
                        recommendation="Enforce max depth, alias, and cost limits.",
                    )
                )
            if graphql_error_leak(payload):
                findings.append(
                    Finding(
                        title="GraphQL error leaks implementation details",
                        severity=Severity.HIGH,
                        category="graphql-error-leak",
                        description="The errors array exposes server internals.",
                        url=redact_url(url),
                        evidence=redact_text(json.dumps(payload.get("errors"))[:240]),
                        recommendation="Return a generic error code and log details server-side.",
                    )
                )
        return findings
