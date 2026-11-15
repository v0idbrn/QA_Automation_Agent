# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Performance quality: bounded concurrency load tests with SLA and error gates.

The runner uses only the standard library (``urllib`` + ``ThreadPoolExecutor``)
so a load test never adds a dependency. Every sample is recorded, latency
statistics come from the shared API fuzzer helpers, and classification lives in
:func:`evaluate_load` so the thresholds are unit-testable without a network.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from qa_agent.api_fuzzer import LatencyStats, analyze_latency, percentile
from qa_agent.models import Finding, Severity
from qa_agent.redaction import redact_text, redact_url

__all__ = [
    "LoadConfig",
    "LoadReport",
    "LoadSample",
    "evaluate_load",
    "run_load_test",
]

_MAX_REQUESTS = 2000
_MAX_CONCURRENCY = 64


def _finding(
    title: str,
    severity: Severity,
    category: str,
    description: str,
    evidence: str = "",
    recommendation: str = "",
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        category=category,
        description=description,
        evidence=redact_text(evidence),
        recommendation=recommendation,
    )


@dataclass(frozen=True)
class LoadConfig:
    url: str
    method: str = "GET"
    requests: int = 20
    concurrency: int = 4
    timeout_s: float = 10.0
    sla_ms: float = 800.0
    max_error_rate: float = 0.01
    headers: tuple[tuple[str, str], ...] = ()
    body: str = ""

    def __post_init__(self) -> None:
        if not str(self.url).lower().startswith(("http://", "https://")):
            raise ValueError("load test target must be an http(s) URL")
        if self.requests < 1:
            raise ValueError("requests must be >= 1")
        if self.concurrency < 1:
            raise ValueError("concurrency must be >= 1")
        if self.method.upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}:
            raise ValueError(f"unsupported method {self.method!r}")

    @property
    def bounded_requests(self) -> int:
        return min(self.requests, _MAX_REQUESTS)

    @property
    def bounded_concurrency(self) -> int:
        return max(1, min(self.concurrency, _MAX_CONCURRENCY, self.bounded_requests))


@dataclass(frozen=True)
class LoadSample:
    index: int
    status: int
    duration_ms: float
    bytes: int = 0
    error: str = ""

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400

    @property
    def server_error(self) -> bool:
        return self.status >= 500

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "status": self.status,
            "duration_ms": round(self.duration_ms, 2),
            "bytes": self.bytes,
            "error": redact_text(self.error),
        }


@dataclass
class LoadReport:
    url: str = ""
    method: str = "GET"
    samples: list[LoadSample] = field(default_factory=list)
    duration_s: float = 0.0
    latency: LatencyStats | None = None
    error_rate: float = 0.0
    status_counts: dict[str, int] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    passed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": redact_url(self.url),
            "method": self.method,
            "samples": len(self.samples),
            "duration_s": round(self.duration_s, 3),
            "error_rate": round(self.error_rate, 4),
            "status_counts": dict(self.status_counts),
            "latency": self.latency.to_dict() if self.latency else None,
            "passed": self.passed,
            "findings": [finding.to_dict() for finding in self.findings],
        }


def _one_request(index: int, config: LoadConfig, opener: urllib.request.OpenerDirector) -> LoadSample:
    request = urllib.request.Request(config.url, method=config.method.upper())
    for name, value in config.headers:
        request.add_header(name, value)
    data = config.body.encode("utf-8") if config.body else None
    started = time.perf_counter()
    try:
        with opener.open(request, data=data, timeout=config.timeout_s) as response:
            payload = response.read()
            return LoadSample(
                index=index,
                status=int(response.status),
                duration_ms=(time.perf_counter() - started) * 1000,
                bytes=len(payload),
            )
    except urllib.error.HTTPError as exc:
        return LoadSample(
            index=index,
            status=int(exc.code),
            duration_ms=(time.perf_counter() - started) * 1000,
            error=f"HTTP {exc.code}",
        )
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        return LoadSample(
            index=index,
            status=0,
            duration_ms=(time.perf_counter() - started) * 1000,
            error=f"{type(exc).__name__}: {exc}",
        )


def evaluate_load(
    samples: Sequence[LoadSample],
    *,
    config: LoadConfig,
    duration_s: float,
) -> LoadReport:
    """Classify recorded samples against the SLA and error-rate gates."""
    report = LoadReport(url=config.url, method=config.method.upper(), samples=list(samples))
    report.duration_s = max(0.0, float(duration_s))
    report.latency = analyze_latency([sample.duration_ms for sample in samples], config.sla_ms, report.duration_s)
    total = len(samples)
    failures = [sample for sample in samples if not sample.ok]
    report.error_rate = (len(failures) / total) if total else 1.0
    counts: dict[str, int] = {}
    for sample in samples:
        key = str(sample.status) if sample.status else "error"
        counts[key] = counts.get(key, 0) + 1
    report.status_counts = dict(sorted(counts.items()))

    if not samples:
        report.findings.append(
            _finding(
                "Load test produced no samples",
                Severity.HIGH,
                "perf-no-samples",
                "No request completed, so throughput and latency are unknown.",
                "samples=0",
                "Verify the target is reachable and re-run the load test.",
            )
        )
    else:
        latency = report.latency
        assert latency is not None
        for metric, value in (("p50", latency.p50_ms), ("p95", latency.p95_ms), ("p99", latency.p99_ms)):
            if config.sla_ms > 0 and value > config.sla_ms:
                report.findings.append(
                    _finding(
                        f"{metric.upper()} latency above SLA",
                        Severity.HIGH if metric == "p95" else Severity.MEDIUM,
                        "perf-latency-sla",
                        f"{metric.upper()} was {value:.1f}ms against a {config.sla_ms:.0f}ms budget.",
                        f"{metric}={value:.1f}ms sla={config.sla_ms:.0f}ms samples={total}",
                        "Profile the slowest endpoint, cache or index the data path, and re-measure.",
                    )
                )
        if report.error_rate > config.max_error_rate:
            report.findings.append(
                _finding(
                    "Error rate above the tolerance",
                    Severity.HIGH if report.error_rate >= 0.05 else Severity.MEDIUM,
                    "perf-error-rate",
                    f"{report.error_rate:.1%} of requests failed against a {config.max_error_rate:.1%} budget.",
                    f"failures={len(failures)} total={total} statuses={report.status_counts}",
                    "Fix the failing dependency before increasing load.",
                )
            )
        server_errors = sum(1 for sample in samples if sample.server_error)
        if server_errors:
            report.findings.append(
                _finding(
                    "Server returned 5xx under load",
                    Severity.HIGH,
                    "perf-server-error",
                    f"{server_errors} request(s) failed inside the application.",
                    f"statuses={report.status_counts}",
                    "Check worker saturation, connection limits, and upstream timeouts.",
                )
            )
        client_errors = sum(1 for sample in samples if 400 <= sample.status < 500 and sample.status != 429)
        if client_errors:
            report.findings.append(
                _finding(
                    "Client errors under load",
                    Severity.MEDIUM,
                    "perf-client-error",
                    f"{client_errors} request(s) returned 4xx, so the request contract is wrong.",
                    f"statuses={report.status_counts}",
                    "Align headers, body, and method with the documented contract.",
                )
            )
        throttled = sum(1 for sample in samples if sample.status == 429)
        if throttled and config.sla_ms > 0 and latency.p95_ms > config.sla_ms:
            report.findings.append(
                _finding(
                    "Rate limiting observed",
                    Severity.INFO,
                    "perf-throttle",
                    f"{throttled} request(s) were throttled with 429.",
                    f"throttled={throttled}",
                    "Distinguish throttling from capacity when reading the latency numbers.",
                )
            )

        monotonic = all(
            later.duration_ms >= earlier.duration_ms * 0.5
            for earlier, later in zip(samples, samples[1:])
        )
        if total >= 10 and not monotonic and config.concurrency == 1:
            report.findings.append(
                _finding(
                    "Latency is unstable at concurrency 1",
                    Severity.LOW,
                    "perf-jitter",
                    "Sequential samples vary by more than 2x, suggesting a cold cache or GC pauses.",
                    f"p50={latency.p50_ms:.1f}ms max={latency.max_ms:.1f}ms",
                    "Warm the service and re-measure before publishing an SLA.",
                )
            )

    report.passed = not any(
        finding.severity in {Severity.CRITICAL, Severity.HIGH} for finding in report.findings
    )
    return report


def run_load_test(config: LoadConfig, *, preview: bool = False) -> LoadReport:
    """Run a bounded load test.

    ``preview=True`` performs a single probe request and evaluates it against
    the full plan, which keeps CLI smoke checks cheap.
    """
    total = 1 if preview else config.bounded_requests
    concurrency = 1 if preview else config.bounded_concurrency
    opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler())
    samples: list[LoadSample] = []
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="qa-load") as pool:
        futures = [pool.submit(_one_request, index, config, opener) for index in range(total)]
        samples = [future.result() for future in futures]
    elapsed = time.perf_counter() - started
    report = evaluate_load(samples, config=config, duration_s=elapsed)
    report.findings.extend(_api_contract_findings(config))
    report.passed = not any(
        finding.severity in {Severity.CRITICAL, Severity.HIGH} for finding in report.findings
    )
    return report


def _api_contract_findings(config: LoadConfig) -> list[Finding]:
    findings: list[Finding] = []
    parts = urlsplit(config.url)
    if parts.scheme == "http" and parts.hostname not in {"localhost", "127.0.0.1", "::1"}:
        findings.append(
            _finding(
                "Load test target is not HTTPS",
                Severity.MEDIUM,
                "perf-transport",
                "Production traffic must not run over plain HTTP.",
                redact_url(config.url),
                "Re-run the load test against the TLS endpoint.",
            )
        )
    if config.requests > _MAX_REQUESTS:
        findings.append(
            _finding(
                "Request count was capped",
                Severity.INFO,
                "perf-bounded",
                f"{config.requests} requests exceeded the safe bound of {_MAX_REQUESTS}.",
                f"requests={_MAX_REQUESTS}",
                "Use a dedicated load generator for large volumes.",
            )
        )
    if config.concurrency > _MAX_CONCURRENCY:
        findings.append(
            _finding(
                "Concurrency was capped",
                Severity.INFO,
                "perf-bounded",
                f"Concurrency was capped at {_MAX_CONCURRENCY}.",
                f"concurrency={_MAX_CONCURRENCY}",
                "Scale the generator horizontally instead of one huge client.",
            )
        )
    return findings


def summarize_samples(samples: Sequence[LoadSample]) -> dict[str, float]:
    """Small helper used by the CLI summary and the tests."""
    values = [sample.duration_ms for sample in samples]
    return {
        "p50_ms": round(percentile(values, 0.50), 2),
        "p95_ms": round(percentile(values, 0.95), 2),
        "p99_ms": round(percentile(values, 0.99), 2),
        "throughput_rps": round(len(values) / max(1e-9, sum(values) / 1000), 2),
    }


def dump_report(report: LoadReport, path: str) -> None:
    """Persist the report as JSON next to the other CLI artifacts."""
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report.to_dict(), handle, indent=2)
