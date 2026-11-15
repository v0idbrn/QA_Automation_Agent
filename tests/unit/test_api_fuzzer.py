# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Unit tests for contract fuzzing, OpenAPI parsing, GraphQL probes, and latency."""

from __future__ import annotations

import json

import httpx
import pytest

from qa_agent.api_fuzzer import (
    PAYLOAD_KINDS,
    ApiFuzzer,
    Endpoint,
    FuzzCase,
    FuzzReport,
    classify_result,
    endpoints_from_openapi,
    graphql_alias_batch,
    graphql_depth_query,
    graphql_error_leak,
    graphql_introspection_exposed,
    load_openapi,
    analyze_latency,
    analyze_sla,
    build_cases,
    percentile,
)

ENDPOINT = Endpoint("post", "/api/validate", field="input")


def transport(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


@pytest.mark.parametrize(
    ("kind", "count"),
    [
        ("empty", 3),
        ("unicode", 5),
        ("sql", 4),
        ("xss", 3),
        ("type", 8),
        ("oversize", 1),
    ],
)
def test_payload_catalog_sizes(kind: str, count: int) -> None:
    assert len(PAYLOAD_KINDS[kind]) == count


def test_build_cases_covers_every_kind() -> None:
    cases = build_cases(ENDPOINT)
    assert len(cases) == sum(len(values) for values in PAYLOAD_KINDS.values())
    assert {case.payload_kind for case in cases} == set(PAYLOAD_KINDS)


def test_build_cases_can_be_narrowed() -> None:
    cases = build_cases(ENDPOINT, kinds=["sql"])
    assert len(cases) == len(PAYLOAD_KINDS["sql"])


def test_endpoint_normalizes_method_and_path() -> None:
    endpoint = Endpoint("post", "api/x")
    assert endpoint.method == "POST"
    assert endpoint.path == "/api/x"


@pytest.mark.parametrize(
    ("kind", "status", "body", "expected"),
    [
        ("empty", 400, "", "rejected-clean"),
        ("empty", 422, "", "rejected-clean"),
        ("empty", 500, "", "server-error"),
        ("empty", 200, "", "accepted"),
        ("sql", 200, "{' OR '1'='1'}", "reflected-payload"),
        ("sql", 400, "", "rejected-clean"),
        ("xss", 200, "<script>alert(1)</script>", "reflected-payload"),
        ("xss", 403, "", "rejected-clean"),
    ],
)
def test_classify_result(kind: str, status: int, body: str, expected: str) -> None:
    case = FuzzCase(ENDPOINT, kind, PAYLOAD_KINDS[kind][0])
    assert classify_result(case, status, body) == expected


def test_classify_transport_error() -> None:
    assert classify_result(FuzzCase(ENDPOINT, "empty", ""), None) == "transport-error"


OPENAPI = {
    "openapi": "3.0.0",
    "servers": [{"url": "https://api.example.com"}],
    "paths": {
        "/orders": {
            "post": {"requestBody": {"content": {"application/json": {"schema": {"properties": {"quantity": {"type": "integer"}}}}}}},
        },
        "/search": {"get": {}},
        "/settings": {"patch": {"security": [{"bearer": []}]}},
    },
}


def test_endpoints_from_openapi_reads_body_fields() -> None:
    endpoints = endpoints_from_openapi(OPENAPI)
    assert [(endpoint.method, endpoint.path, endpoint.field) for endpoint in endpoints] == [
        ("POST", "/orders", "quantity"),
        ("PATCH", "/settings", "input"),
    ]
    assert endpoints[1].requires_auth is True


def test_endpoints_from_openapi_max_endpoints() -> None:
    assert len(endpoints_from_openapi(OPENAPI, max_endpoints=1)) == 1


def test_endpoints_from_openapi_ignores_non_mapping_paths() -> None:
    assert endpoints_from_openapi({"paths": {"/x": "not-a-mapping"}}) == []


def test_load_openapi_from_mapping() -> None:
    assert load_openapi(OPENAPI)["openapi"] == "3.0.0"


def test_load_openapi_from_file(tmp_path) -> None:
    path = tmp_path / "openapi.json"
    path.write_text(json.dumps(OPENAPI), encoding="utf-8")
    assert load_openapi(path)["servers"][0]["url"] == "https://api.example.com"


@pytest.mark.parametrize(
    ("values", "fraction", "expected"),
    [
        ([], 0.5, 0.0),
        ([42], 0.95, 42.0),
        ([1, 2, 3, 4, 5], 0.5, 3.0),
        ([1, 2, 3, 4, 5], 0.95, 5.0),
        ([5, 1, 3], 0.5, 3.0),
    ],
)
def test_percentile(values: list[float], fraction: float, expected: float) -> None:
    assert percentile(values, fraction) == expected


def test_analyze_latency_statistics() -> None:
    stats = analyze_latency([10, 20, 30, 40, 50], sla_ms=45, duration_s=1.0)
    assert stats.count == 5
    assert stats.p50_ms == 30
    assert stats.p95_ms == 50
    assert stats.p99_ms == 50
    assert stats.max_ms == 50
    assert stats.throughput_rps == 5
    assert stats.sla_violations == 2
    assert stats.passed is False


def test_analyze_latency_within_sla() -> None:
    stats = analyze_latency([10, 20, 30], sla_ms=100)
    assert stats.passed is True
    assert stats.sla_violations == 0


def test_analyze_latency_without_sla() -> None:
    assert analyze_latency([10]).passed is True


def test_analyze_latency_empty() -> None:
    stats = analyze_latency([], sla_ms=100)
    assert stats.count == 0
    assert stats.p95_ms == 0


def test_analyze_sla_lists_breaches() -> None:
    stats = analyze_latency([10, 200, 300], sla_ms=100)
    breaches = analyze_sla(stats)
    assert [breach.metric for breach in breaches] == ["p50_latency", "p95_latency", "p99_latency"]


def test_analyze_sla_without_limit() -> None:
    assert analyze_sla(analyze_latency([10])) == []


def test_stats_serialize() -> None:
    payload = analyze_latency([10, 20], sla_ms=100).to_dict()
    assert payload["count"] == 2
    assert payload["passed"] is True


def test_graphql_introspection_detected() -> None:
    assert graphql_introspection_exposed({"data": {"__schema": {"types": [{"name": "User"}]}}}) is True


def test_graphql_introspection_absent() -> None:
    assert graphql_introspection_exposed({"data": {"user": {"id": 1}}}) is False
    assert graphql_introspection_exposed({}) is False


@pytest.mark.parametrize(
    "errors",
    [
        [{"stacktrace": "at resolve (/app/src/resolver.js:10)"}],
        [{"message": "SQLSTATE[42000]"}],
        [{"message": "boom", "path": ["node_modules"]}],
    ],
)
def test_graphql_error_leak_detected(errors: list) -> None:
    assert graphql_error_leak({"errors": errors}) is True


def test_graphql_error_leak_clean() -> None:
    assert graphql_error_leak({"errors": [{"message": "invalid field"}]}) is False
    assert graphql_error_leak({"data": {}}) is False


def test_graphql_depth_query_bounds() -> None:
    assert graphql_depth_query(depth=2).count("user {") == 2
    assert graphql_depth_query(depth=100).count("user {") == 30


def test_graphql_alias_batch() -> None:
    query = graphql_alias_batch(count=3)
    assert "a0:" in query and "a2:" in query
    assert "a3:" not in query


def test_fuzz_report_gate_and_serialization() -> None:
    report = FuzzReport(base_url="https://api.example.com/?token=abc")
    assert report.passed is True
    payload = report.to_dict()
    assert "abc" not in payload["base_url"]


def test_fuzzer_clean_4xx_endpoint_passes() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": "validation"})

    with transport(handler) as client:
        report = ApiFuzzer(max_cases=10).run("http://api.test", [ENDPOINT], client=client)
    assert len(report.results) == 10
    assert report.passed is True
    assert report.server_error_count == 0


def test_fuzzer_detects_500_crash() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    with transport(handler) as client:
        report = ApiFuzzer(max_cases=3).run("http://api.test", [ENDPOINT], client=client)
    assert report.server_error_count == 3
    assert report.passed is False
    assert any(finding.category == "api-server-error" for finding in report.findings)


def test_fuzzer_detects_reflected_xss() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content.decode())
        return httpx.Response(200, json={"echo": payload["input"]})

    with transport(handler) as client:
        report = ApiFuzzer(max_cases=24).run("http://api.test", [ENDPOINT], client=client)
    assert any(finding.category == "api-xss-reflection" for finding in report.findings)


def test_fuzzer_detects_missing_auth() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "authorization" not in {key.lower() for key in request.headers}:
            return httpx.Response(200, json={"secret": "data"})
        return httpx.Response(400, json={"error": "validation"})

    endpoint = Endpoint("POST", "/api/orders", requires_auth=True)
    with transport(handler) as client:
        report = ApiFuzzer(auth_header=("Authorization", "Bearer token"), max_cases=1).run(
            "http://api.test", [endpoint], client=client
        )
    assert any(finding.category == "api-auth-bypass" for finding in report.findings)


def test_fuzzer_rejects_anonymous_request_cleanly() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "unauthorized"})

    endpoint = Endpoint("POST", "/api/orders", requires_auth=True)
    with transport(handler) as client:
        report = ApiFuzzer(auth_header=("Authorization", "Bearer token"), max_cases=1).run(
            "http://api.test", [endpoint], client=client
        )
    assert not any(finding.category == "api-auth-bypass" for finding in report.findings)


def test_fuzzer_handles_transport_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    with transport(handler) as client:
        report = ApiFuzzer(max_cases=2).run("http://api.test", [ENDPOINT], client=client)
    assert all(result.verdict == "transport-error" for result in report.results)
    assert any(finding.category == "api-transport" for finding in report.findings)


def test_fuzzer_respects_max_cases() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400)

    with transport(handler) as client:
        report = ApiFuzzer(max_cases=1).run("http://api.test", [ENDPOINT], client=client)
    assert len(report.results) == 1


def test_fuzzer_graphql_probes() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        query = json.loads(request.content.decode()).get("query", "")
        if "__schema" in query:
            return httpx.Response(200, json={"data": {"__schema": {"types": [{"name": "User"}]}}})
        if "nonexistentField" in query:
            return httpx.Response(200, json={"errors": [{"stacktrace": "at resolve (/app/x.js:1)"}]})
        return httpx.Response(200, json={"data": {"ok": True}})

    with transport(handler) as client:
        report = ApiFuzzer(max_cases=1).run("http://api.test", [ENDPOINT], client=client, graphql_path="/graphql")
    categories = {finding.category for finding in report.graphql_findings}
    assert {"graphql-introspection", "graphql-complexity", "graphql-error-leak"} <= categories


def test_fuzzer_adds_sla_finding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400)

    with transport(handler) as client:
        report = ApiFuzzer(max_cases=1, sla_ms=0.0001).run("http://api.test", [ENDPOINT], client=client)
    assert any(finding.category == "api-latency-sla" for finding in report.findings)
