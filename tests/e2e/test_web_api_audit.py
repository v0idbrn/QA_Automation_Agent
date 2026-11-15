# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""API contract and Playwright mobile-layout audit suite."""

from __future__ import annotations

import asyncio
import threading
from typing import Literal

import httpx
from pydantic import BaseModel, ConfigDict

from qa_agent.web_auditor import (
    audit_error_response,
    audit_json_contract,
    audit_web_page,
    validate_payload,
)
from tests.e2e.fixture_data import asgi_app


class HealthCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    ok: bool


class Health(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["ok", "degraded"]
    version: str
    checks: list[HealthCheck]


class Item(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int
    name: str
    price: float
    tags: list[str]


# ---------------------------------------------------------------------------
# API contracts over the local HTTP fixture
# ---------------------------------------------------------------------------


def test_health_endpoint_matches_contract(fixture_server: str) -> None:
    result = audit_json_contract(f"{fixture_server}/api/health", Health)
    assert result.passed is True
    assert result.status_code == 200
    assert result.payload["status"] == "ok"


def test_item_endpoint_matches_contract(fixture_server: str) -> None:
    result = audit_json_contract(f"{fixture_server}/api/items/1", Item)
    assert result.passed is True
    assert result.payload["tags"] == ["alpha", "beta"]


def test_wrong_field_types_break_the_contract(fixture_server: str) -> None:
    result = audit_json_contract(f"{fixture_server}/api/items/bad", Item)
    assert result.passed is False
    assert any("id" in error for error in result.errors)
    assert any("price" in error for error in result.errors)


def test_missing_fields_break_the_contract(fixture_server: str) -> None:
    result = audit_json_contract(f"{fixture_server}/api/incomplete", Item)
    assert result.passed is False
    assert len(result.errors) == 3


def test_unexpected_extra_field_breaks_the_contract(fixture_server: str) -> None:
    result = audit_json_contract(f"{fixture_server}/api/extra", Item)
    assert result.passed is False
    assert any("debug" in error for error in result.errors)


def test_404_error_envelope_is_valid(fixture_server: str) -> None:
    result = audit_error_response(f"{fixture_server}/api/missing", expected_status=404)
    assert result.passed is True
    assert result.payload["error"] == "not_found"


def test_500_error_envelope_is_valid(fixture_server: str) -> None:
    result = audit_error_response(f"{fixture_server}/api/crash", expected_status=500)
    assert result.passed is True
    assert result.payload["error"] == "internal_error"


def test_error_envelope_must_not_leak_a_traceback(fixture_server: str) -> None:
    result = audit_error_response(f"{fixture_server}/api/leaky-error", expected_status=500)
    assert result.passed is False
    assert any("traceback" in error for error in result.errors)


def test_non_json_response_is_flagged(fixture_server: str) -> None:
    result = audit_json_contract(f"{fixture_server}/api/not-json", Health)
    assert result.passed is False
    assert any("JSON content type" in error for error in result.errors)
    assert any("not valid JSON" in error for error in result.errors)


def test_malformed_json_response_is_flagged(fixture_server: str) -> None:
    result = audit_json_contract(f"{fixture_server}/api/malformed", Health)
    assert result.passed is False
    assert result.valid_json is False


def test_status_mismatch_is_flagged(fixture_server: str) -> None:
    result = audit_json_contract(f"{fixture_server}/api/missing", expected_status=200)
    assert result.passed is False
    assert any("expected status 200" in error for error in result.errors)


def test_connection_failure_is_reported_not_raised() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("fixture connection failed", request=request)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = audit_json_contract("http://unreachable.invalid/api/health", Health, client=client)
    assert result.passed is False
    assert result.status_code is None
    assert result.errors == ("request failed: ConnectError",)


# ---------------------------------------------------------------------------
# Playwright mobile layout and console checks
# ---------------------------------------------------------------------------


def test_clean_mobile_page_has_no_console_errors(fixture_server: str) -> None:
    result = audit_web_page(f"{fixture_server}/clean.html")
    assert result.console_errors == ()
    assert result.page_errors == ()
    assert result.passed is True


def test_clean_mobile_page_has_no_horizontal_overflow(fixture_server: str) -> None:
    result = audit_web_page(f"{fixture_server}/")
    assert result.viewport == (390, 844)
    assert result.horizontal_overflow is False
    assert result.scroll_width <= result.viewport[0] + 1


def test_console_error_is_detected(fixture_server: str) -> None:
    result = audit_web_page(f"{fixture_server}/noisy.html")
    assert any("fixture console failure" in error for error in result.console_errors)
    assert result.passed is False


def test_horizontal_overflow_is_detected_at_mobile_viewport(fixture_server: str) -> None:
    result = audit_web_page(f"{fixture_server}/noisy.html")
    assert result.horizontal_overflow is True
    assert result.scroll_width > result.viewport[0]
    assert any("#wide" in element for element in result.overflowing_elements)


def test_uncaught_page_error_is_detected(fixture_server: str) -> None:
    result = audit_web_page(f"{fixture_server}/page-error.html")
    assert any("fixture page error" in error for error in result.page_errors)
    assert result.passed is False


def test_desktop_audit_uses_requested_viewport(fixture_server: str) -> None:
    result = audit_web_page(
        f"{fixture_server}/noisy.html",
        viewport=(1280, 720),
    )
    assert result.viewport == (1280, 720)
    assert result.status_code == 200
    assert result.horizontal_overflow is False


# ---------------------------------------------------------------------------
# ASGI transport (no socket) contract checks
# ---------------------------------------------------------------------------


def _asgi_get(path: str) -> httpx.Response:
    """Run the ASGI app in a worker thread.

    Playwright's sync driver keeps an event loop alive in the main thread, so
    ``asyncio.run`` must happen on a fresh thread rather than inline.
    """
    result: dict[str, httpx.Response] = {}
    errors: list[BaseException] = []

    def run() -> None:
        async def fetch() -> httpx.Response:
            transport = httpx.ASGITransport(app=asgi_app)
            async with httpx.AsyncClient(transport=transport, base_url="http://asgi") as client:
                return await client.get(path)

        try:
            result["response"] = asyncio.run(fetch())
        except BaseException as exc:  # noqa: BLE001 - surfaced to the test
            errors.append(exc)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(timeout=10)
    if errors:
        raise errors[0]
    return result["response"]


def test_asgi_health_contract_passes() -> None:
    response = _asgi_get("/api/health")
    assert response.status_code == 200
    assert validate_payload(response.json(), Health) == ()


def test_asgi_item_contract_failure_is_reported() -> None:
    errors = validate_payload(_asgi_get("/api/items/bad").json(), Item)
    assert errors
    assert any("id" in error for error in errors)
