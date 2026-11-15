# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Reusable HTTPX + Playwright web auditor.

Two independent surfaces:

  * :func:`audit_json_contract` -- status code, JSON content type, payload
    parsing, and Pydantic contract validation through HTTPX;
  * :func:`audit_web_page` -- one bounded Chromium session that collects
    console/page errors and checks horizontal overflow at a mobile viewport.

Both return frozen result objects so assertions in the E2E suite read as data.
No network access is performed unless the caller supplies a URL.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx
from pydantic import BaseModel, ValidationError
from playwright.sync_api import Browser, sync_playwright

__all__ = [
    "ApiContractResult",
    "WebAuditResult",
    "audit_error_response",
    "audit_json_contract",
    "audit_web_page",
    "validate_error_payload",
    "validate_payload",
]

DEFAULT_VIEWPORT = (390, 844)


@dataclass(frozen=True)
class ApiContractResult:
    url: str
    expected_status: int
    status_code: int | None
    content_type: str
    valid_json: bool
    errors: tuple[str, ...]
    payload: Any = None

    @property
    def passed(self) -> bool:
        return not self.errors


@dataclass(frozen=True)
class WebAuditResult:
    url: str
    viewport: tuple[int, int]
    console_errors: tuple[str, ...] = ()
    page_errors: tuple[str, ...] = ()
    horizontal_overflow: bool = False
    scroll_width: int = 0
    client_width: int = 0
    overflowing_elements: tuple[str, ...] = ()
    status_code: int | None = None

    @property
    def passed(self) -> bool:
        return not self.console_errors and not self.page_errors and not self.horizontal_overflow


# ---------------------------------------------------------------------------
# API contract helpers
# ---------------------------------------------------------------------------


def validate_payload(payload: Any, schema: type[BaseModel]) -> tuple[str, ...]:
    """Validate an already-parsed JSON payload against a Pydantic model."""
    if not isinstance(payload, dict):
        return ("payload must be a JSON object",)
    try:
        schema.model_validate(payload)
    except ValidationError as exc:
        return tuple(
            f"{'.'.join(str(part) for part in error['loc']) or '<root>'}: {error['msg']}"
            for error in exc.errors()
        )
    return ()


def validate_error_payload(payload: Any, *, expected_status: int) -> tuple[str, ...]:
    """Check the stable error envelope used by the fixture and real APIs."""
    errors: list[str] = []
    if not isinstance(payload, dict):
        return ("error payload must be a JSON object",)

    error = payload.get("error")
    if not isinstance(error, str) or not error.strip():
        errors.append("missing or empty 'error' field")
    if "message" in payload and not isinstance(payload["message"], str):
        errors.append("'message' must be a string")
    for leak in ("traceback", "stack", "stacktrace", "exception"):
        if leak in payload:
            errors.append(f"error payload leaks internal detail via {leak!r} field")
    if expected_status >= 500 and payload.get("error") in {"ok", "success"}:
        errors.append("server error reports a success status")
    return tuple(errors)


def _fetch_json(
    url: str,
    *,
    expected_status: int,
    timeout: float,
    client: httpx.Client | None = None,
) -> ApiContractResult:
    owned = client is None
    http = client or httpx.Client(follow_redirects=True, timeout=timeout)
    try:
        try:
            response = http.get(url)
        except httpx.HTTPError as exc:
            # A dead endpoint is an audit result, not an unhandled crash.
            return ApiContractResult(
                url=url,
                expected_status=expected_status,
                status_code=None,
                content_type="",
                valid_json=False,
                errors=(f"request failed: {type(exc).__name__}",),
            )

        content_type = response.headers.get("content-type", "")
        errors: list[str] = []
        if response.status_code != expected_status:
            errors.append(f"expected status {expected_status}, got {response.status_code}")
        if "application/json" not in content_type.lower():
            errors.append(f"expected JSON content type, got {content_type or '<missing>'!r}")

        payload: Any = None
        try:
            payload = response.json()
            valid_json = True
        except ValueError:
            valid_json = False
            errors.append("response body is not valid JSON")

        return ApiContractResult(
            url=url,
            expected_status=expected_status,
            status_code=response.status_code,
            content_type=content_type,
            valid_json=valid_json,
            errors=tuple(errors),
            payload=payload,
        )
    finally:
        if owned:
            http.close()


def audit_json_contract(
    url: str,
    schema: type[BaseModel] | None = None,
    *,
    expected_status: int = 200,
    timeout: float = 5.0,
    client: httpx.Client | None = None,
) -> ApiContractResult:
    """Fetch a URL and validate status, content type, JSON, and schema."""
    result = _fetch_json(url, expected_status=expected_status, timeout=timeout, client=client)
    errors = list(result.errors)
    if schema is not None and result.valid_json:
        errors.extend(validate_payload(result.payload, schema))
    return ApiContractResult(
        url=result.url,
        expected_status=result.expected_status,
        status_code=result.status_code,
        content_type=result.content_type,
        valid_json=result.valid_json,
        errors=tuple(errors),
        payload=result.payload,
    )


def audit_error_response(
    url: str,
    *,
    expected_status: int = 400,
    timeout: float = 5.0,
    client: httpx.Client | None = None,
) -> ApiContractResult:
    """Fetch an error endpoint and validate the error envelope."""
    result = _fetch_json(url, expected_status=expected_status, timeout=timeout, client=client)
    errors = list(result.errors)
    if result.valid_json:
        errors.extend(validate_error_payload(result.payload, expected_status=expected_status))
    return ApiContractResult(
        url=result.url,
        expected_status=result.expected_status,
        status_code=result.status_code,
        content_type=result.content_type,
        valid_json=result.valid_json,
        errors=tuple(errors),
        payload=result.payload,
    )


# ---------------------------------------------------------------------------
# Browser layout / console auditor
# ---------------------------------------------------------------------------

_LAYOUT_SCRIPT = """
() => {
  const root = document.documentElement;
  const viewport = window.innerWidth;
  const offenders = [];
  for (const element of document.querySelectorAll('body *')) {
    const rect = element.getBoundingClientRect();
    if (rect.width > 0 && (rect.right > viewport + 1 || rect.left < -1)) {
      const id = element.id ? '#' + element.id : '';
      offenders.push(element.tagName.toLowerCase() + id);
      if (offenders.length === 5) break;
    }
  }
  return {
    scrollWidth: Math.max(root.scrollWidth, document.body ? document.body.scrollWidth : 0),
    clientWidth: root.clientWidth,
    innerWidth: viewport,
    offenders,
  };
}
"""


def audit_web_page(
    url: str,
    *,
    viewport: tuple[int, int] = DEFAULT_VIEWPORT,
    browser: Browser | None = None,
    timeout_ms: float = 10_000,
    settle_ms: float = 100,
) -> WebAuditResult:
    """Audit console errors and mobile horizontal overflow for one page.

    Pass a session-scoped ``browser`` to reuse Chromium; otherwise a browser is
    launched and stopped for this single audit.
    """
    console_errors: list[str] = []
    page_errors: list[str] = []
    owned_playwright = browser is None

    playwright = sync_playwright().start() if owned_playwright else None
    if browser is None:
        try:
            active_browser = playwright.chromium.launch(headless=True)
        except BaseException:
            playwright.stop()
            raise
    else:
        active_browser = browser
    context = active_browser.new_context(viewport={"width": viewport[0], "height": viewport[1]})
    try:
        page = context.new_page()
        page.on("console", lambda message: console_errors.append(message.text) if message.type == "error" else None)
        page.on("pageerror", lambda error: page_errors.append(str(error)))

        response = page.goto(url, wait_until="load", timeout=timeout_ms)
        page.wait_for_timeout(settle_ms)
        layout = page.evaluate(_LAYOUT_SCRIPT)
        status_code = response.status if response is not None else None

        return WebAuditResult(
            url=url,
            viewport=viewport,
            console_errors=tuple(console_errors),
            page_errors=tuple(page_errors),
            horizontal_overflow=bool(layout["scrollWidth"] > layout["innerWidth"] + 1),
            scroll_width=int(layout["scrollWidth"]),
            client_width=int(layout["clientWidth"]),
            overflowing_elements=tuple(layout["offenders"]),
            status_code=status_code,
        )
    finally:
        context.close()
        if owned_playwright:
            active_browser.close()
            playwright.stop()
