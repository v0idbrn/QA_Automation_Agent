# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Live browser session — planner-driven skills execute REAL audits.

Playwright's connection is event-loop bound: once a loop closes, its
transports die and the connection can never be revived on a new loop.
Therefore every public operation runs as ONE self-contained cycle inside a
single asyncio.run():

    open browser -> run the audit body -> close browser (finally)

Per-cycle state that must survive across cycles (visited URLs, page HTML for
endpoint extraction) is kept on the session object; everything else is
created and destroyed inside the cycle. The budget (STOP semantics) and the
scope guard persist across cycles, so repeated skills stay bounded.

Every navigation is scope-checked (DENY UNKNOWN) and budget-consumed before
execution; page HTML evidence goes through EvidenceManager with
sensitive=True so the central redaction layer scrubs it before persistence.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable
from urllib.parse import urljoin

from core.models import Confidence, Finding, FindingCategory, FindingSeverity, FindingStatus

_API_REF_RE = re.compile(r"(?:[\"'(])((?:/?)api/[A-Za-z0-9_?=&.%-]+)")

_MAX_ENDPOINT_PROBES = 10
_MAX_FORMS_EXERCISED = 3
_MAX_A11Y_SWEEP_PAGES = 8
_MAX_SNAPSHOTS_STORED = 3


def _normalize_url(url: str) -> str:
    """Canonical form for dedup: strip fragment, normalize trailing slash,
    so `/index.html`, `/index.html#x` and `/` resolve to one visit."""
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    path = parts.path or "/"
    if path.endswith("/"):
        path = path.rstrip("/") or "/"
    if path == "/":
        path = "/index.html"
    return f"{parts.scheme}://{parts.netloc}{path}" + (f"?{parts.query}" if parts.query else "")


def run_coro_sync(coro: Any) -> Any:
    """Run an async coroutine from sync code.

    Uses asyncio.run() when no loop is running; falls back to a worker thread
    when the caller already has a loop (a running loop can never be blocked).
    NOTE: not used for Playwright work — see run_cycle for why.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(asyncio.run, coro).result()


def _sev(text: str, default: FindingSeverity = FindingSeverity.MEDIUM) -> FindingSeverity:
    try:
        return FindingSeverity(str(text).lower())
    except ValueError:
        return default


def _finding(
    *,
    category: FindingCategory,
    severity: FindingSeverity,
    title: str,
    description: str,
    location: str,
    source_skill: str,
    evidence: str = "",
    expected: str = "",
    actual: str = "",
    recommendation: str = "",
) -> Finding:
    return Finding(
        category=category,
        severity=severity,
        confidence=Confidence.HIGH,
        title=title[:200],
        description=description,
        location=location,
        source_skill=source_skill,
        status=FindingStatus.OPEN,
        evidence=evidence or None,
        expected=expected or None,
        actual=actual or None,
        recommendation=recommendation or None,
    )


# ---------------------------------------------------------------------------
# Engine-result -> unified Finding mapping
# ---------------------------------------------------------------------------


def crawl_finding_to_finding(cf: Any, *, run_id: str = "") -> Finding:
    """core.crawler.CrawlFinding -> unified Finding."""
    detail = str(getattr(cf, "detail", ""))
    is_nav_error = "navigation error" in detail
    return _finding(
        category=FindingCategory.CRAWL,
        severity=FindingSeverity.HIGH if is_nav_error else FindingSeverity.MEDIUM,
        title=f"Broken link: {getattr(cf, 'url', '')}",
        description=f"{getattr(cf, 'url', '')} — {detail} (parent: {getattr(cf, 'parent', '') or 'none'})",
        location=str(getattr(cf, "url", "")),
        source_skill="crawler",
        expected="linked page responds 2xx",
        actual=detail or "non-2xx response",
        recommendation="Fix or remove the broken link.",
    )


def console_error_to_finding(ce: Any, *, page_url: str = "") -> Finding:
    level = str(getattr(ce, "level", "error")).lower()
    return _finding(
        category=FindingCategory.CONSOLE,
        severity=FindingSeverity.MEDIUM if level == "error" else FindingSeverity.LOW,
        title=f"Console {level}: {str(getattr(ce, 'message', ''))[:120]}",
        description=f"{getattr(ce, 'message', '')} [{getattr(ce, 'location', 'unknown')}]",
        location=page_url or str(getattr(ce, "location", "")) or "unknown",
        source_skill="crawler",
        recommendation="Investigate the client-side error.",
    )


def api_finding_to_finding(af: Any, *, run_id: str = "") -> Finding:
    status = getattr(af, "status", None)
    sev = FindingSeverity.HIGH if (status or 0) >= 500 else FindingSeverity.MEDIUM
    return _finding(
        category=FindingCategory.API,
        severity=sev,
        title=f"API {getattr(af, 'method', 'GET')} {status}: {getattr(af, 'request_url', '')}",
        description=str(getattr(af, "detail", "")),
        location=str(getattr(af, "request_url", "")),
        source_skill="api_auditor",
        expected="2xx response with valid payload",
        actual=f"status {status}",
        recommendation="Fix the failing endpoint or its client usage.",
    )


def a11y_finding_to_finding(af: Any, *, page_url: str = "") -> Finding:
    return _finding(
        category=FindingCategory.ACCESSIBILITY,
        severity=_sev(getattr(af, "severity", "medium"), FindingSeverity.MEDIUM),
        title=f"A11y {getattr(af, 'rule', 'issue')}: {str(getattr(af, 'detail', ''))[:140]}",
        description=f"{getattr(af, 'detail', '')} (element: {getattr(af, 'element', 'unknown')})",
        location=page_url,
        source_skill="a11y_auditor",
        recommendation="Fix the accessibility issue; heuristics do not certify WCAG compliance.",
    )


def form_finding_to_finding(ff: Any, *, page_url: str = "") -> Finding:
    sev = _sev(getattr(ff, "severity", "low"), FindingSeverity.LOW)
    return _finding(
        category=FindingCategory.FORM,
        severity=sev,
        title=f"Form check [{getattr(ff, 'status', 'info')}]: {getattr(ff, 'field', '')} — {str(getattr(ff, 'detail', ''))[:120]}",
        description=f"{getattr(ff, 'detail', '')} (field: {getattr(ff, 'field', '')}, value: {getattr(ff, 'input_value', '')!r})",
        location=page_url,
        source_skill="form_tester",
        recommendation="Verify form validation and error handling.",
    )


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------


@dataclass
class SessionMeta:
    available: bool = False
    degraded_reason: str = ""
    pages_visited: int = 0
    omits: int = 0


@dataclass
class _Services:
    """Per-cycle Playwright services handed to the audit bodies."""

    context: Any
    api_auditor: Any
    crawler: Any


class LiveBrowserSession:
    """Bounded Playwright session driving the real engines.

    One self-contained open->work->close cycle per public call (crawl,
    a11y_sweep, probe_apis, exercise_forms). Nothing persistent is held
    between cycles except audit memory (visited URLs, page HTML) — the
    Playwright transport itself never outlives a loop.
    """

    def __init__(
        self,
        *,
        origin: str,
        scope: Any,
        budget: Any,
        evidence: Any,
        browser_name: str = "chromium",
        headless: bool = True,
        output_dir: Path | None = None,
    ) -> None:
        self.origin = origin
        self.scope = scope
        self.budget = budget
        self.evidence = evidence
        self.browser_name = browser_name
        self.headless = bool(headless)
        self.output_dir = Path(output_dir) if output_dir else Path("reports")
        # Audit memory persisting across cycles (bounded by scope.max_pages).
        self._visited_urls: list[str] = []
        self._page_html: dict[str, str] = {}
        self._snapshots_stored = 0
        self._last_error: str = ""
        self._cycles_ok = 0
        self._probed_urls: set[str] = set()  # each endpoint probed once per session

    # ------------------------------------------------------------------
    # Cycle driver — the ONLY way Playwright is touched
    # ------------------------------------------------------------------
    def run_cycle(self, body: Callable[[_Services], Awaitable[list[Finding]]]) -> list[Finding]:
        """One open->work->close Playwright cycle in a single asyncio.run()."""
        try:
            findings = asyncio.run(self._cycle(body))
        except Exception as exc:  # noqa: BLE001 — degradation must be graceful
            self._last_error = f"{type(exc).__name__}: {exc}"[:300]
            return []
        self._last_error = ""
        self._cycles_ok += 1
        return findings

    async def _cycle(self, body: Callable[[_Services], Awaitable[list[Finding]]]) -> list[Finding]:
        from playwright.async_api import async_playwright

        async with async_playwright() as pw:
            launcher = getattr(pw, self.browser_name, None) or pw.chromium
            browser = await launcher.launch(headless=self.headless)
            try:
                context = await browser.new_context()
                context.set_default_timeout(max(1, self.scope.per_request_timeout_seconds) * 1000)
                from core.api_auditor import ApiAuditor
                from core.crawler import Crawler

                services = _Services(
                    context=context,
                    api_auditor=ApiAuditor(),
                    crawler=Crawler(base_url=self.origin, max_depth=self.scope.max_depth, max_links=self.scope.max_pages),
                )
                return await body(services)
            finally:
                try:
                    await browser.close()
                except Exception:  # noqa: BLE001 — teardown is best-effort
                    pass

    # Backward-compat no-ops: nothing persistent to open/close anymore.
    def open(self) -> bool:
        return True

    def close(self) -> None:
        return None

    @property
    def available(self) -> bool:
        return True

    def session_meta(self) -> SessionMeta:
        return SessionMeta(
            available=self.available,
            degraded_reason=self._last_error,
            pages_visited=len(self._visited_urls),
            omits=len(self.scope.omits()),
        )

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------
    def _consume_request(self) -> bool:
        return self.budget is None or self.budget.consume_request()

    def _store_snapshot(self, html: str, url: str, test_id: str | None) -> str:
        """Persist an HTML snapshot as redacted evidence (bounded count)."""
        if self.evidence is None or self._snapshots_stored >= _MAX_SNAPSHOTS_STORED:
            return ""
        self._snapshots_stored += 1
        return str(
            self.evidence.store_temporary(
                "html",
                html.encode("utf-8", errors="replace"),
                f"page snapshot: {url}",
                extension="html",
                test_id=test_id,
                sensitive=True,  # central redaction scrubs text before persistence
            )
        )

    def _store_html_findings(self, html: str, url: str, findings: list[Finding]) -> None:
        """Attach the (bounded) redacted snapshot to the batch's primary finding."""
        if not findings:
            return
        path = self._store_snapshot(html, url, findings[0].test_id or None)
        if path:
            for f in findings:
                f.evidence_ids.append(path)
                f.evidence = f.evidence or f"snapshot: {path}"

    @staticmethod
    def _attach_page_handler(page: Any, findings_out: list[Any]) -> None:
        """Console-error capture on a live page via the crawler's handler."""
        from core.crawler import _console_handler_decorator

        page.on("console", _console_handler_decorator(findings_out))

    @staticmethod
    def _attach_response_handler(page: Any, auditor: Any, sink: list[Any]) -> None:
        class _StatusOnlyResponse:
            """Shim exposing only .status: body sampling in the async listener
            would require awaiting response.text() inside a fire-and-forget
            callback — explicit probes own body capture instead."""

            def __init__(self, response: Any) -> None:
                self._status = getattr(response, "status", 0)

            @property
            def status(self) -> int:
                return self._status or 0

            def text(self) -> str:  # auditor's optional sampling hook
                return ""

        async def _on_response(response: Any) -> None:
            try:
                request = getattr(response, "request", None)
                status = getattr(response, "status", 0)
                if status and status < 400:
                    return
                finding = auditor.on_response(request, _StatusOnlyResponse(response))
                if finding is not None:
                    sink.append(finding)
            except Exception:  # noqa: BLE001 — observation must never break navigation
                pass

        page.on("response", _on_response)

    @staticmethod
    async def _safe_content(page: Any) -> str:
        try:
            return await page.content()
        except Exception:  # noqa: BLE001
            return ""

    def _collect_endpoint_refs(self) -> list[str]:
        """Extract in-page API references (onclick handlers, fetch/xhr strings)."""
        refs: list[str] = []
        for page_url, html in list(self._page_html.items())[: self.scope.max_pages]:
            for match in _API_REF_RE.finditer(html or ""):
                ref = match.group(1)
                absolute = urljoin(page_url, ref if ref.startswith("/") else f"/{ref}")
                if absolute not in refs:
                    refs.append(absolute)
        return refs

    # ------------------------------------------------------------------
    # Crawl (crawler skill)
    # ------------------------------------------------------------------
    async def _crawl_body(self, svc: _Services) -> list[Finding]:
        from core.crawler import ConsoleError, CrawlFinding

        findings: list[Finding] = []
        raw: list[Any] = []
        queue: list[tuple[str, int]] = [(self.origin, 0)]
        seen: set[str] = {_normalize_url(u) for u in self._visited_urls}  # never re-crawl across cycles

        while queue and (self.budget is None or not self.budget.is_exhausted()):
            url, depth = queue.pop(0)
            norm = _normalize_url(url)
            if norm in seen:
                continue
            seen.add(norm)
            if not self.scope.is_allowed(url):
                continue  # omission already recorded by the scope guard
            if self.budget is not None and not self.budget.consume_page():
                break
            if self.budget is not None and not self.budget.within_depth(depth):
                break
            if not self._consume_request():
                break

            page = await svc.context.new_page()
            console_raw: list[Any] = []
            self._attach_page_handler(page, console_raw)
            api_sink: list[Any] = []
            self._attach_response_handler(page, svc.api_auditor, api_sink)
            try:
                response = await page.goto(
                    url, wait_until="domcontentloaded", timeout=self.scope.per_request_timeout_seconds * 1000
                )
                try:
                    await page.wait_for_load_state("networkidle", timeout=5000)
                except Exception:  # noqa: BLE001 — slow networkidle must not abort the crawl
                    pass
                status = getattr(response, "status", 0) if response is not None else 0
                if status >= 400:
                    raw.append(
                        CrawlFinding(
                            kind="broken",
                            url=url,
                            parent="",
                            detail=f"http {status}",
                            html_snapshot=await self._safe_content(page),
                        )
                    )
                else:
                    self._visited_urls.append(url)
                    html = await self._safe_content(page)
                    if len(self._page_html) < self.scope.max_pages:
                        self._page_html[url] = html
                    from bs4 import BeautifulSoup

                    for link in svc.crawler.extract_links(BeautifulSoup(html, "html.parser"), url):
                        abs_url = urljoin(url, link)
                        if not self.scope.is_allowed(abs_url):
                            continue  # omit recorded by scope guard
                        if _normalize_url(abs_url) not in seen:
                            queue.append((abs_url, depth + 1))
            except Exception as exc:  # noqa: BLE001 — navigation failure is a finding, not a crash
                raw.append(
                    CrawlFinding(
                        kind="broken",
                        url=url,
                        parent="",
                        detail=f"navigation error: {exc}",
                        html_snapshot=None,
                    )
                )
            finally:
                for ce in console_raw:
                    if isinstance(ce, ConsoleError):
                        raw.append(ce)
                for af in api_sink:
                    findings.append(api_finding_to_finding(af))
                try:
                    await page.close()
                except Exception:  # noqa: BLE001
                    pass

        for item in raw:
            if isinstance(item, CrawlFinding):
                findings.append(crawl_finding_to_finding(item))
            else:  # ConsoleError
                findings.append(console_error_to_finding(item, page_url=self.origin))

        # Attach a redacted snapshot to the first finding (bounded to 1 per cycle).
        if self._visited_urls:
            html = self._page_html.get(self._visited_urls[0])
            if html:
                self._store_html_findings(html, self._visited_urls[0], findings[:1])
        return findings

    def crawl(self) -> list[Finding]:
        return self.run_cycle(self._crawl_body)

    # ------------------------------------------------------------------
    # Accessibility sweep (a11y skill)
    # ------------------------------------------------------------------
    async def _a11y_body(self, svc: _Services) -> list[Finding]:
        from core.a11y_auditor import A11yAuditor

        auditor = A11yAuditor(screenshot_dir=str(self.output_dir / "screenshots"))
        urls = self._visited_urls[:_MAX_A11Y_SWEEP_PAGES] or [self.origin]
        findings: list[Finding] = []
        for url in urls:
            if not self.scope.is_allowed(url) or not self._consume_request():
                break
            page = await svc.context.new_page()
            try:
                await page.goto(
                    url, wait_until="domcontentloaded", timeout=self.scope.per_request_timeout_seconds * 1000
                )
                af_list = await auditor.audit_page(page, url)
                findings.extend(a11y_finding_to_finding(af, page_url=url) for af in af_list)
            except Exception:  # noqa: BLE001 — a11y sweep is best-effort per page
                continue
            finally:
                try:
                    await page.close()
                except Exception:  # noqa: BLE001
                    pass
        return findings

    def a11y_sweep(self) -> list[Finding]:
        return self.run_cycle(self._a11y_body)

    # ------------------------------------------------------------------
    # API probes (api skill)
    # ------------------------------------------------------------------
    async def _probe_body(self, svc: _Services, endpoints: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        urls: list[str] = []
        for ep in list(endpoints)[:_MAX_ENDPOINT_PROBES]:
            urls.append(ep if ep.startswith("http") else urljoin(self.origin, ep))
        for ref in self._collect_endpoint_refs():
            if len(urls) >= _MAX_ENDPOINT_PROBES:
                break
            if ref not in urls:
                urls.append(ref)

        for url in urls:
            norm = _normalize_url(url)
            if norm in self._probed_urls:
                continue  # dedup across cycles: the api skill may run repeatedly
            if not self.scope.is_allowed(url, method="GET"):
                continue  # omission recorded by scope guard (stays retryable)
            if not self._consume_request():
                break
            self._probed_urls.add(norm)  # marked only once actually attempted
            started = time.perf_counter()
            try:
                response = await svc.context.request.get(url, timeout=self.scope.per_request_timeout_seconds * 1000)
                elapsed = time.perf_counter() - started
                status = getattr(response, "status", 0)
                body = ""
                try:
                    text = response.text()
                    if asyncio.iscoroutine(text):
                        text = await text
                    body = (text or "")[:400]
                except Exception:  # noqa: BLE001 — binary/blocked bodies are fine to skip
                    body = ""
                if status >= 400:
                    from core.api_auditor import ApiFinding

                    findings.append(
                        api_finding_to_finding(
                            ApiFinding(
                                request_url=url,
                                method="GET",
                                status=status,
                                detail=f"probe received status {status}",
                                payload_sample=body or None,
                                severity="high" if status >= 500 else "medium",
                            )
                        )
                    )
                elif elapsed > 3.0:
                    findings.append(
                        _finding(
                            category=FindingCategory.PERFORMANCE,
                            severity=FindingSeverity.LOW,
                            title=f"Slow endpoint: {url} ({elapsed:.1f}s)",
                            description=f"GET {url} took {elapsed:.2f}s",
                            location=url,
                            source_skill="api_auditor",
                            expected="sub-3s response",
                            actual=f"{elapsed:.2f}s",
                            recommendation="Investigate server-side latency.",
                        )
                    )
                content_type = ""
                try:
                    headers = response.headers
                    content_type = str((headers or {}).get("content-type", ""))
                except Exception:  # noqa: BLE001
                    content_type = ""
                if "json" in content_type and body:
                    from core.api_auditor import flag_malformed_json

                    malformed = flag_malformed_json(body)
                    if malformed is not None:
                        findings.append(
                            _finding(
                                category=FindingCategory.API,
                                severity=FindingSeverity.MEDIUM,
                                title=f"Malformed JSON from {url}",
                                description=f"declared {content_type} but body is not valid JSON",
                                location=url,
                                source_skill="api_auditor",
                                expected="parseable JSON body",
                                actual=body[:120],
                                recommendation="Return valid JSON or fix the content type.",
                            )
                        )
            except Exception as exc:  # noqa: BLE001 — probe failure is a finding, not a crash
                findings.append(
                    _finding(
                        category=FindingCategory.NETWORK,
                        severity=FindingSeverity.MEDIUM,
                        title=f"API probe failed: {url}",
                        description=f"{type(exc).__name__}: {exc}"[:300],
                        location=url,
                        source_skill="api_auditor",
                    )
                )
        return findings

    def probe_apis(self, endpoints: list[str] | None = None) -> list[Finding]:
        eps = list(endpoints or [])
        return self.run_cycle(lambda svc: self._probe_body(svc, eps))

    # ------------------------------------------------------------------
    # Form exercise (form_tester skill) — empty-submit, defensive, bounded
    # ------------------------------------------------------------------
    @staticmethod
    async def _extract_form_inputs(form: Any) -> list[Any]:
        from core.form_tester import FormInput

        inputs: list[Any] = []
        try:
            handles = await form.query_selector_all("input, select, textarea")
        except Exception:  # noqa: BLE001
            return inputs
        for handle in handles[:10]:
            try:
                name = (await handle.get_attribute("name")) or (await handle.get_attribute("id")) or ""
                itype = (await handle.get_attribute("type")) or "text"
                required = (await handle.get_attribute("required")) is not None
                inputs.append(FormInput(name=name or f"field_{len(inputs)}", value_type=itype, required=required))
            except Exception:  # noqa: BLE001 — detached nodes are skipped
                continue
        return inputs

    async def _forms_body(self, svc: _Services) -> list[Finding]:
        findings: list[Finding] = []
        candidate_urls = [u for u in self._visited_urls if u in self._page_html][:_MAX_FORMS_EXERCISED]
        exercised = 0
        for url in candidate_urls:
            if exercised >= _MAX_FORMS_EXERCISED:
                break
            if not self._consume_request():
                break
            page = await svc.context.new_page()
            api_sink: list[Any] = []
            self._attach_response_handler(page, svc.api_auditor, api_sink)
            try:
                await page.goto(
                    url, wait_until="domcontentloaded", timeout=self.scope.per_request_timeout_seconds * 1000
                )
                forms = await page.query_selector_all("form")
                for form in forms[: _MAX_FORMS_EXERCISED - exercised]:
                    action = (await form.get_attribute("action")) or ""
                    method = ((await form.get_attribute("method")) or "GET").upper()
                    target_url = urljoin(url, action) if action else url
                    if method not in self.scope.allowed_methods:
                        self.scope._record_omit(target_url, f"form method {method} not in allowlist", category="method")
                        continue
                    if not self.scope.is_allowed(target_url, method=method):
                        continue
                    inputs = await self._extract_form_inputs(form)
                    exercised += 1
                    submit = await form.query_selector("[type=submit]")
                    if submit is None:
                        continue
                    try:
                        async with page.expect_navigation(timeout=8000):
                            await submit.click()
                    except Exception:  # noqa: BLE001 — client-side-only submit is fine
                        pass
                    status_seen: int | None = None
                    if api_sink:
                        status_seen = getattr(api_sink[-1], "status", None)
                    from core.form_tester import FormFinding

                    findings.append(
                        form_finding_to_finding(
                            FormFinding(
                                status="fail" if (status_seen or 0) >= 400 else "info",
                                field="__empty_submit__",
                                input_value="",
                                input_type=method.lower(),
                                detail=(
                                    f"empty submit of {len(inputs)} fields to {target_url} -> http {status_seen}"
                                    if status_seen
                                    else f"empty submit of {len(inputs)} fields to {target_url} (no server response observed)"
                                ),
                                severity="medium" if (status_seen or 0) >= 400 else "low",
                            ),
                            page_url=url,
                        )
                    )
            except Exception:  # noqa: BLE001 — form exercise is best-effort per page
                continue
            finally:
                try:
                    await page.close()
                except Exception:  # noqa: BLE001
                    pass
        return findings

    def exercise_forms(self) -> list[Finding]:
        return self.run_cycle(self._forms_body)

    def capture_screenshot(self, url: str) -> list[Finding]:
        """Capture one viewport screenshot of `url` as redacted evidence."""
        return self.run_cycle(lambda svc: self._evidence_body(svc, url))

    def store_html_snapshot(self, url: str) -> str:
        """Store a redacted DOM snapshot of a page crawled this session."""
        html = self._page_html.get(url)
        if not html:
            return ""
        return self._store_snapshot(html, url, None)

    # ------------------------------------------------------------------
    # Screenshot evidence (bounded)
    # ------------------------------------------------------------------
    async def _evidence_body(self, svc: _Services, url: str) -> list[Finding]:
        if self.evidence is None or self._snapshots_stored >= _MAX_SNAPSHOTS_STORED:
            return []
        if not self._consume_request():
            return []
        page = await svc.context.new_page()
        try:
            await page.goto(
                url, wait_until="domcontentloaded", timeout=self.scope.per_request_timeout_seconds * 1000
            )
            self._snapshots_stored += 1
            png = await page.screenshot(full_page=False)
            self.evidence.store_temporary(
                "screenshot",
                png,
                f"viewport screenshot: {url}",
                extension="png",
                sensitive=True,  # pixels cannot be scrubbed; marked sensitive
            )
        except Exception:  # noqa: BLE001 — screenshot evidence is best-effort
            pass
        finally:
            try:
                await page.close()
            except Exception:  # noqa: BLE001
                pass
        return []


__all__ = [
    "LiveBrowserSession",
    "SessionMeta",
    "run_coro_sync",
    "crawl_finding_to_finding",
    "console_error_to_finding",
    "api_finding_to_finding",
    "a11y_finding_to_finding",
    "form_finding_to_finding",
]
