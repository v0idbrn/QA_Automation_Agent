# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Autonomous stateful crawler and deep DOM explorer.

The crawler is bounded and same-origin by default. It reuses one Playwright
context per crawl (optional ``storage_state`` for authenticated SaaS runs),
walks pages in BFS or DFS order, and records broken links, broken assets,
redirect loops, mixed content, console/page errors, and failed XHR/fetch calls.

All evidence URLs pass through local redaction before they reach a report.
"""

from __future__ import annotations

import hashlib
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence
from urllib.parse import urljoin, urlsplit, urlunsplit

from playwright.sync_api import Browser, Error as PlaywrightError, sync_playwright

from qa_agent.models import Finding, Severity
from qa_agent.redaction import redact_text, redact_url

__all__ = [
    "CrawlConfig",
    "CrawlReport",
    "Crawler",
    "InteractiveElement",
    "PageRecord",
    "detect_mixed_content",
    "detect_redirect_loop",
    "extract_page_data",
    "normalize_url",
    "same_origin",
]

_ASSET_HINTS = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".css", ".js", ".woff", ".woff2")
_SKIP_SCHEMES = ("mailto:", "tel:", "javascript:", "data:", "blob:", "file:")


@dataclass(frozen=True)
class CrawlConfig:
    max_pages: int = 15
    max_depth: int = 3
    strategy: str = "bfs"
    timeout_ms: float = 10_000
    auth_state: str | None = None
    same_origin_only: bool = True
    include_assets: bool = True

    def __post_init__(self) -> None:
        if self.strategy not in {"bfs", "dfs"}:
            raise ValueError("strategy must be 'bfs' or 'dfs'")
        if self.max_pages < 1:
            raise ValueError("max_pages must be >= 1")


@dataclass(frozen=True)
class InteractiveElement:
    tag: str
    role: str = ""
    name: str = ""
    testid: str = ""
    placeholder: str = ""
    input_type: str = ""
    href: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "tag": self.tag,
            "role": self.role,
            "name": self.name,
            "testid": self.testid,
            "placeholder": self.placeholder,
            "input_type": self.input_type,
            "href": self.href,
        }


@dataclass(frozen=True)
class PageRecord:
    url: str
    final_url: str
    status: int | None
    title: str
    depth: int
    links: tuple[str, ...] = ()
    assets: tuple[str, ...] = ()
    interactive: tuple[InteractiveElement, ...] = ()
    console_errors: tuple[str, ...] = ()
    page_errors: tuple[str, ...] = ()
    failed_requests: tuple[dict[str, Any], ...] = ()
    broken_assets: tuple[str, ...] = ()
    mixed_content: tuple[str, ...] = ()
    redirect_loop: bool = False

    @property
    def url_redacted(self) -> str:
        return redact_url(self.url)


@dataclass
class CrawlReport:
    start_url: str
    pages: list[PageRecord] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    duration_ms: float = 0.0
    visited_urls: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not any(finding.severity in {Severity.CRITICAL, Severity.HIGH} for finding in self.findings)

    @property
    def console_error_count(self) -> int:
        return sum(len(page.console_errors) for page in self.pages)

    @property
    def page_error_count(self) -> int:
        return sum(len(page.page_errors) for page in self.pages)

    def to_dict(self) -> dict[str, Any]:
        return {
            "start_url": redact_url(self.start_url),
            "pages": [
                {
                    "url": page.url_redacted,
                    "final_url": redact_url(page.final_url),
                    "status": page.status,
                    "title": page.title,
                    "depth": page.depth,
                    "links": len(page.links),
                    "interactive": [element.to_dict() for element in page.interactive],
                    "console_errors": list(page.console_errors),
                    "page_errors": list(page.page_errors),
                    "failed_requests": list(page.failed_requests),
                    "broken_assets": [redact_url(item) for item in page.broken_assets],
                    "mixed_content": [redact_url(item) for item in page.mixed_content],
                    "redirect_loop": page.redirect_loop,
                }
                for page in self.pages
            ],
            "findings": [finding.to_dict() for finding in self.findings],
            "duration_ms": round(self.duration_ms, 2),
            "passed": self.passed,
        }


# ---------------------------------------------------------------------------
# Pure URL and HTML helpers
# ---------------------------------------------------------------------------


def normalize_url(url: str, base: str | None = None) -> str:
    absolute = urljoin(base, url) if base else url
    absolute = absolute.strip()
    if not absolute or absolute.lower().startswith(_SKIP_SCHEMES):
        return ""
    parts = urlsplit(absolute)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        return ""
    path = parts.path or "/"
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, parts.query, ""))


def origin_of(url: str) -> tuple[str, str, int | None]:
    parts = urlsplit(url)
    port = parts.port
    if port is None:
        port = 443 if parts.scheme == "https" else 80
    return parts.scheme.lower(), (parts.hostname or "").lower(), port


def same_origin(first: str, second: str) -> bool:
    return origin_of(first) == origin_of(second)


def is_asset_url(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return path.endswith(_ASSET_HINTS)


def detect_mixed_content(page_url: str, resource_urls: Iterable[str]) -> list[str]:
    if urlsplit(page_url).scheme != "https":
        return []
    return [url for url in resource_urls if url.lower().startswith("http://")]


def detect_redirect_loop(urls: Sequence[str]) -> bool:
    seen: set[str] = set()
    for url in urls:
        normalized = normalize_url(url)
        if normalized in seen:
            return True
        seen.add(normalized)
    return False


def _text(node: Any) -> str:
    return " ".join(node.get_text(" ", strip=True).split()) if node is not None else ""


def _accessible_name(node: Any) -> str:
    for attribute in ("aria-label", "title", "alt", "placeholder"):
        value = node.get(attribute)
        if value:
            return str(value).strip()
    return _text(node)


def extract_page_data(html: str, base_url: str) -> dict[str, Any]:
    """Extract links, assets, forms, and interactive elements from HTML."""
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html, "html.parser")
    links: list[str] = []
    assets: list[str] = []
    interactive: list[InteractiveElement] = []
    forms: list[dict[str, Any]] = []

    for anchor in soup.select("a[href]"):
        url = normalize_url(str(anchor.get("href", "")), base_url)
        if url:
            links.append(url)
        interactive.append(
            InteractiveElement(
                tag="a",
                role="link",
                name=_accessible_name(anchor),
                testid=str(anchor.get("data-testid", "")),
                href=url,
            )
        )

    for image in soup.select("img[src]"):
        url = normalize_url(str(image.get("src", "")), base_url)
        if url:
            assets.append(url)

    for script in soup.select("script[src]"):
        url = normalize_url(str(script.get("src", "")), base_url)
        if url:
            assets.append(url)

    for link in soup.select("link[href]"):
        rel = " ".join(link.get("rel", [])) if link.get("rel") else ""
        if rel in {"stylesheet", "icon", "preload"} or "stylesheet" in rel:
            url = normalize_url(str(link.get("href", "")), base_url)
            if url:
                assets.append(url)

    for form in soup.select("form"):
        fields = []
        for control in form.select("input, select, textarea"):
            label = str(control.get("aria-label") or control.get("placeholder") or control.get("name") or "")
            fields.append(
                {
                    "tag": control.name,
                    "name": str(control.get("name", "")),
                    "type": str(control.get("type", "text")),
                    "label": label,
                    "placeholder": str(control.get("placeholder", "")),
                    "required": control.has_attr("required"),
                }
            )
        forms.append(
            {
                "action": normalize_url(str(form.get("action", "")), base_url),
                "method": str(form.get("method", "get")).upper(),
                "fields": fields,
            }
        )

    for node in soup.select("button, input, select, textarea, [role=button], [role=link]"):
        tag = str(node.name)
        if tag == "input":
            input_type = str(node.get("type", "text")).lower()
            role = {"submit": "button", "button": "button", "checkbox": "checkbox", "radio": "radio"}.get(input_type, "textbox")
        else:
            role = str(node.get("role") or {"button": "button", "a": "link"}.get(tag, tag))
        interactive.append(
            InteractiveElement(
                tag=tag,
                role=role,
                name=_accessible_name(node),
                testid=str(node.get("data-testid", "")),
                placeholder=str(node.get("placeholder", "")),
                input_type=str(node.get("type", "")),
            )
        )

    deduped_links = list(dict.fromkeys(links))
    deduped_assets = list(dict.fromkeys(assets))
    deduped_interactive = list({(item.tag, item.role, item.name, item.testid, item.placeholder, item.input_type, item.href): item for item in interactive}.values())

    return {
        "links": deduped_links,
        "assets": deduped_assets,
        "forms": forms,
        "interactive": deduped_interactive,
        "mixed_content": detect_mixed_content(base_url, deduped_assets),
    }


# ---------------------------------------------------------------------------
# Finding helpers
# ---------------------------------------------------------------------------


def _finding(
    title: str,
    severity: Severity,
    category: str,
    url: str,
    description: str,
    evidence: str = "",
    recommendation: str = "",
    **metadata: Any,
) -> Finding:
    redacted_url = redact_url(url)
    digest = hashlib.sha256(f"{category}|{redacted_url}|{title}|{evidence}".encode("utf-8")).hexdigest()[:12]
    return Finding(
        title=title,
        severity=severity,
        category=category,
        description=redact_text(description),
        url=redacted_url,
        evidence=redact_text(evidence),
        reproduction=redact_text(f"Open {redacted_url}"),
        recommendation=recommendation,
        finding_id=f"CRW-{digest}",
        metadata=metadata,
    )


# ---------------------------------------------------------------------------
# Live crawler
# ---------------------------------------------------------------------------


class Crawler:
    """Bounded same-origin crawler with optional authenticated storage state."""

    def __init__(self, config: CrawlConfig | None = None) -> None:
        self.config = config or CrawlConfig()

    def crawl(self, url: str, browser: Browser | None = None) -> CrawlReport:
        started = time.perf_counter()
        start_url = normalize_url(url)
        if not start_url:
            raise ValueError("a valid http(s) URL is required")

        if self.config.auth_state and not Path(self.config.auth_state).exists():
            raise FileNotFoundError(f"auth state not found: {self.config.auth_state}")

        owned_playwright = browser is None
        playwright = sync_playwright().start() if owned_playwright else None
        active_browser = browser
        if active_browser is None:
            active_browser = playwright.chromium.launch(headless=True)

        context_options: dict[str, Any] = {"viewport": {"width": 390, "height": 844}}
        if self.config.auth_state:
            context_options["storage_state"] = self.config.auth_state
        context = active_browser.new_context(**context_options)

        report = CrawlReport(start_url=start_url)
        queue: deque[tuple[str, int]] = deque([(start_url, 0)])
        visited: set[str] = set()

        try:
            while queue and len(report.pages) < self.config.max_pages:
                current, depth = queue.popleft() if self.config.strategy == "bfs" else queue.pop()
                if current in visited:
                    continue
                visited.add(current)
                page_record = self._visit(context, current, depth)
                report.pages.append(page_record)
                report.visited_urls.append(current)
                self._collect_findings(report, page_record)
                if depth >= self.config.max_depth:
                    continue
                for link in page_record.links:
                    if link in visited:
                        continue
                    if self.config.same_origin_only and not same_origin(start_url, link):
                        continue
                    if is_asset_url(link):
                        continue
                    queue.append((link, depth + 1))
        finally:
            context.close()
            if owned_playwright:
                active_browser.close()
                playwright.stop()

        report.duration_ms = (time.perf_counter() - started) * 1000.0
        return report

    def _visit(self, context: Any, url: str, depth: int) -> PageRecord:
        page = context.new_page()
        console_errors: list[str] = []
        page_errors: list[str] = []
        failed_requests: list[dict[str, Any]] = []
        asset_responses: dict[str, int] = {}

        page.on("console", lambda message: console_errors.append(redact_text(message.text)) if message.type == "error" else None)
        page.on("pageerror", lambda error: page_errors.append(redact_text(str(error))))
        page.on(
            "requestfailed",
            lambda request: failed_requests.append(
                {
                    "url": redact_url(request.url),
                    "method": request.method,
                    "resource_type": request.resource_type,
                    "failure": redact_text(str(request.failure or "unknown")),
                }
            ),
        )
        page.on(
            "response",
            lambda response: asset_responses.__setitem__(redact_url(response.url), response.status)
            if response.request.resource_type in {"image", "script", "stylesheet", "font"}
            else None,
        )

        status: int | None = None
        final_url = url
        title = ""
        html = ""
        redirect_loop = False
        try:
            response = page.goto(url, wait_until="load", timeout=self.config.timeout_ms)
            status = response.status if response is not None else None
            final_url = page.url
            title = page.title()
            html = page.content()
            page.wait_for_timeout(40)
            chain: list[str] = []
            request = response.request if response is not None else None
            while request is not None:
                chain.append(normalize_url(request.url))
                request = request.redirected_from
            redirect_loop = detect_redirect_loop(chain)
        except PlaywrightError as exc:
            message = redact_text(str(exc))
            failed_requests.append({"url": redact_url(url), "method": "GET", "resource_type": "document", "failure": message})
            final_url = page.url if page.url else url

        data = extract_page_data(html, final_url) if html else {"links": [], "assets": [], "interactive": [], "mixed_content": []}

        broken_assets: list[str] = []
        if self.config.include_assets and html:
            try:
                images = page.eval_on_selector_all(
                    "img",
                    "els => els.map(e => ({src: e.currentSrc || e.src, naturalWidth: e.naturalWidth, complete: e.complete}))",
                )
            except PlaywrightError:
                images = []
            for image in images:
                src = normalize_url(str(image.get("src", "")), final_url)
                if not src:
                    continue
                if int(image.get("naturalWidth") or 0) == 0 or asset_responses.get(redact_url(src), 200) >= 400:
                    broken_assets.append(src)

        try:
            page.close()
        except PlaywrightError:
            pass

        return PageRecord(
            url=url,
            final_url=final_url,
            status=status,
            title=title,
            depth=depth,
            links=tuple(data.get("links", ())),
            assets=tuple(data.get("assets", ())),
            interactive=tuple(data.get("interactive", ())),
            console_errors=tuple(dict.fromkeys(console_errors)),
            page_errors=tuple(dict.fromkeys(page_errors)),
            failed_requests=tuple(failed_requests),
            broken_assets=tuple(dict.fromkeys(broken_assets)),
            mixed_content=tuple(data.get("mixed_content", ())),
            redirect_loop=redirect_loop,
        )

    def _collect_findings(self, report: CrawlReport, page: PageRecord) -> None:
        if page.status is not None and page.status >= 400:
            report.findings.append(
                _finding(
                    title=f"Broken page: HTTP {page.status}",
                    severity=Severity.HIGH,
                    category="broken-link",
                    url=page.url,
                    description=f"The crawler received HTTP {page.status} for a linked page.",
                    evidence=f"status={page.status}",
                    recommendation="Fix the link or return a valid page; add a regression check to CI.",
                )
            )

        if page.console_errors:
            report.findings.append(
                _finding(
                    title="Unhandled console errors",
                    severity=Severity.MEDIUM,
                    category="console-error",
                    url=page.url,
                    description="The page logs errors in the browser console.",
                    evidence=" | ".join(page.console_errors[:5]),
                    recommendation="Capture and fix console errors; fail E2E tests on unexpected errors.",
                )
            )

        if page.page_errors:
            report.findings.append(
                _finding(
                    title="Unhandled JavaScript exception",
                    severity=Severity.HIGH,
                    category="page-error",
                    url=page.url,
                    description="An uncaught exception interrupted page execution.",
                    evidence=" | ".join(page.page_errors[:3]),
                    recommendation="Add an error boundary and a Playwright pageerror assertion.",
                )
            )

        for asset in page.broken_assets:
            report.findings.append(
                _finding(
                    title="Dead image or asset",
                    severity=Severity.MEDIUM,
                    category="broken-asset",
                    url=page.url,
                    description="An image failed to decode or returned an HTTP error.",
                    evidence=asset,
                    recommendation="Restore the asset or remove the reference.",
                )
            )

        if page.mixed_content:
            report.findings.append(
                _finding(
                    title="Mixed HTTP content on HTTPS page",
                    severity=Severity.HIGH,
                    category="mixed-content",
                    url=page.url,
                    description="An HTTPS page loads insecure HTTP resources.",
                    evidence=" | ".join(page.mixed_content[:5]),
                    recommendation="Serve every asset over HTTPS.",
                )
            )

        if page.redirect_loop:
            report.findings.append(
                _finding(
                    title="Redirect loop or self-redirect",
                    severity=Severity.HIGH,
                    category="redirect-loop",
                    url=page.url,
                    description="The requested URL redirects back to itself.",
                    evidence=f"{page.url} -> {page.final_url}",
                    recommendation="Break the loop and add a single canonical destination.",
                )
            )

        for request in page.failed_requests:
            if request.get("resource_type") == "document":
                continue
            report.findings.append(
                _finding(
                    title=f"Failed {request.get('resource_type', 'resource')} request",
                    severity=Severity.MEDIUM,
                    category="failed-request",
                    url=page.url,
                    description="A network request failed before receiving a response.",
                    evidence=f"{request.get('method')} {request.get('url')} :: {request.get('failure')}",
                    recommendation="Handle the failure in the UI and retry idempotent requests.",
                    resource_type=request.get("resource_type"),
                )
            )
