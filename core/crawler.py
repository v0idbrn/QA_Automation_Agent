# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Smart Crawler & Performance Auditor for autonomous QA.

Provides:
- Async recursive crawling with Playwright.
- HTTP status and navigation failure capture (4xx/5xx).
- Uncaught JavaScript console error capture.
- Performance metrics (TTFB, page load time).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
from playwright.async_api import Page, Response


@dataclass(frozen=True)
class CrawlFinding:
    kind: LinkKind
    url: str
    parent: str
    detail: str = ""
    html_snapshot: str | None = None
    ttfb_ms: int | None = None
    load_time_ms: int | None = None


@dataclass(frozen=True)
class ConsoleError:
    message: str
    location: str
    level: str


@dataclass(frozen=True)
class PerformanceMetrics:
    url: str
    ttfb_ms: int | None = None
    load_time_ms: int | None = None


class LinkKind:
    ok = "ok"
    broken = "broken"
    external = "external"
    console_error = "console_error"
    queued = "queued"


class Crawler:
    def __init__(self, base_url: str, max_depth: int = 2, max_links: int = 50) -> None:
        self.base_url = base_url
        self.base_netloc = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.max_links = max_links
        self._visited: set[str] = set()
        self.metrics: list[PerformanceMetrics] = []

    @property
    def visited(self) -> set[str]:
        return set(self._visited)

    def _is_internal(self, url: str) -> bool:
        parsed = urlparse(url)
        return parsed.netloc == self.base_netloc

    def extract_links(self, soup: BeautifulSoup, page_url: str) -> list[str]:
        links: list[str] = []
        for anchor in soup.find_all("a", href=True):
            href = anchor["href"].strip()
            if not href or href.startswith("#") or href.startswith("javascript:"):
                continue
            resolved = urljoin(page_url, href)
            if not self._is_internal(resolved):
                continue
            if resolved not in self._visited and resolved not in links:
                links.append(resolved)
        return links

    def _snapshot_html(self, page: Page) -> str:
        try:
            return page.content()
        except Exception as exc:  # noqa: BLE001
            return f"<!-- snapshot failed: {exc} -->"


async def crawl_page(
    page: Page,
    url: str,
    crawler: Crawler,
    findings: list[Any],
    max_links: int = 50,
    screenshot_on_failure: bool = True,
) -> bool:
    """
    Crawl a single page asynchronously.

    Returns True if the page was fetched successfully, False otherwise.
    Appends findings (broken links, console errors, performance metrics) to the shared list.
    """
    if url in crawler.visited:
        return True
    crawler._visited.add(url)

    console_handler = _console_handler_decorator(findings)
    page.on("console", console_handler)

    ttfb_start = time.perf_counter()
    try:
        response: Response | None = await page.goto(url, wait_until="domcontentloaded", timeout=20000)
    except Exception as exc:  # noqa: BLE001
        ttfb_ms = int((time.perf_counter() - ttfb_start) * 1000)
        findings.append(
            CrawlFinding(
                kind=LinkKind.broken,
                url=url,
                parent="",
                detail=f"navigation error: {exc}",
                html_snapshot=None,
                ttfb_ms=ttfb_ms,
            )
        )
        if screenshot_on_failure:
            await _maybe_screenshot(page, url)
        return False

    ttfb_ms = int((time.perf_counter() - ttfb_start) * 1000)

    if response is None:
        findings.append(
            CrawlFinding(
                kind=LinkKind.broken,
                url=url,
                parent="",
                detail="no response returned",
                html_snapshot=None,
                ttfb_ms=ttfb_ms,
            )
        )
        if screenshot_on_failure:
            await _maybe_screenshot(page, url)
        return False

    status = getattr(response, "status", 0)
    if status >= 400:
        load_time_ms = None
        try:
            load_start = time.perf_counter()
            await page.wait_for_load_state("networkidle", timeout=5000)
            load_time_ms = int((time.perf_counter() - load_start) * 1000)
        except Exception:  # noqa: BLE001
            pass

        findings.append(
            CrawlFinding(
                kind=LinkKind.broken,
                url=url,
                parent="",
                detail=f"http {status}",
                html_snapshot=crawler._snapshot_html(page),
                ttfb_ms=ttfb_ms,
                load_time_ms=load_time_ms,
            )
        )
        if screenshot_on_failure:
            await _maybe_screenshot(page, url)
        return False

    load_start = time.perf_counter()
    try:
        await page.wait_for_load_state("networkidle", timeout=10000)
    except Exception:  # noqa: BLE001
        pass
    load_time_ms = int((time.perf_counter() - load_start) * 1000)

    crawler.metrics.append(
        PerformanceMetrics(url=url, ttfb_ms=ttfb_ms, load_time_ms=load_time_ms)
    )

    html = crawler._snapshot_html(page)
    soup = BeautifulSoup(html, "html.parser")
    links = crawler.extract_links(soup, url)

    for link in links[: max_links - len(crawler.visited)]:
        crawler._visited.add(link)
        finding = CrawlFinding(
            kind=LinkKind.queued,
            url=link,
            parent=url,
            detail="queued",
            html_snapshot=None,
        )
        findings.append(finding)

    return True


class _ConsoleHandlerRegistry:
    def __init__(self, findings: list[Any]) -> None:
        self.findings = findings

    def __call__(self, message):
        msg_type = getattr(message, "message_type", None)
        if msg_type is None:
            msg_type = getattr(message, "type", None) or getattr(message, "kind", None)
        if msg_type in ("error", "warning"):
            location = getattr(message, "location", None)
            loc_url = getattr(location, "url", "unknown") if location is not None else "unknown"
            line = getattr(location, "line_number", 0) if location is not None else 0
            col = getattr(location, "column_number", 0) if location is not None else 0
            loc_str = f"{loc_url}:{line}:{col}"
            collector = getattr(self.findings, "append", None)
            if collector is not None:
                collector(
                    ConsoleError(
                        message=getattr(message, "text", ""),
                        location=loc_str,
                        level=msg_type or getattr(message, "type", "unknown"),
                    )
                )


def _console_handler_decorator(findings: list[Any]) -> _ConsoleHandlerRegistry:
    return _ConsoleHandlerRegistry(findings)


async def _maybe_screenshot(page: Page, url: str) -> None:
    try:
        path = f"screenshot_{urlparse(url).path.strip('/') or 'index'}.png"
        await page.screenshot(path=path, full_page=False)
    except Exception:  # noqa: BLE001
        pass


async def run_audit_pipeline(
    page: Page,
    urls: list[str],
    max_links: int = 50,
) -> tuple[list[Any], Crawler]:
    """Run a small audit pipeline over a list of URLs and return findings plus crawler state."""
    findings: list[Any] = []
    crawler = Crawler(base_url=urls[0] if urls else "https://example.test")
    for target in urls:
        _ = await crawl_page(page, target, crawler, findings, max_links=max_links)
    return findings, crawler
