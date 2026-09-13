import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.crawler import (
    ConsoleError,
    CrawlFinding,
    Crawler,
    LinkKind,
    crawl_page,
    run_audit_pipeline,
)


@pytest.fixture
def browser_page():
    page = MagicMock()
    page.url = "https://example.test/"
    page.goto = AsyncMock()
    page.wait_for_load_state = AsyncMock()
    page.query_selector_all = MagicMock(return_value=[])
    page.on = MagicMock()
    page.screenshot = AsyncMock()
    page.content = AsyncMock(return_value="<html></html>")
    return page


class TestCrawlFinding:
    def test_link_finding_defaults(self):
        finding = CrawlFinding(
            kind=LinkKind.broken,
            url="https://example.test/missing",
            parent="https://example.test/",
            detail="404 Not Found",
        )
        assert finding.kind == LinkKind.broken
        assert finding.url == "https://example.test/missing"
        assert finding.parent == "https://example.test/"
        assert finding.detail == "404 Not Found"
        assert finding.html_snapshot is None

    def test_performance_fields_optional(self):
        finding = CrawlFinding(kind=LinkKind.broken, url="/", parent="")
        assert finding.ttfb_ms is None
        assert finding.load_time_ms is None


class TestCrawlerEngine:
    @pytest.mark.asyncio
    async def test_extract_links_only_accepts_same_origin(self, browser_page):
        browser_page.url = "https://example.test/"
        html = """
        <html>
          <body>
            <a href="/about">About</a>
            <a href="https://other.test/bad">External</a>
            <a href="#anchor">Anchor</a>
          </body>
        </html>
        """
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html, "html.parser")
        crawler = Crawler(base_url="https://example.test")
        links = crawler.extract_links(soup, "https://example.test/")
        assert len(links) == 1
        assert links[0] == "https://example.test/about"

    @pytest.mark.asyncio
    async def test_extract_links_normalizes_relative_paths(self, browser_page):
        from bs4 import BeautifulSoup

        html = """
        <html>
          <body>
            <a href="contact">Contact</a>
            <a href="./terms">Terms</a>
          </body>
        </html>
        """
        soup = BeautifulSoup(html, "html.parser")
        crawler = Crawler(base_url="https://example.test/")
        links = crawler.extract_links(soup, "https://example.test/")
        assert "https://example.test/contact" in links
        assert "https://example.test/terms" in links

    @pytest.mark.asyncio
    async def test_crawl_record_performance_metrics_on_success(self, browser_page):
        class FakeResponse:
            status = 200

        browser_page.goto = AsyncMock(return_value=FakeResponse())
        browser_page.wait_for_load_state = AsyncMock()
        browser_page.url = "https://example.test/ok"
        browser_page.query_selector_all = MagicMock(return_value=[])
        browser_page.screenshot = AsyncMock()
        browser_page.content = AsyncMock(return_value="<html></html>")

        findings: list = []
        crawler = Crawler(base_url="https://example.test")

        with patch("core.crawler.Crawler._snapshot_html", new=AsyncMock(return_value="<html></html>")):
            result = await crawl_page(
                page=browser_page,
                url="https://example.test/ok",
                crawler=crawler,
                findings=findings,
                max_links=10,
            )

        assert result is True
        assert crawler.metrics
        assert crawler.metrics[0].url == "https://example.test/ok"
        assert crawler.metrics[0].ttfb_ms is not None


class TestCrawlPageFlow:
    @pytest.mark.asyncio
    async def test_crawl_page_marks_failure_on_non_200(self, browser_page):
        class FakeResponse:
            status = 500

        browser_page.goto = AsyncMock(return_value=FakeResponse())
        browser_page.wait_for_load_state = AsyncMock()
        browser_page.url = "https://example.test/error"
        browser_page.query_selector_all = MagicMock(return_value=[])
        browser_page.screenshot = AsyncMock()
        browser_page.content = AsyncMock(return_value="<html></html>")

        findings: list = []

        with patch("core.crawler.Crawler._snapshot_html", new=AsyncMock(return_value="<html></html>")):
            result = await crawl_page(
                page=browser_page,
                url="https://example.test/error",
                crawler=Crawler(base_url="https://example.test"),
                findings=findings,
                max_links=10,
            )

        assert result is False
        assert any(f.url == "https://example.test/error" for f in findings)

    @pytest.mark.asyncio
    async def test_crawl_page_captures_navigation_errors(self, browser_page):
        browser_page.goto = AsyncMock(side_effect=Exception("connection lost"))
        browser_page.url = "https://example.test/broken"
        browser_page.screenshot = AsyncMock()

        findings: list = []

        result = await crawl_page(
            page=browser_page,
            url="https://example.test/broken",
            crawler=Crawler(base_url="https://example.test"),
            findings=findings,
            max_links=10,
        )

        assert result is False
        assert any("navigation error" in f.detail for f in findings)


class TestPipelineHelper:
    @pytest.mark.asyncio
    async def test_run_audit_pipeline_returns_findings_and_crawler(self):
        page = MagicMock()
        page.goto = AsyncMock(side_effect=Exception("skip"))
        page.wait_for_load_state = AsyncMock()
        page.url = "https://example.test/"
        page.content = AsyncMock(return_value="<html></html>")

        findings, crawler = await run_audit_pipeline(page, ["https://example.test/"], max_links=5)

        assert isinstance(findings, list)
        assert isinstance(crawler, Crawler)
