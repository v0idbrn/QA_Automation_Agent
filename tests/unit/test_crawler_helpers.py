# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Unit tests for crawler URL/HTML helpers and bounded configuration."""

from __future__ import annotations

import pytest

from qa_agent.crawler import (
    CrawlConfig,
    CrawlReport,
    InteractiveElement,
    PageRecord,
    detect_mixed_content,
    detect_redirect_loop,
    extract_page_data,
    is_asset_url,
    normalize_url,
    same_origin,
)
from qa_agent.models import Finding


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://Example.COM/Path?q=1#frag", "https://example.com/Path?q=1"),
        ("https://example.com", "https://example.com/"),
        ("  https://example.com/a  ", "https://example.com/a"),
        ("/relative", ""),
        ("mailto:qa@example.com", ""),
        ("javascript:alert(1)", ""),
        ("data:text/plain,hi", ""),
        ("", ""),
        ("ftp://example.com/file", ""),
    ],
)
def test_normalize_url(raw: str, expected: str) -> None:
    assert normalize_url(raw) == expected


def test_normalize_url_joins_base() -> None:
    assert normalize_url("../pricing?x=1", "https://app.example.com/shop/cart") == "https://app.example.com/pricing?x=1"


def test_normalize_url_drops_fragment_only() -> None:
    assert normalize_url("#section", "https://app.example.com/docs") == "https://app.example.com/docs"


@pytest.mark.parametrize(
    ("first", "second", "expected"),
    [
        ("https://a.example.com/x", "https://a.example.com/y", True),
        ("https://a.example.com/x", "https://b.example.com/x", False),
        ("https://a.example.com/x", "http://a.example.com/x", False),
        ("https://a.example.com/x", "https://a.example.com:8443/x", False),
        ("http://a.example.com:80/x", "http://a.example.com/y", True),
    ],
)
def test_same_origin(first: str, second: str, expected: bool) -> None:
    assert same_origin(first, second) is expected


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://cdn.example.com/app.js", True),
        ("https://cdn.example.com/logo.png", True),
        ("https://cdn.example.com/font.woff2", True),
        ("https://app.example.com/checkout", False),
        ("https://app.example.com/api/orders", False),
    ],
)
def test_is_asset_url(url: str, expected: bool) -> None:
    assert is_asset_url(url) is expected


def test_detect_mixed_content_on_https_page() -> None:
    assert detect_mixed_content("https://app.example.com", ["http://cdn.example.com/a.js"]) == ["http://cdn.example.com/a.js"]


def test_detect_mixed_content_ignores_https_page_with_secure_assets() -> None:
    assert detect_mixed_content("https://app.example.com", ["https://cdn.example.com/a.js"]) == []


def test_detect_mixed_content_ignores_http_page() -> None:
    assert detect_mixed_content("http://app.example.com", ["http://cdn.example.com/a.js"]) == []


def test_detect_redirect_loop_true() -> None:
    assert detect_redirect_loop(["https://a.example.com/x", "https://a.example.com/y", "https://a.example.com/x"]) is True


def test_detect_redirect_loop_false_for_distinct_urls() -> None:
    assert detect_redirect_loop(["https://a.example.com/x", "https://a.example.com/y"]) is False


def test_detect_redirect_loop_empty() -> None:
    assert detect_redirect_loop([]) is False


HTML = """
<html><body>
  <a href="/checkout">Checkout</a>
  <a href="/checkout">Checkout again</a>
  <a href="mailto:qa@example.com">Mail</a>
  <img src="/logo.png">
  <img src="http://cdn.example.com/banner.jpg">
  <script src="/assets/app.js"></script>
  <link rel="stylesheet" href="/assets/app.css">
  <form action="/api/checkout" method="post">
    <input name="email" type="email" placeholder="Email" required>
    <button type="submit">Pay</button>
  </form>
</body></html>
"""


def test_extract_page_data_links_and_assets() -> None:
    data = extract_page_data(HTML, "https://app.example.com/")
    assert "https://app.example.com/checkout" in data["links"]
    assert data["links"].count("https://app.example.com/checkout") == 1
    assert "https://app.example.com/logo.png" in data["assets"]
    assert "https://app.example.com/assets/app.js" in data["assets"]
    assert "https://app.example.com/assets/app.css" in data["assets"]


def test_extract_page_data_mixed_content() -> None:
    data = extract_page_data(HTML, "https://app.example.com/")
    assert data["mixed_content"] == ["http://cdn.example.com/banner.jpg"]


def test_extract_page_data_forms() -> None:
    data = extract_page_data(HTML, "https://app.example.com/")
    form = data["forms"][0]
    assert form["action"] == "https://app.example.com/api/checkout"
    assert form["method"] == "POST"
    assert form["fields"][0]["name"] == "email"
    assert form["fields"][0]["required"] is True


def test_extract_page_data_interactive_roles() -> None:
    data = extract_page_data(HTML, "https://app.example.com/")
    roles = {(item.tag, item.role) for item in data["interactive"]}
    assert ("a", "link") in roles
    assert ("input", "textbox") in roles
    assert ("button", "button") in roles


def test_extract_page_data_empty_html() -> None:
    data = extract_page_data("<html></html>", "https://app.example.com/")
    assert data["links"] == []
    assert data["assets"] == []
    assert data["interactive"] == []


def test_interactive_element_serializes() -> None:
    element = InteractiveElement(tag="button", role="button", name="Pay", testid="pay")
    assert element.to_dict()["testid"] == "pay"


@pytest.mark.parametrize(("field", "kwargs"), [("strategy", {"strategy": "random"}), ("max_pages", {"max_pages": 0})])
def test_crawl_config_rejects_invalid_values(field: str, kwargs: dict) -> None:
    with pytest.raises(ValueError):
        CrawlConfig(**kwargs)


def test_crawl_config_defaults() -> None:
    config = CrawlConfig()
    assert config.strategy == "bfs"
    assert config.max_pages >= 1
    assert config.same_origin_only is True


def test_page_record_redacts_url() -> None:
    page = PageRecord(url="https://app.example.com/?token=abc", final_url="", status=200, title="t", depth=0)
    assert "abc" not in page.url_redacted


def test_crawl_report_severity_gate() -> None:
    report = CrawlReport(start_url="https://app.example.com")
    assert report.passed is True
    report.findings.append(Finding("x", "critical", "c"))
    assert report.passed is False


def test_crawl_report_counts_errors() -> None:
    page = PageRecord(url="u", final_url="u", status=200, title="t", depth=0, console_errors=("a", "b"), page_errors=("c",))
    report = CrawlReport(start_url="u", pages=[page])
    assert report.console_error_count == 2
    assert report.page_error_count == 1


def test_crawl_report_serializes_redacted() -> None:
    page = PageRecord(url="https://app.example.com/?token=abc", final_url="https://app.example.com/", status=200, title="t", depth=1)
    payload = CrawlReport(start_url="https://app.example.com/", pages=[page], duration_ms=1.234).to_dict()
    assert "abc" not in payload["pages"][0]["url"]
    assert payload["passed"] is True
    assert payload["duration_ms"] == 1.23
