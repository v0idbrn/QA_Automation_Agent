# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Generate runnable Pytest + Playwright E2E tests from a crawled page.

The generator never runs the tests it writes. It emits a self-contained module
using resilient ``get_by_role`` / ``get_by_label`` locators, plus navigation,
responsive-overflow and API status assertions derived from the crawl report.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

from qa_agent.crawler import CrawlReport, InteractiveElement, PageRecord

__all__ = [
    "GeneratedTest",
    "E2ETestGenerator",
    "generate_test_file",
    "slugify",
]

_SLUG_RE = re.compile(r"[^a-z0-9]+")
_PYTHON_KEYWORDS = frozenset(
    {
        "and", "as", "assert", "async", "await", "break", "class", "continue", "def", "del",
        "elif", "else", "except", "finally", "for", "from", "global", "if", "import", "in",
        "is", "lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try", "while",
        "with", "yield", "none", "true", "false",
    }
)


def slugify(value: str) -> str:
    cleaned = _SLUG_RE.sub("-", str(value).lower()).strip("-")
    return cleaned or "page"


def _identifier(value: str, fallback: str = "page") -> str:
    candidate = re.sub(r"\W+", "_", str(value).strip().lower()).strip("_") or fallback
    if candidate[0].isdigit():
        candidate = f"page_{candidate}"
    if candidate in _PYTHON_KEYWORDS:
        candidate = f"{candidate}_page"
    return candidate


def _quote(value: str) -> str:
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _locator(element: InteractiveElement) -> str | None:
    if element.role and element.name and element.role in {"button", "link", "textbox", "checkbox", "radio", "combobox"}:
        return f'page.get_by_role({_quote(element.role)}, name={_quote(element.name)})'
    if element.testid:
        return f'page.get_by_test_id({_quote(element.testid)})'
    if element.placeholder:
        return f'page.get_by_placeholder({_quote(element.placeholder)})'
    if element.tag in {"input", "select", "textarea"} and element.name:
        return f'page.get_by_label({_quote(element.name)})'
    return None


@dataclass
class GeneratedTest:
    path: str
    content: str
    page_url: str

    def write(self, directory: str | Path) -> Path:
        target = Path(directory) / self.path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.content, encoding="utf-8")
        return target


def _render(page: PageRecord, base_url: str) -> str:
    name = _identifier(slugify(page.url.rsplit("/", 1)[-1] or "home"))
    controls = [item for item in page.interactive if _locator(item)]
    form_controls = [item for item in controls if item.tag in {"input", "select", "textarea"}][:6]
    button_controls = [item for item in controls if item.role == "button"][:4]

    lines = [
        '"""Auto-generated E2E smoke suite. Review before committing.',
        "",
        f"Source page: {page.url}",
        '"""',
        "",
        "from __future__ import annotations",
        "",
        "import pytest",
        "from playwright.sync_api import Page, expect, sync_playwright",
        "",
        "pytestmark = pytest.mark.e2e",
        "",
        "",
        "@pytest.fixture()",
        "def page():",
        "    \"\"\"Self-contained browser fixture so this module runs unmodified.\"\"\"",
        "    with sync_playwright() as playwright:",
        "        browser = playwright.chromium.launch(headless=True)",
        "        context = browser.new_context()",
        "        current = context.new_page()",
        "        try:",
        "            yield current",
        "        finally:",
        "            context.close()",
        "            browser.close()",
        "",
        "",
        f"PAGE_URL = {_quote(page.final_url or page.url)}",
        f"BASE_URL = {_quote(base_url)}",
        "",
        "",
        f"def test_{name}_loads(page: Page) -> None:",
        "    response = page.goto(PAGE_URL, wait_until=\"domcontentloaded\")",
        "    assert response is not None",
        "    assert response.status < 400",
        f"    expect(page).to_have_title({_quote(page.title)})" if page.title else "    expect(page.locator(\"body\")).to_be_visible()",
        "",
    ]

    if button_controls:
        lines += [
            "",
            f"def test_{name}_interactive_controls_are_visible(page: Page) -> None:",
            "    page.goto(PAGE_URL, wait_until=\"domcontentloaded\")",
        ]
        for button in button_controls:
            lines.append(f"    expect({_locator(button)}).to_be_visible()")
        lines.append("")

    if form_controls:
        lines += [
            "",
            f"def test_{name}_form_controls_are_reachable(page: Page) -> None:",
            "    page.goto(PAGE_URL, wait_until=\"domcontentloaded\")",
        ]
        for control in form_controls:
            lines.append(f"    expect({_locator(control)}).to_be_visible()")
        lines += [
            "    first = page.locator(\"input, select, textarea\").first",
            "    if first.count():",
            "        first.focus()",
            "        expect(first).to_be_focused()",
            "",
        ]

    lines += [
        "",
        f"def test_{name}_has_no_horizontal_overflow(page: Page) -> None:",
        "    page.set_viewport_size({\"width\": 390, \"height\": 844})",
        "    page.goto(PAGE_URL, wait_until=\"domcontentloaded\")",
        "    metrics = page.evaluate(",
        '        "() => ({scroll: document.documentElement.scrollWidth, client: document.documentElement.clientWidth})"',
        "    )",
        "    assert metrics[\"scroll\"] <= metrics[\"client\"] + 1, \"horizontal overflow at 390x844\"",
        "",
        "",
        f"def test_{name}_primary_api_responds(page: Page) -> None:",
        "    response = page.request.get(BASE_URL + \"/\")",
        "    assert response.status < 500",
        "",
    ]
    return "\n".join(lines)


def generate_test_file(page: PageRecord, base_url: str | None = None) -> GeneratedTest:
    source = base_url or page.url
    stem = slugify(page.url.rstrip("/").rsplit("/", 1)[-1] or "home")
    return GeneratedTest(
        path=f"test_{stem}.py",
        content=_render(page, source),
        page_url=page.url,
    )


@dataclass
class E2ETestGenerator:
    """Write one module per crawled page into ``generated_tests/`` by default."""

    output_dir: str | Path = "generated_tests"
    written: list[GeneratedTest] = field(default_factory=list)

    def from_pages(self, pages: Iterable[PageRecord], base_url: str | None = None) -> list[GeneratedTest]:
        generated: list[GeneratedTest] = []
        seen: set[str] = set()
        for page in pages:
            item = generate_test_file(page, base_url)
            if item.path in seen:
                continue
            seen.add(item.path)
            generated.append(item)
        return generated

    def from_report(self, report: CrawlReport) -> list[GeneratedTest]:
        return self.from_pages(report.pages, report.start_url)

    def write(self, pages: Sequence[PageRecord] | None = None, report: CrawlReport | None = None, base_url: str | None = None) -> list[Path]:
        if pages is None:
            pages = report.pages if report is not None else []
        if report is not None and base_url is None:
            base_url = report.start_url
        items = self.from_pages(pages, base_url)
        written = [item.write(self.output_dir) for item in items]
        self.written.extend(items)
        return written
