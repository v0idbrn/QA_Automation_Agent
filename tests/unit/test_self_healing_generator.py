# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Unit tests for locator recovery and Playwright test generation."""

from __future__ import annotations

import pytest

from qa_agent.crawler import CrawlReport, InteractiveElement, PageRecord
from qa_agent.self_healing import (
    ElementSignature,
    SelfHealingResolver,
    recover_selector,
    selector_patch,
    similarity,
    text_similarity,
)
from qa_agent.test_generator import E2ETestGenerator, GeneratedTest, generate_test_file, slugify


@pytest.mark.parametrize(
    ("first", "second", "expected"),
    [
        ("Pay now", "Pay now", 1.0),
        ("pay now", "Pay Now", 1.0),
        ("Pay now", "Pay", 0.5),
        ("Pay now", "Cancel", 0.0),
        ("", "", 1.0),
        ("", "Pay", 0.0),
        ("Proceed to checkout", "Proceed to checkout page", 0.75),
    ],
)
def test_text_similarity(first: str, second: str, expected: float) -> None:
    assert text_similarity(first, second) == pytest.approx(expected)


def test_similarity_identical_elements() -> None:
    signature = ElementSignature(tag="button", role="button", text="Pay now", testid="pay")
    assert similarity(signature, signature) == pytest.approx(1.0)


def test_similarity_unrelated_elements_is_low() -> None:
    first = ElementSignature(tag="button", role="button", text="Pay now", testid="pay")
    second = ElementSignature(tag="a", role="link", text="Read the blog", testid="blog")
    assert similarity(first, second) < 0.2


def test_similarity_testid_dominates() -> None:
    target = ElementSignature(tag="button", role="button", text="Pay now", testid="pay")
    same_id = ElementSignature(tag="button", role="button", text="Other", testid="pay")
    same_text = ElementSignature(tag="button", role="button", text="Pay now")
    assert similarity(target, same_id) > similarity(target, same_text)


def test_similarity_handles_empty_signatures() -> None:
    assert similarity(ElementSignature(), ElementSignature()) == 0.0


def test_signature_from_mapping() -> None:
    signature = ElementSignature.from_mapping({"tag": "BUTTON", "data-testid": "x", "parent": "FORM"})
    assert signature.tag == "button"
    assert signature.testid == "x"
    assert signature.parent_tag == "form"


@pytest.mark.parametrize(
    ("signature", "expected"),
    [
        (ElementSignature(testid="pay"), 'get_by_test_id("pay")'),
        (ElementSignature(role="button", text="Pay"), 'get_by_role("button", name="Pay")'),
        (ElementSignature(name="email"), 'locator("[name=\\"email\\"]")'),
        (ElementSignature(placeholder="Email"), 'get_by_placeholder("Email")'),
        (ElementSignature(text="Continue"), 'get_by_text("Continue")'),
        (ElementSignature(tag="form"), 'locator("form")'),
        (ElementSignature(), 'locator("*")'),
    ],
)
def test_selector_patch_precedence(signature: ElementSignature, expected: str) -> None:
    assert selector_patch(signature) == expected


def test_recover_selector_finds_best_match() -> None:
    target = ElementSignature(role="button", text="Place order", testid="place-order")
    candidates = [
        ElementSignature(role="link", text="Cancel", testid="cancel"),
        ElementSignature(role="button", text="Place order", testid="place-order", selector="#new"),
    ]
    recovery = recover_selector(target, candidates)
    assert recovery is not None
    assert recovery.matched.selector == "#new"
    assert recovery.confidence > 0.9
    assert "get_by_test_id" in recovery.selector_patch


def test_recover_selector_returns_none_below_threshold() -> None:
    target = ElementSignature(role="button", text="Pay now", testid="pay")
    candidates = [ElementSignature(role="link", text="Blog", testid="blog")]
    assert recover_selector(target, candidates, threshold=0.9) is None


def test_recover_selector_empty_candidates() -> None:
    assert recover_selector(ElementSignature(text="Pay"), []) is None


def test_recovery_serializes() -> None:
    target = ElementSignature(text="Pay")
    recovery = recover_selector(target, [ElementSignature(text="Pay", selector="#pay")])
    payload = recovery.to_dict()
    assert payload["confidence"] == 1.0
    assert "get_by_text" in payload["selector_patch"]


def test_resolver_tracks_history_and_rate() -> None:
    resolver = SelfHealingResolver()
    target = ElementSignature(role="button", text="Pay")
    assert resolver.resolve("#pay", [{"text": "Pay", "role": "button", "selector": "#pay"}], target=target) is not None
    assert resolver.resolve("#ghost", [{"text": "Nothing", "role": "link"}], target=target) is None
    assert len(resolver.history) == 2
    assert resolver.recovery_rate == 0.5
    assert resolver.to_dict()["events"][0]["success"] is True


def test_resolver_parses_legacy_selector() -> None:
    resolver = SelfHealingResolver()
    recovery = resolver.resolve('[data-testid="pay"]', [{"testid": "pay", "role": "button", "text": "Pay"}])
    assert recovery is not None
    assert recovery.confidence >= 0.5


def test_resolver_accepts_signature_candidates() -> None:
    resolver = SelfHealingResolver()
    recovery = resolver.resolve(
        "#x",
        [ElementSignature(tag="button", text="Go", selector="#x")],
        target=ElementSignature(tag="button", text="Go", selector="#x"),
    )
    assert recovery is not None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("Checkout", "checkout"),
        ("/pricing/", "pricing"),
        ("My Page", "my-page"),
        ("Über 42", "ber-42"),
        ("", "page"),
        ("---", "page"),
        ("A/B", "a-b"),
    ],
)
def test_slugify(value: str, expected: str) -> None:
    assert slugify(value) == expected


def page(url: str = "https://app.example.com/checkout") -> PageRecord:
    interactive = (
        InteractiveElement(tag="button", role="button", name="Place order", testid="place-order"),
        InteractiveElement(tag="input", role="textbox", name="Email"),
        InteractiveElement(tag="a", role="link", name="Home"),
    )
    return PageRecord(
        url=url,
        final_url=url,
        status=200,
        title="Checkout",
        depth=0,
        interactive=interactive,
    )


def test_generate_test_file_is_valid_python() -> None:
    generated = generate_test_file(page(), "https://app.example.com")
    compile(generated.content, generated.path, "exec")
    assert generated.path == "test_checkout.py"


def test_generated_content_uses_resilient_locators() -> None:
    content = generate_test_file(page(), "https://app.example.com").content
    assert "get_by_role" in content
    assert "set_viewport_size" in content
    assert "scrollWidth" in content


def test_generated_content_uses_testid_when_available() -> None:
    record = PageRecord(
        url="https://app.example.com/checkout",
        final_url="https://app.example.com/checkout",
        status=200,
        title="Checkout",
        depth=0,
        interactive=(InteractiveElement(tag="button", role="button", testid="place-order"),),
    )
    assert "get_by_test_id" in generate_test_file(record).content


def test_generated_content_has_browser_fixture() -> None:
    content = generate_test_file(page()).content
    assert "def page():" in content
    assert "sync_playwright" in content


def test_generated_handles_missing_title() -> None:
    record = PageRecord(url="https://app.example.com/x", final_url="", status=200, title="", depth=0)
    content = generate_test_file(record).content
    assert "to_be_visible" in content


def test_generated_test_writes_to_disk(tmp_path) -> None:
    generated = generate_test_file(page())
    target = generated.write(tmp_path / "generated_tests")
    assert target.is_file()
    assert target.read_text(encoding="utf-8") == generated.content


def test_generator_writes_one_module_per_page(tmp_path) -> None:
    report = CrawlReport(
        start_url="https://app.example.com/",
        pages=[page("https://app.example.com/checkout"), page("https://app.example.com/about")],
    )
    written = E2ETestGenerator(output_dir=tmp_path).write(report=report)
    assert len(written) == 2
    assert all(path.is_file() for path in written)


def test_generator_avoids_duplicate_paths(tmp_path) -> None:
    duplicate = page("https://app.example.com/checkout")
    report = CrawlReport(start_url="https://app.example.com/", pages=[duplicate, duplicate])
    assert len(E2ETestGenerator(output_dir=tmp_path).write(report=report)) == 1


def test_generator_from_pages_without_base() -> None:
    generated = E2ETestGenerator().from_pages([page()])
    assert generated[0].page_url == "https://app.example.com/checkout"


def test_generated_test_dataclass_exposes_fields() -> None:
    item = GeneratedTest(path="test_x.py", content="x = 1\n", page_url="https://app.example.com/")
    assert item.path.endswith(".py")
    assert item.page_url.endswith("/")
