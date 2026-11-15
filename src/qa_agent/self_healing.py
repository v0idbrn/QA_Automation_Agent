# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Weighted DOM-similarity locator recovery.

When a selector breaks, the resolver scores every candidate element against the
original signature across independent attributes (test id, role, accessible
text, name, placeholder, tag hierarchy) and returns the best match with a
confidence score plus a resilient selector patch.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

__all__ = [
    "ElementSignature",
    "Recovery",
    "SelfHealingResolver",
    "WEIGHTS",
    "recover_selector",
    "selector_patch",
    "similarity",
    "text_similarity",
]

_WEIGHTS = {
    "testid": 0.34,
    "role": 0.18,
    "text": 0.22,
    "name": 0.10,
    "placeholder": 0.08,
    "tag": 0.05,
    "parent_tag": 0.03,
}
WEIGHTS: Mapping[str, float] = dict(_WEIGHTS)

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokens(value: str) -> set[str]:
    return set(_TOKEN_RE.findall(str(value).lower()))


def text_similarity(first: str, second: str) -> float:
    """Jaccard token overlap with a containment fallback for short labels."""
    if not first and not second:
        return 1.0
    if not first or not second:
        return 0.0
    left, right = _tokens(first), _tokens(second)
    if not left or not right:
        return 1.0 if str(first).strip().lower() == str(second).strip().lower() else 0.0
    intersection = len(left & right)
    return intersection / len(left | right)


@dataclass(frozen=True)
class ElementSignature:
    tag: str = ""
    role: str = ""
    text: str = ""
    testid: str = ""
    name: str = ""
    placeholder: str = ""
    parent_tag: str = ""
    attributes: Mapping[str, str] = field(default_factory=dict)
    selector: str = ""

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "ElementSignature":
        return cls(
            tag=str(data.get("tag", "")).lower(),
            role=str(data.get("role", "")).lower(),
            text=str(data.get("text", "")),
            testid=str(data.get("testid", data.get("data-testid", ""))),
            name=str(data.get("name", "")),
            placeholder=str(data.get("placeholder", "")),
            parent_tag=str(data.get("parent", data.get("parent_tag", ""))).lower(),
            attributes={str(key): str(value) for key, value in (data.get("attributes") or {}).items()},
            selector=str(data.get("selector", "")),
        )

    def attribute(self, key: str, default: str = "") -> str:
        return self.attributes.get(key, default)


def _attribute_score(target: str, candidate: str, weight: float) -> tuple[float, float]:
    # Only attributes present in the original signature are expectations.
    if not target:
        return 0.0, 0.0
    if target and candidate and target.strip().lower() == candidate.strip().lower():
        return weight, weight
    return 0.0, weight


def similarity(target: ElementSignature, candidate: ElementSignature) -> float:
    """Return a 0..1 confidence score between two element signatures."""
    scored = 0.0
    total = 0.0
    for attribute, weight in _WEIGHTS.items():
        if attribute == "text":
            if not target.text:
                continue
            scored += text_similarity(target.text, candidate.text) * weight
            total += weight
            continue
        first = getattr(target, attribute)
        second = getattr(candidate, attribute)
        points, available = _attribute_score(first, second, weight)
        scored += points
        total += available
    if total == 0:
        return 0.0
    return max(0.0, min(1.0, scored / total))


def selector_patch(signature: ElementSignature) -> str:
    """Emit a resilient Playwright locator for the recovered element."""
    if signature.testid:
        return f'get_by_test_id("{signature.testid}")'
    if signature.role and signature.text:
        return f'get_by_role("{signature.role}", name="{signature.text}")'
    if signature.name:
        return f'locator("[name=\\"{signature.name}\\"]")'
    if signature.placeholder:
        return f'get_by_placeholder("{signature.placeholder}")'
    if signature.text:
        return f'get_by_text("{signature.text}")'
    if signature.tag:
        return f'locator("{signature.tag}")'
    return "locator(\"*\")"


@dataclass(frozen=True)
class Recovery:
    matched: ElementSignature
    confidence: float
    selector_patch: str
    original: ElementSignature
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "confidence": round(self.confidence, 3),
            "selector_patch": self.selector_patch,
            "matched_selector": self.matched.selector,
            "reason": self.reason,
        }


def recover_selector(
    target: ElementSignature,
    candidates: Sequence[ElementSignature],
    *,
    threshold: float = 0.55,
) -> Recovery | None:
    best: tuple[float, ElementSignature] | None = None
    for candidate in candidates:
        score = similarity(target, candidate)
        if best is None or score > best[0]:
            best = (score, candidate)
    if best is None or best[0] < threshold:
        return None
    score, matched = best
    reason = "unique high-confidence match" if score >= 0.85 else "best available match above threshold"
    return Recovery(
        matched=matched,
        confidence=score,
        selector_patch=selector_patch(matched),
        original=target,
        reason=reason,
    )


@dataclass
class HealingEvent:
    selector: str
    confidence: float
    patch: str
    success: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "selector": self.selector,
            "confidence": round(self.confidence, 3),
            "patch": self.patch,
            "success": self.success,
        }


@dataclass
class SelfHealingResolver:
    """Stateful resolver that remembers every recovery attempt for reporting."""

    threshold: float = 0.55
    history: list[HealingEvent] = field(default_factory=list)

    def resolve(
        self,
        selector: str,
        candidates: Iterable[ElementSignature | Mapping[str, Any]],
        *,
        target: ElementSignature | None = None,
    ) -> Recovery | None:
        normalized = [
            item if isinstance(item, ElementSignature) else ElementSignature.from_mapping(item)
            for item in candidates
        ]
        expected = target or _signature_from_selector(selector)
        recovery = recover_selector(expected, normalized, threshold=self.threshold)
        self.history.append(
            HealingEvent(
                selector=selector,
                confidence=0.0 if recovery is None else recovery.confidence,
                patch="" if recovery is None else recovery.selector_patch,
                success=recovery is not None,
            )
        )
        return recovery

    @property
    def recovery_rate(self) -> float:
        if not self.history:
            return 0.0
        return sum(1 for event in self.history if event.success) / len(self.history)

    def to_dict(self) -> dict[str, Any]:
        return {
            "threshold": self.threshold,
            "recovery_rate": round(self.recovery_rate, 3),
            "events": [event.to_dict() for event in self.history],
        }


def _signature_from_selector(selector: str) -> ElementSignature:
    """Best-effort signature for a legacy selector string."""
    text = str(selector or "").strip()
    testid = ""
    match = re.search(r"data-testid=['\"]?([\w-]+)", text)
    if match:
        testid = match.group(1)
    role = ""
    match = re.search(r"get_by_role\(\s*['\"]([\w-]+)['\"]", text)
    if match:
        role = match.group(1)
    name = ""
    match = re.search(r"\[name=['\"]?([\w-]+)", text)
    if match:
        name = match.group(1)
    tag = ""
    match = re.match(r"^([a-z][a-z0-9-]*)", text)
    if match:
        tag = match.group(1)
    button_text = ""
    match = re.search(r"text=['\"]?([^'\"\]]+)", text)
    if match:
        button_text = match.group(1)
    return ElementSignature(tag=tag, role=role, text=button_text, testid=testid, name=name, selector=text)
