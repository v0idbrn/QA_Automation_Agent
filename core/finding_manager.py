# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Finding Manager — deduplication + confidence scoring + status transitions.

Finding fingerprint (6-field canonical hash):
  category, location_normalized, title_normalized, error_signature,
  route/endpoint, stack_signature

Duplicates are NOT discarded: the first seen finding is kept and subsequent
ones populate the `duplicate_of` field pointing to the primary finding_id,
and an `occurrences` counter on the primary is incremented for reporting.

Confidence scoring (LOW/MEDIUM/HIGH) is computed from:
  * reproducibility
  * evidence quality
  * deterministic behavior (no flaky indicator)
  * source skill reliability
  * failure classification type (never UNKNOWN => never HIGH)
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from core.models import Finding, FindingStatus, ConfidenceLevel, FindingSeverity


# ---------------------------------------------------------------------------
# Fingerprint
# ---------------------------------------------------------------------------

_WS = re.compile(r"\s+")
_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def _norm(text: str) -> str:
    if not text:
        return ""
    lowered = text.lower()
    lowered = _WS.sub(" ", lowered).strip()
    lowered = _NON_ALNUM.sub("_", lowered)
    return lowered.strip("_")


def _route_from_location(location: str) -> str:
    if not location:
        return ""
    for token in location.split():
        if token.startswith("http://") or token.startswith("https://"):
            from urllib.parse import urlparse
            try:
                p = urlparse(token)
                return p.path or ""
            except Exception:
                continue
        if token.startswith("/"):
            return token
    return ""


def compute_fingerprint(finding: Finding) -> str:
    """6-field fingerprint for finding deduplication."""
    try:
        category = finding.category.value
    except Exception:
        category = str(finding.category)
    loc_norm = _norm(finding.location or "")
    title_norm = _norm(finding.title or "")
    error_sig = _norm(str(getattr(finding, "error_signature", "") or finding.description or "")[:200])
    route = _norm(_route_from_location(finding.location or ""))
    stack_sig = _norm(str(getattr(finding, "stack_signature", "") or "")[:200])
    joined = "|".join((category, loc_norm, title_norm, error_sig, route, stack_sig))
    return hashlib.sha1(joined.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Confidence scorer
# ---------------------------------------------------------------------------

_SKILL_RELIABILITY: dict[str, float] = {
    "api": 0.9,
    "crawler": 0.8,
    "form_tester": 0.65,
    "a11y": 0.6,
    "scope": 0.95,
    "evidence": 0.9,
    "discovery": 0.85,
    "orchestrator": 0.95,
    "report_builder": 0.95,
    "executor": 0.9,
    "analyzer": 0.85,
}


def score_confidence(
    finding: Finding,
    *,
    reproducibility: float = 0.5,
    evidence_quality: float = 0.5,
    deterministic: bool = True,
    failure_type: str | None = None,
) -> ConfidenceLevel:
    """Combine 5 axes into LOW/MEDIUM/HIGH confidence."""
    reliability = _SKILL_RELIABILITY.get(str(getattr(finding, "source_skill", "") or getattr(finding, "source", "")), 0.6)
    ft_penalty = 0.0
    if failure_type:
        ft = str(failure_type).upper()
        if ft in {"UNKNOWN", "TEST_BUG", "DEPENDENCY_FAILURE"}:
            ft_penalty = 0.2
        if ft == "PRODUCT_BUG":
            ft_penalty = 0.0
    weight = (
        reproducibility * 0.30
        + evidence_quality * 0.25
        + (1.0 if deterministic else 0.3) * 0.20
        + reliability * 0.15
        + (1.0 - ft_penalty) * 0.10
    )
    if weight >= 0.75:
        return ConfidenceLevel.HIGH
    if weight >= 0.45:
        return ConfidenceLevel.MEDIUM
    return ConfidenceLevel.LOW


# ---------------------------------------------------------------------------
# Finding Manager
# ---------------------------------------------------------------------------

@dataclass
class DeduplicationSummary:
    total_input: int
    unique_output: int
    duplicates_removed: int
    primary_with_dupes: int
    duplicate_pairs: dict[str, list[str]] = field(default_factory=dict)


class FindingManager:
    """Unified finding lifecycle: dedup, confidence, transitions, status reset."""

    def __init__(self) -> None:
        self._fingerprints: dict[str, Finding] = {}
        self._primary_ids: dict[str, str] = {}  # fp -> primary finding_id
        self._occurrences: dict[str, int] = {}  # finding_id -> total occurrences
        self._findings: list[Finding] = []

    # ------------------------------------------------------------------
    def add(self, finding: Finding) -> tuple[Finding, bool]:
        """Add a finding. Returns (canonical finding, was_duplicate_bool)."""
        fp = compute_fingerprint(finding)
        if fp in self._fingerprints:
            primary = self._fingerprints[fp]
            self._occurrences[primary.finding_id] = self._occurrences.get(primary.finding_id, 1) + 1
            if finding.description and finding.description not in (primary.reproduction or ""):
                primary.reproduction = (primary.reproduction or "") + "\n" + f"[dup] {finding.location or ''}: {finding.description[:200]}"
            primary.duplicate_of = None  # primary never points at itself
            finding.duplicate_of = primary.finding_id
            return primary, True
        self._fingerprints[fp] = finding
        self._primary_ids[fp] = finding.finding_id
        self._occurrences[finding.finding_id] = 1
        self._findings.append(finding)
        return finding, False

    def extend(self, findings: Iterable[Finding]) -> DeduplicationSummary:
        dupes_removed = 0
        pairs: dict[str, list[str]] = {}
        for f in findings:
            canonical, is_dup = self.add(f)
            if is_dup:
                dupes_removed += 1
                pairs.setdefault(canonical.finding_id, []).append(f.finding_id)
        primary_with_dupes = sum(1 for f in self._findings if self._occurrences.get(f.finding_id, 1) > 1)
        return DeduplicationSummary(
            total_input=len(self._findings) + dupes_removed,
            unique_output=len(self._findings),
            duplicates_removed=dupes_removed,
            primary_with_dupes=primary_with_dupes,
            duplicate_pairs=pairs,
        )

    def findings(self) -> list[Finding]:
        out = []
        for f in self._findings:
            occ = self._occurrences.get(f.finding_id, 1)
            if occ > 1:
                f.metadata = {**(f.metadata or {}), "occurrences": occ}
            out.append(f)
        return out

    def occurrences(self, finding_id: str) -> int:
        return self._occurrences.get(finding_id, 1)

    def by_severity(self) -> dict[str, int]:
        out: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self._findings:
            try:
                val = f.severity.value.upper()
            except Exception:
                val = str(f.severity).upper()
            out[val] = out.get(val, 0) + 1
        return out

    def by_status(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self._findings:
            try:
                val = f.status.value.upper()
            except Exception:
                val = str(f.status).upper()
            out[val] = out.get(val, 0) + 1
        return out

    # ------------------------------------------------------------------
    def transition_status(self, finding_id: str, new_status: FindingStatus, *, reason: str = "") -> bool:
        for f in self._findings:
            if f.finding_id == finding_id:
                old = f.status
                f.status = new_status
                if reason:
                    f.metadata = {**(f.metadata or {}), "status_reason": reason, "previous_status": str(old)}
                return True
        return False
