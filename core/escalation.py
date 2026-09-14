# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Human Escalation Registry.

Records every escalation with the four mandatory explanations:

    WHY                          — what triggered the escalation
    WHAT WAS ATTEMPTED           — actions the agent already tried
    WHAT EVIDENCE EXISTS         — pointers to evidence artifacts / summaries
    WHAT HUMAN INPUT IS REQUIRED — the concrete decision or credential needed

Escalations with halt=True stop the autonomous loop immediately.
The registry is idempotent: escalating the same reason twice returns the
same EscalationRecord.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any


@dataclass
class EscalationRecord:
    why: str
    what_was_attempted: str
    what_evidence_exists: str
    what_human_input_is_required: str
    halt: bool = True
    escalation_id: str = ""
    context: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.escalation_id:
            raw = f"esc|{self.why}|{self.what_human_input_is_required}"
            self.escalation_id = f"esc_{hashlib.sha1(raw.encode('utf-8')).hexdigest()[:12]}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "escalation_id": self.escalation_id,
            "why": self.why,
            "what_was_attempted": self.what_was_attempted,
            "what_evidence_exists": self.what_evidence_exists,
            "what_human_input_is_required": self.what_human_input_is_required,
            "halt": self.halt,
            "context": self.context,
        }


class HumanEscalationRegistry:
    """Bounded registry of human escalations. Deduplicates by reason."""

    def __init__(self, *, max_records: int = 64) -> None:
        if max_records < 1:
            raise ValueError("max_records must be >= 1")
        self.max_records = max_records
        self._records: list[EscalationRecord] = []
        self._by_reason: dict[str, EscalationRecord] = {}

    def escalate(
        self,
        why: str,
        *,
        what_was_attempted: str = "Autonomous pipeline attempted discover/plan/execute paths within scope.",
        what_evidence_exists: str = "Evidence registry and run manifest initialized; see run_evidence.json.",
        what_human_input_is_required: str = "Human must confirm scope, credentials, or permission.",
        halt: bool = True,
        context: dict[str, Any] | None = None,
    ) -> tuple[EscalationRecord, bool]:
        """Record an escalation. Returns (record, newly_created)."""
        key = " ".join(why.split()).strip().lower()
        existing = self._by_reason.get(key)
        if existing is not None:
            return existing, False
        if len(self._records) >= self.max_records:
            halt_record = EscalationRecord(
                why="escalation registry full",
                what_was_attempted="too many distinct escalation reasons",
                what_evidence_exists="see earlier escalation records",
                what_human_input_is_required="human review of agent configuration",
            )
            return halt_record, True
        record = EscalationRecord(
            why=why,
            what_was_attempted=what_was_attempted,
            what_evidence_exists=what_evidence_exists,
            what_human_input_is_required=what_human_input_is_required,
            halt=halt,
            context=context or {},
        )
        self._records.append(record)
        self._by_reason[key] = record
        return record, True

    def records(self) -> list[EscalationRecord]:
        return list(self._records)

    def has_halt(self) -> bool:
        return any(r.halt for r in self._records)

    def summary(self) -> list[dict[str, Any]]:
        return [r.as_dict() for r in self._records]

    def __len__(self) -> int:
        return len(self._records)


__all__ = ["EscalationRecord", "HumanEscalationRegistry"]
