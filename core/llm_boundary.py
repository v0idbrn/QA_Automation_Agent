# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
LLM Boundary — PROPOSE -> VALIDATE -> AUTHORIZE.

An LLM integration (present or future) may ONLY *propose* actions. Proposals
are inert data. They can never execute shell, filesystem, browser, network,
or destructive operations directly. Each proposal passes a validator gate
before an authorized Action is constructed by the orchestrator's executor.

Rejected proposals are recorded with a reason and never silently dropped.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ProposalKind(str, Enum):
    TEST_CASE = "test_case"
    PLAN_ITEM = "plan_item"
    FINDING_ANNOTATION = "finding_annotation"
    REPORT_NOTE = "report_note"


class ProposalVerdict(str, Enum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"


_FORBIDDEN_KEYS = {
    "shell",
    "command",
    "cmd",
    "exec",
    "eval",
    "subprocess",
    "os.system",
    "delete",
    "drop",
    "rm -rf",
    "truncate",
    "format",
}

_MAX_PROPOSAL_BYTES = 64 * 1024


@dataclass
class LLMProposal:
    """An inert suggestion. Has NO executable semantics by construction."""

    kind: ProposalKind
    content: dict[str, Any]
    rationale: str = ""
    proposed_by: str = "llm"
    proposal_id: str = ""

    def __post_init__(self) -> None:
        if not self.proposal_id:
            import hashlib
            import json

            raw = json.dumps(
                {"k": self.kind.value, "c": self.content, "r": self.rationale},
                sort_keys=True,
                default=str,
            )
            self.proposal_id = (
                "prop_" + hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]
            )


@dataclass
class ProposalDecision:
    verdict: ProposalVerdict
    reason: str
    proposal_id: str


class LLMBoundary:
    """Validates LLM proposals. Enforces the PROPOSE-only contract."""

    def __init__(self, *, max_proposals: int = 256) -> None:
        if max_proposals < 1:
            raise ValueError("max_proposals must be >= 1")
        self.max_proposals = max_proposals
        self._decisions: list[ProposalDecision] = []
        self._accepted: list[LLMProposal] = []

    def validate(self, proposal: LLMProposal) -> ProposalDecision:
        import json as _json

        if not isinstance(proposal.content, dict) or not proposal.content:
            decision = ProposalDecision(ProposalVerdict.REJECTED, "proposal content must be a non-empty dict", proposal.proposal_id)
            self._decisions.append(decision)
            return decision

        try:
            blob = _json.dumps(proposal.content, default=str)
        except (TypeError, ValueError):
            decision = ProposalDecision(ProposalVerdict.REJECTED, "proposal content is not JSON-serializable", proposal.proposal_id)
            self._decisions.append(decision)
            return decision

        if len(blob.encode("utf-8", errors="replace")) > _MAX_PROPOSAL_BYTES:
            decision = ProposalDecision(ProposalVerdict.REJECTED, "proposal exceeds size cap (64KB)", proposal.proposal_id)
            self._decisions.append(decision)
            return decision

        lowered = blob.lower()
        for token in _FORBIDDEN_KEYS:
            if token in lowered:
                decision = ProposalDecision(
                    ProposalVerdict.REJECTED,
                    f"proposal contains forbidden execution token {token!r}",
                    proposal.proposal_id,
                )
                self._decisions.append(decision)
                return decision

        if len(self._accepted) >= self.max_proposals:
            decision = ProposalDecision(ProposalVerdict.REJECTED, "proposal cap reached", proposal.proposal_id)
            self._decisions.append(decision)
            return decision

        decision = ProposalDecision(ProposalVerdict.ACCEPTED, "within boundary constraints", proposal.proposal_id)
        self._decisions.append(decision)
        self._accepted.append(proposal)
        return decision

    def submit(self, proposal: LLMProposal) -> ProposalDecision:
        """PROPOSE -> VALIDATE. Accepted proposals still require an
        orchestrator-authorized Action to ever execute anything."""
        return self.validate(proposal)

    def accepted(self) -> list[LLMProposal]:
        return list(self._accepted)

    def decisions(self) -> list[ProposalDecision]:
        return list(self._decisions)

    def summary(self) -> dict[str, int]:
        return {
            "proposals_seen": len(self._decisions),
            "accepted": len(self._accepted),
            "rejected": len(self._decisions) - len(self._accepted),
        }


__all__ = [
    "LLMBoundary",
    "LLMProposal",
    "ProposalDecision",
    "ProposalKind",
    "ProposalVerdict",
]
