# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Bounded autonomous state machine.

States: DISCOVER ANALYZE PLAN EXECUTE ANALYZE_FAILURE RETRY CONTINUE
STOP ESCALATE REPORT (plus HALTED terminal).

Guarantees:
  * Explicit transition table — no implicit fallthrough.
  * Global step cap (max_steps): the machine can NEVER loop forever.
  * Retry hops are counted separately and bounded by max_retries_total.
  * No transition leaves the machine without a terminal state reachable
    within max_steps.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable


class State(str, Enum):
    DISCOVER = "DISCOVER"
    ANALYZE = "ANALYZE"
    PLAN = "PLAN"
    EXECUTE = "EXECUTE"
    ANALYZE_FAILURE = "ANALYZE_FAILURE"
    RETRY = "RETRY"
    CONTINUE = "CONTINUE"
    STOP = "STOP"
    ESCALATE = "ESCALATE"
    REPORT = "REPORT"
    HALTED = "HALTED"


# Default transition table. Callers may override any edge via
# `transition_overrides` but every state must keep at least one outgoing
# edge (checked in __init__) so the machine can always terminate.
_DEFAULT_TRANSITIONS: dict[State, tuple[State, ...]] = {
    State.DISCOVER: (State.ANALYZE,),
    State.ANALYZE: (State.PLAN, State.STOP),
    State.PLAN: (State.EXECUTE, State.STOP),
    State.EXECUTE: (State.ANALYZE_FAILURE,),
    State.ANALYZE_FAILURE: (State.RETRY, State.CONTINUE, State.ESCALATE),
    State.RETRY: (State.EXECUTE, State.CONTINUE),
    State.CONTINUE: (State.REPORT, State.EXECUTE),
    State.STOP: (State.REPORT,),
    State.ESCALATE: (State.REPORT,),
    State.REPORT: (State.HALTED,),
    State.HALTED: (),
}

TERMINAL_STATES = frozenset({State.HALTED})


@dataclass
class StateMachineRun:
    state: State = State.DISCOVER
    steps: int = 0
    retry_hops: int = 0
    escalations: int = 0
    history: list[str] = field(default_factory=list)
    stop_reason: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "final_state": self.state.value,
            "steps": self.steps,
            "retry_hops": self.retry_hops,
            "escalations": self.escalations,
            "stop_reason": self.stop_reason,
            "history": list(self.history),
        }


class StateMachineError(RuntimeError):
    """Raised when the machine is driven illegally (e.g. from a terminal state)."""


class AutonomousStateMachine:
    """Finite, bounded state machine. `step()` advances exactly one edge."""

    def __init__(
        self,
        *,
        max_steps: int = 64,
        max_retries_total: int = 9,
        transition_overrides: dict[State, tuple[State, ...]] | None = None,
    ) -> None:
        if max_steps < 1:
            raise ValueError("max_steps must be >= 1")
        if max_retries_total < 0:
            raise ValueError("max_retries_total must be >= 0")
        self.max_steps = max_steps
        self.max_retries_total = max_retries_total
        self._transitions: dict[State, tuple[State, ...]] = dict(_DEFAULT_TRANSITIONS)
        if transition_overrides:
            for src, dsts in transition_overrides.items():
                if not dsts:
                    raise ValueError(f"state {src} must keep at least one outgoing edge")
                self._transitions[src] = tuple(dsts)
        for src, dsts in self._transitions.items():
            if src not in TERMINAL_STATES and not dsts:
                raise ValueError(f"non-terminal state {src} has no outgoing edge")

    # ------------------------------------------------------------------
    def allowed_next(self, state: State) -> tuple[State, ...]:
        return self._transitions.get(state, ())

    def is_terminal(self, state: State) -> bool:
        return state in TERMINAL_STATES

    # ------------------------------------------------------------------
    def step(
        self,
        run: StateMachineRun,
        choose: Callable[[StateMachineRun], State] | None = None,
    ) -> StateMachineRun:
        """Advance one edge. Returns the same run for chaining.

        `choose` picks the next state among allowed successors. If omitted,
        the first allowed successor is taken (deterministic default).
        """
        if self.is_terminal(run.state):
            raise StateMachineError(f"cannot step from terminal state {run.state}")
        if run.steps >= self.max_steps:
            run.stop_reason = "global step cap reached"
            run.state = State.HALTED
            run.history.append(run.state.value)
            return run

        successors = self.allowed_next(run.state)
        if not successors:
            run.stop_reason = f"no outgoing transition from {run.state.value}"
            run.state = State.HALTED
            run.history.append(run.state.value)
            return run

        chosen = choose(run) if choose is not None else successors[0]
        if chosen not in successors:
            raise StateMachineError(
                f"illegal transition {run.state.value} -> {chosen.value}; allowed: {[s.value for s in successors]}"
            )
        if chosen is State.RETRY:
            run.retry_hops += 1
            if run.retry_hops > self.max_retries_total:
                run.stop_reason = "total retry cap reached"
                chosen = State.ESCALATE
                run.escalations += 1
        if chosen is State.ESCALATE:
            run.escalations += 1
        run.state = chosen
        run.steps += 1
        run.history.append(chosen.value)
        return run

    # ------------------------------------------------------------------
    def run_to_completion(
        self,
        run: StateMachineRun,
        decide: Callable[[StateMachineRun], State] | None = None,
    ) -> StateMachineRun:
        """Drive until HALTED or caps fire. `decide` re-chooses each step."""
        guard = 0
        while not self.is_terminal(run.state):
            guard += 1
            if guard > self.max_steps * 2:
                run.stop_reason = "internal driver guard tripped"
                run.state = State.HALTED
                run.history.append(run.state.value)
                break
            self.step(run, decide)
        return run


__all__ = [
    "AutonomousStateMachine",
    "State",
    "StateMachineError",
    "StateMachineRun",
    "TERMINAL_STATES",
]
