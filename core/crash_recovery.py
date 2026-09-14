# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Crash Recovery.

Handles:
  * worker crash
  * browser crash
  * subprocess crash
  * timeout
  * cancellation
  * KeyboardInterrupt / SIGINT
  * artifact corruption (manifest/evidence unreadable)

INVARIANT: an interrupted run must NEVER look like a successful run. The
manifest is finalized with interrupted=True and an explicit interrupt_reason
before the process exits via any recovery path.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class InterruptKind(str, Enum):
    WORKER_CRASH = "worker_crash"
    BROWSER_CRASH = "browser_crash"
    SUBPROCESS_CRASH = "subprocess_crash"
    TIMEOUT = "timeout"
    CANCELLATION = "cancellation"
    KEYBOARD_INTERRUPT = "keyboard_interrupt"
    ARTIFACT_CORRUPTION = "artifact_corruption"
    UNKNOWN = "unknown"


@dataclass
class RecoveryResult:
    kind: InterruptKind
    detail: str
    manifest_finalized: bool = False
    manifest_path: str | None = None
    findings_committed: int = 0


class CrashRecoveryManager:
    """Central interrupt handling for the orchestrator loop."""

    def __init__(self, *, logger: Any = None) -> None:
        self._logger = logger

    def _log(self, msg: str, **kw: Any) -> None:
        if self._logger is not None:
            try:
                self._logger.warning(msg, **kw)
            except Exception:
                pass

    # ------------------------------------------------------------------
    def classify_exception(self, exc: BaseException) -> InterruptKind:
        name = type(exc).__name__.lower()
        text = str(exc).lower()
        if isinstance(exc, KeyboardInterrupt):
            return InterruptKind.KEYBOARD_INTERRUPT
        if "timeout" in name or "timeout" in text:
            return InterruptKind.TIMEOUT
        if "target closed" in text or "browser" in text and "closed" in text:
            return InterruptKind.BROWSER_CRASH
        if "subprocess" in text or "process" in name:
            return InterruptKind.SUBPROCESS_CRASH
        if "worker" in text or "worker" in name:
            return InterruptKind.WORKER_CRASH
        if "cancel" in text or "cancel" in name:
            return InterruptKind.CANCELLATION
        return InterruptKind.UNKNOWN

    # ------------------------------------------------------------------
    def finalize_interrupted(
        self,
        *,
        run_id: str,
        output_dir: Path,
        kind: InterruptKind,
        detail: str,
        manifest_payload: dict[str, Any] | None = None,
        findings_count: int = 0,
    ) -> RecoveryResult:
        """Write a manifest that explicitly records the interrupt.

        Uses atomic write so a crash during finalize cannot corrupt the
        previous manifest either.
        """
        from core.atomic_write import atomic_write_json

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        payload = dict(manifest_payload or {})
        payload.update(
            {
                "run_id": run_id,
                "interrupted": True,
                "interrupt_reason": f"{kind.value}: {detail}"[:400],
                "status": "INTERRUPTED",
            }
        )
        # Never mark quality_gate as a pass on an interrupted run.
        gate = payload.get("quality_gate")
        if isinstance(gate, dict):
            gate["status"] = "BLOCKED"
            gate["passed"] = False
            gate["reasons"] = sorted({*(gate.get("reasons") or []), "run was interrupted before completion"})
        else:
            payload["quality_gate"] = {
                "status": "BLOCKED",
                "passed": False,
                "reasons": ["run was interrupted before completion"],
            }
        path = atomic_write_json(output_dir / "run_manifest.json", payload)
        self._log(
            "run interrupted — manifest finalized with interrupted=true",
            kind=kind.value,
            detail=detail[:120],
        )
        return RecoveryResult(
            kind=kind,
            detail=detail,
            manifest_finalized=True,
            manifest_path=str(path),
            findings_committed=findings_count,
        )

    # ------------------------------------------------------------------
    def validate_manifest(self, path: Path) -> tuple[bool, str]:
        """Return (is_valid, detail). A manifest is valid iff it parses as
        JSON and either declares interrupted=true or has a non-BLOCKED gate."""
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception as exc:
            return False, f"unreadable manifest: {exc}"
        if not isinstance(data, dict):
            return False, "manifest is not a JSON object"
        if data.get("interrupted") is True:
            return True, "interrupted run (explicitly recorded)"
        gate = data.get("quality_gate")
        if isinstance(gate, dict) and gate.get("passed") is False and gate.get("status") == "BLOCKED":
            return True, "blocked run (explicitly recorded)"
        if "run_id" not in data:
            return False, "manifest missing run_id"
        return True, "complete run"

    # ------------------------------------------------------------------
    def run_protected(self, callable_fn: Any, *, run_id: str, output_dir: Path, manifest_payload: dict[str, Any] | None = None) -> RecoveryResult:
        """Execute callable_fn, finalizing an interrupted manifest on any
        exception (including KeyboardInterrupt). Re-raises after recording.
        """
        try:
            callable_fn()
            return RecoveryResult(kind=InterruptKind.UNKNOWN, detail="completed", manifest_finalized=False)
        except BaseException as exc:  # noqa: BLE001 — deliberate: KeyboardInterrupt must be caught
            kind = self.classify_exception(exc)
            result = self.finalize_interrupted(
                run_id=run_id,
                output_dir=output_dir,
                kind=kind,
                detail=str(exc)[:400],
                manifest_payload=manifest_payload,
            )
            raise


__all__ = [
    "CrashRecoveryManager",
    "InterruptKind",
    "RecoveryResult",
]
