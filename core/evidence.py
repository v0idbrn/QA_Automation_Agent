# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Evidence manager + Run manifest.

Extension points over the previous implementation:
  * Every EvidenceEntry now declares run_id, test_id, finding_id.
  * Atomic writes used for run_manifest.json and run_evidence.json.
  * Central redaction before any file write.
  * Promoted evidence list is returned from finalize() with paths.
"""

from __future__ import annotations

import hashlib
import json as _json
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.models import Finding
from core.redaction import scrub
from core.atomic_write import atomic_write, atomic_write_json


@dataclass
class RunManifest:
    run_id: str
    started_at: datetime
    finished_at: datetime | None = None
    target: str = ""
    configuration: dict[str, Any] = field(default_factory=dict)
    test_count: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    blocked: int = 0
    errors: int = 0
    limits: dict[str, Any] = field(default_factory=dict)
    environment: dict[str, Any] = field(default_factory=dict)
    version: str = "1.0.0"
    notes: list[str] = field(default_factory=list)
    # ---- Enterprise extension ----
    agent_version: str = "1.0.0"
    python_version: str = ""
    os_name: str = ""
    browser: str = ""
    project_fingerprint: str = ""
    scope: dict[str, Any] = field(default_factory=dict)
    budget: dict[str, Any] = field(default_factory=dict)
    tests_planned: int = 0
    tests_executed: int = 0
    findings: dict[str, Any] = field(default_factory=dict)
    artifacts: list[str] = field(default_factory=list)
    quality_gate: dict[str, Any] = field(default_factory=dict)
    escalations: list[dict[str, Any]] = field(default_factory=list)
    retries: int = 0
    flaky_count: int = 0

    def to_safe_dict(self, redaction: Any | None = None) -> dict[str, Any]:
        data: dict[str, Any] = {
            "run_id": self.run_id,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "target": self.target,
            "configuration": scrub(self.configuration),
            "environment": scrub(self.environment),
            "test_count": self.test_count,
            "passed": self.passed,
            "failed": self.failed,
            "skipped": self.skipped,
            "blocked": self.blocked,
            "errors": self.errors,
            "limits": self.limits,
            "version": self.version,
            "notes": list(self.notes),
            "agent_version": self.agent_version,
            "python_version": self.python_version,
            "os": self.os_name,
            "browser": self.browser,
            "project_fingerprint": self.project_fingerprint,
            "scope": self.scope,
            "budget": self.budget,
            "tests_planned": self.tests_planned,
            "tests_executed": self.tests_executed,
            "findings": scrub(self.findings),
            "artifacts": list(self.artifacts),
            "quality_gate": scrub(self.quality_gate),
            "escalations": scrub(self.escalations),
            "retries": self.retries,
            "flaky_count": self.flaky_count,
        }
        return data

    def save(self, path: str | Path) -> Path:
        return atomic_write_json(path, self.to_safe_dict())


@dataclass
class EvidenceEntry:
    kind: str
    path: str
    description: str
    sensitive: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)
    # ---- Traceability extension ----
    run_id: str | None = None
    test_id: str | None = None
    finding_id: str | None = None


class EvidenceManager:
    def __init__(
        self,
        temporary_dir: Path,
        final_dir: Path,
        manifest: RunManifest | None = None,
        *,
        run_id: str | None = None,
    ) -> None:
        self.temporary_dir = Path(temporary_dir).resolve()
        self.final_dir = Path(final_dir).resolve()
        self.manifest = manifest
        self._run_id = run_id
        self._entries: list[EvidenceEntry] = []

    # ------------------------------------------------------------------
    @property
    def run_id(self) -> str:
        if self._run_id:
            return self._run_id
        if self.manifest:
            return self.manifest.run_id
        return ""

    # ------------------------------------------------------------------
    def temporary_directory(self) -> Path:
        self.temporary_dir.mkdir(parents=True, exist_ok=True)
        return self.temporary_dir

    def final_directory(self) -> Path:
        self.final_dir.mkdir(parents=True, exist_ok=True)
        return self.final_dir

    # ------------------------------------------------------------------
    def store_temporary(
        self,
        kind: str,
        content: bytes,
        description: str,
        *,
        extension: str = "png",
        test_id: str | None = None,
        finding_id: str | None = None,
        sensitive: bool = False,
    ) -> str:
        if sensitive:
            # Binary redaction: for screenshots we can't scrub pixels; we just
            # mark them sensitive. For HTML/DOM snapshots, scrub text content.
            if kind in {"dom_snapshot", "html", "log"} and isinstance(content, (bytes, bytearray)):
                try:
                    decoded = content.decode("utf-8", errors="ignore")
                    cleaned = scrub(decoded)
                    content = cleaned.encode("utf-8")
                except Exception:
                    pass
        name = f"{uuid.uuid4().hex}.{extension.lstrip('.')}"
        path = self.temporary_directory() / name
        path.write_bytes(content)
        entry = EvidenceEntry(
            kind=kind,
            path=str(path),
            description=description,
            sensitive=sensitive,
            run_id=self.run_id or None,
            test_id=test_id,
            finding_id=finding_id,
        )
        self._entries.append(entry)
        return str(path)

    def promote_to_final(self, entry: EvidenceEntry, destination_name: str | None = None) -> str:
        dest_dir = self.final_directory()
        dest_name = destination_name or f"{uuid.uuid4().hex}_{Path(entry.path).name}"
        dest = dest_dir / dest_name
        src = Path(entry.path)
        if src.exists():
            try:
                os.replace(src, dest)
            except OSError:
                dest.write_bytes(src.read_bytes())
                try:
                    src.unlink()
                except OSError:
                    pass
        entry.path = str(dest)
        entry.metadata["promoted_at"] = datetime.now(timezone.utc).isoformat()
        return str(dest)

    def list_entries(self) -> list[EvidenceEntry]:
        return list(self._entries)

    def snapshot_evidence_summary(self) -> dict[str, Any]:
        summary: dict[str, Any] = {"temporary": [], "final": []}
        for entry in self._entries:
            target = "final"
            try:
                exists = Path(entry.path).exists()
            except OSError:
                exists = False
            if exists and str(self.temporary_dir) in entry.path:
                target = "temporary"
            summary[target].append(
                {
                    "kind": entry.kind,
                    "path": entry.path,
                    "description": entry.description,
                    "sensitive": entry.sensitive,
                    "run_id": entry.run_id,
                    "test_id": entry.test_id,
                    "finding_id": entry.finding_id,
                }
            )
        return summary

    # ------------------------------------------------------------------
    def finalize(
        self,
        findings: list[Finding],
        output_dir: Path,
        *,
        redaction: Any | None = None,
    ) -> dict[str, Any]:
        output_dir = Path(output_dir).resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = output_dir / "run_manifest.json"
        if self.manifest:
            self.manifest.finished_at = datetime.now(timezone.utc)
            self.manifest.save(manifest_path)

        evidence_summary = scrub(self.snapshot_evidence_summary())
        safe_findings = [scrub(f.model_dump_safe() if hasattr(f, "model_dump_safe") else _dict_of_finding(f)) for f in findings]

        report_evidence: dict[str, Any] = {
            "run_id": self.manifest.run_id if self.manifest else self.run_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "evidence_summary": evidence_summary,
            "findings": safe_findings,
        }
        report_path = output_dir / "run_evidence.json"
        atomic_write_json(report_path, report_evidence)
        return report_evidence


def _dict_of_finding(f: Finding) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name in ("finding_id", "category", "severity", "confidence", "title", "description", "location", "evidence", "reproduction", "expected", "actual", "source_skill", "source", "status", "recommendation", "timestamp"):
        if hasattr(f, name):
            out[name] = getattr(f, name)
    return out
