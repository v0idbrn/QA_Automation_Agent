# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Evidence manager and run manifest for reproducible QA runs.

Temporary evidence stays in a dedicated directory and is kept separate from
final report evidence until a run is explicitly finalized.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.models import Finding


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

    def to_safe_dict(self, redaction: "RedactionPolicy | None" = None) -> dict[str, Any]:
        from core.security import redact_sensitive_data

        data: dict[str, Any] = {
            "run_id": self.run_id,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "target": self.target,
            "configuration": redact_sensitive_data(self.configuration) if redaction else self.configuration,
            "test_count": self.test_count,
            "passed": self.passed,
            "failed": self.failed,
            "skipped": self.skipped,
            "blocked": self.blocked,
            "errors": self.errors,
            "limits": self.limits,
            "environment": redact_sensitive_data(self.environment) if redaction else self.environment,
            "version": self.version,
            "notes": self.notes,
        }
        if redaction:
            data["configuration"] = redaction.redact(json.dumps(data["configuration"], default=str))
            data["environment"] = redaction.redact(json.dumps(data["environment"], default=str))
        return data

    def save(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_safe_dict(), indent=2, default=str), encoding="utf-8")
        return path


@dataclass
class EvidenceEntry:
    kind: str
    path: str
    description: str
    sensitive: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


class EvidenceManager:
    def __init__(self, temporary_dir: Path, final_dir: Path, manifest: RunManifest | None = None):
        self.temporary_dir = temporary_dir.resolve()
        self.final_dir = final_dir.resolve()
        self.manifest = manifest
        self._entries: list[EvidenceEntry] = []

    def temporary_directory(self) -> Path:
        self.temporary_dir.mkdir(parents=True, exist_ok=True)
        return self.temporary_dir

    def final_directory(self) -> Path:
        self.final_dir.mkdir(parents=True, exist_ok=True)
        return self.final_dir

    def store_temporary(self, kind: str, content: bytes, description: str, extension: str = "png") -> str:
        name = f"{uuid.uuid4().hex}.{extension}"
        path = self.temporary_dir / name
        path.write_bytes(content)
        entry = EvidenceEntry(kind=kind, path=str(path), description=description)
        self._entries.append(entry)
        return str(path)

    def promote_to_final(self, entry: EvidenceEntry, destination_name: str | None = None) -> str:
        dest_dir = self.final_directory()
        dest_name = destination_name or f"{uuid.uuid4().hex}_{Path(entry.path).name}"
        dest = dest_dir / dest_name
        src = Path(entry.path)
        if src.exists():
            src.replace(dest)
        entry.path = str(dest)
        entry.metadata["promoted"] = datetime.now(timezone.utc).isoformat()
        return str(dest)

    def list_entries(self) -> list[EvidenceEntry]:
        return list(self._entries)

    def snapshot_evidence_summary(self) -> dict[str, Any]:
        summary: dict[str, Any] = {
            "temporary": [],
            "final": [],
        }
        for entry in self._entries:
            summary["temporary" if Path(entry.path).exists() and str(self.temporary_dir) in entry.path else "final"].append(
                {
                    "kind": entry.kind,
                    "path": entry.path,
                    "description": entry.description,
                    "sensitive": entry.sensitive,
                }
            )
        return summary

    def finalize(
        self,
        findings: list[Finding],
        output_dir: Path,
        redaction: "RedactionPolicy | None" = None,
    ) -> dict[str, Any]:
        from core.security import redact_sensitive_data

        output_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = output_dir / "run_manifest.json"
        if self.manifest:
            self.manifest.finished_at = datetime.now(timezone.utc)
            self.manifest.save(manifest_path)

        evidence_summary = self.snapshot_evidence_summary()
        if redaction:
            evidence_summary = redaction.redact(evidence_summary)

        report_evidence: dict[str, Any] = {
            "run_id": self.manifest.run_id if self.manifest else "",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "evidence_summary": evidence_summary,
            "findings": [f.model_dump_safe(redaction) for f in findings],
        }
        report_path = output_dir / "run_evidence.json"
        report_path.write_text(json.dumps(report_evidence, indent=2, default=str), encoding="utf-8")
        return report_evidence
