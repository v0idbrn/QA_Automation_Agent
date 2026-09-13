import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from core.analyzer import FailureAnalyzer, FailureType
from core.evidence import EvidenceManager, EvidenceEntry, RunManifest
from core.models import Finding, FindingCategory, Severity


class TestFailureAnalyzer:
    def test_classifies_timeout(self):
        analyzer = FailureAnalyzer()
        finding = Finding(
            id="t1",
            category=FindingCategory.TIMEOUT,
            severity=Severity.HIGH,
            title="Request timed out",
            description="connection timed out after 20s",
            evidence="timeout",
        )
        result = analyzer.classify(finding)
        assert result.failure_type == FailureType.TIMEOUT

    def test_classifies_network_failure(self):
        analyzer = FailureAnalyzer()
        finding = Finding(
            id="n1",
            category=FindingCategory.NETWORK,
            severity=Severity.HIGH,
            title="Connection refused",
            description="Could not connect",
            evidence="connection refused",
        )
        result = analyzer.classify(finding)
        assert result.failure_type == FailureType.NETWORK_FAILURE

    def test_classifies_unknown_when_low_confidence(self):
        analyzer = FailureAnalyzer()
        finding = Finding(
            id="u1",
            category=FindingCategory.UNKNOWN,
            severity=Severity.MEDIUM,
            title="Something happened",
            description="unknown",
            confidence=0.2,
        )
        result = analyzer.classify(finding)
        assert result.failure_type == FailureType.UNKNOWN

    def test_classification_always_has_evidence_summary(self):
        analyzer = FailureAnalyzer()
        finding = Finding(
            id="x1",
            category=FindingCategory.TEST,
            severity=Severity.MEDIUM,
            title="Test failure",
            description="assertion error",
        )
        result = analyzer.classify(finding)
        assert result.evidence_summary


class TestRunManifest:
    def test_safe_dict_does_not_leak_secrets(self):
        manifest = RunManifest(
            run_id="run-1",
            started_at=datetime.now(timezone.utc),
            target="https://example.test",
            configuration={"api_key": "SECRET"},
            environment={"token": "TOKEN"},
        )
        safe = manifest.to_safe_dict()
        config_text = json.dumps(safe["configuration"])
        env_text = json.dumps(safe["environment"])
        assert "SECRET" not in config_text
        assert "TOKEN" not in env_text

    def test_manifest_save_writes_json(self, tmp_path: Path):
        manifest = RunManifest(
            run_id="run-2",
            started_at=datetime.now(timezone.utc),
            target=".",
        )
        path = manifest.save(tmp_path / "manifest.json")
        assert path.exists()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["run_id"] == "run-2"


class TestEvidenceManager:
    def test_temporary_directory_created(self, tmp_path: Path):
        evidence = EvidenceManager(temporary_dir=tmp_path / "tmp", final_dir=tmp_path / "final")
        tmp = evidence.temporary_directory()
        assert tmp.exists()

    def test_store_temporary_creates_file(self, tmp_path: Path):
        evidence = EvidenceManager(temporary_dir=tmp_path / "tmp", final_dir=tmp_path / "final")
        path = evidence.store_temporary("screenshot", b"fake", "captured failure")
        assert Path(path).exists()
        assert path.endswith(".png")

    def test_promote_to_final_moves_file(self, tmp_path: Path):
        evidence = EvidenceManager(temporary_dir=tmp_path / "tmp", final_dir=tmp_path / "final")
        src = evidence.store_temporary("screenshot", b"fake", "captured failure")
        entry = evidence.list_entries()[0]
        dest = evidence.promote_to_final(entry)
        assert not Path(src).exists()
        assert Path(dest).exists()
        assert dest.endswith(".png")

    def test_finalize_writes_evidence_json(self, tmp_path: Path):
        evidence = EvidenceManager(temporary_dir=tmp_path / "tmp", final_dir=tmp_path / "final")
        evidence.store_temporary("screenshot", b"fake", "captured failure")
        manifest = RunManifest(run_id="run-3", started_at=datetime.now(timezone.utc), target=".")
        evidence.manifest = manifest
        finding = Finding(
            id="f1",
            category=FindingCategory.HTTP,
            severity=Severity.HIGH,
            title="HTTP error",
            description="500",
        )
        report = evidence.finalize([finding], tmp_path / "report", redaction=None)
        assert (tmp_path / "report" / "run_evidence.json").exists()
        data = json.loads((tmp_path / "report" / "run_evidence.json").read_text(encoding="utf-8"))
        assert data["findings"]
        assert data["evidence_summary"]
