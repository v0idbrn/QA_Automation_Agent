from datetime import datetime, timezone
from pathlib import Path

from core.actions import Action, Result
from core.discovery import DiscoveredProject, ProjectProfile, discover_project
from core.failure_analyzer import FailureAnalyzer, FailureType
from core.manifest import RunManifest
from core.models import Finding, FindingCategory, FindingStatus, Severity
from core.orchestrator import AgentState, Orchestrator, RunContext
from core.quality_gate import QualityGate
from core.scope import Budget, Scope
from core.skills_registry import SkillRegistry
from core.spec_analyzer import SpecConfidence, analyze_specs
from core.strategist import QAStrategist
from core.evidence import EvidenceManager


class TestSpecAnalyzer:
    def test_readme_is_observed(self, tmp_path: Path):
        (tmp_path / "README.md").write_text("# App\nRun pytest locally.\n", encoding="utf-8")
        analysis = analyze_specs(tmp_path)
        confidences = {item.confidence for item in analysis.statements}
        assert SpecConfidence.OBSERVED in confidences

    def test_missing_specs_are_unknown(self, tmp_path: Path):
        analysis = analyze_specs(tmp_path / "missing")
        assert analysis.statements
        assert analysis.statements[0].confidence == SpecConfidence.UNKNOWN


class TestStrategist:
    def test_skips_irrelevant_api_skill_on_empty_ui_profile(self):
        profile = DiscoveredProject(root=Path("/tmp"), language="python")
        strategy = QAStrategist().select(profile, risk_level="low")
        assert "scope" in strategy.selected_skills
        assert "api" in strategy.skipped_skills

    def test_selects_api_when_endpoints_observed(self):
        profile = ProjectProfile(root=Path("/tmp"), language="python", api_endpoints=["/api/health"])
        strategy = QAStrategist().select(profile, risk_level="low")
        assert "api" in strategy.selected_skills


class TestSkillRegistryAndActions:
    def test_registry_exposes_core_engines(self):
        registry = SkillRegistry()
        for name in ("crawler", "form_tester", "a11y", "api"):
            assert registry.get(name) is not None

    def test_action_result_contract(self):
        action = Action(name="scope:Safety", skill="scope", idempotent=True)
        result = Result(ok=True, findings=[], retryable=False)
        assert action.skill == "scope"
        assert result.ok is True


class TestFailureAnalyzerEnterprise:
    def test_maps_timeout_and_caps_retries(self):
        analyzer = FailureAnalyzer()
        finding = Finding(
            id="t1",
            category=FindingCategory.TIMEOUT,
            severity=Severity.HIGH,
            title="Request timed out",
            description="connection timed out after 20s",
            evidence="timeout",
        )
        classification = analyzer.classify(finding)
        assert classification.failure_type == FailureType.TIMEOUT
        action = Action(name="retry", skill="crawler", idempotent=True)
        assert analyzer.should_retry(classification, action) is True
        assert analyzer.should_retry(classification, action) is True
        assert analyzer.should_retry(classification, action) is True
        assert analyzer.should_retry(classification, action) is False


class TestQualityGate:
    def test_fails_when_no_findings(self):
        gate = QualityGate().evaluate([])
        assert gate.passed is False
        assert "no findings produced" in gate.reasons

    def test_passes_with_evidence_backed_run(self):
        findings = [
            Finding(
                id="ok",
                category=FindingCategory.FUNCTIONAL,
                severity=Severity.INFO,
                title="ok",
                description="ok",
                evidence="log",
                status=FindingStatus.PASSED,
            )
        ]
        gate = QualityGate().evaluate(findings)
        assert gate.passed is True


class TestManifestReexport:
    def test_manifest_module_exports_run_manifest(self):
        manifest = RunManifest(run_id="x", started_at=datetime.now(timezone.utc), target=".")
        assert manifest.run_id == "x"


class TestOrchestratorLoop:
    def test_runs_decision_loop_and_writes_reports(self, tmp_path: Path):
        output = tmp_path / "out"
        scope = Scope(allowed_origin="https://example.test", max_pages=5, max_requests=10)
        budget = Budget(scope=scope)
        budget.start()
        ctx = RunContext(
            target=str(Path(__file__).resolve().parent.parent),
            output_dir=output,
            budget=budget,
            evidence=EvidenceManager(temporary_dir=output / "tmp", final_dir=output / "final"),
            risk_level="low",
        )
        result = Orchestrator().run(ctx)
        assert AgentState.DISCOVER.value in result.history
        assert AgentState.PLAN.value in result.history
        assert AgentState.EXECUTE.value in result.history
        assert AgentState.REPORT.value in result.history
        assert AgentState.DONE.value in result.history
        assert result.findings
        assert (output / "audit_report.md").exists()
        assert (output / "audit_report.json").exists()


class TestCliParser:
    def test_run_subcommand_exists(self):
        from main import build_parser

        parser = build_parser()
        args = parser.parse_args(["run", ".", "--risk-level", "low", "--browser", "chromium"])
        assert args.command == "run"
        assert args.target == "."
        assert args.risk_level == "low"
        assert args.browser == "chromium"
