# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Local-first QA orchestration CLI.

Usage:
    qa-agent discover <target>
    qa-agent plan <target>
    qa-agent run <target>
    qa-agent report <run-dir>
    qa-agent validate <run-dir>

Common flags:
    --profile safe|standard|deep|ci   configuration profile (default standard)
    --risk / --risk-level low|medium|high
    --browser chromium|firefox|webkit
    --headed / --headless
    --output DIR                      report output directory
    --budget key=value,...            max_pages/max_requests/max_depth/max_tests/max_runtime
    --scope origin=URL|allow_external|allow_uploads
    --config FILE                     JSON file with extra config overrides
    --dry-run                         plan only, never execute
    --url URL                         explicit target origin for scope
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from core.config import AgentConfig, ValidationError, load_profile, validate_config
from core.crash_recovery import CrashRecoveryManager
from core.evidence import EvidenceManager
from core.orchestrator import Orchestrator, RunContext
from core.scope import Budget, Scope


def build_scope(cfg: AgentConfig) -> Scope:
    origin = cfg.url or (cfg.target if str(cfg.target).startswith("http") else "https://example.test")
    return Scope(
        allowed_origin=origin,
        allowed_paths=cfg.scope.allowed_paths or (),
        allow_external=cfg.allow_external or cfg.scope.allow_external,
        max_depth=cfg.budget.max_depth if cfg.budget.max_depth is not None else 2,
        max_pages=cfg.budget.max_pages if cfg.budget.max_pages is not None else 25,
        max_requests=cfg.budget.max_requests if cfg.budget.max_requests is not None else 100,
        max_runtime_seconds=cfg.budget.max_runtime_seconds if cfg.budget.max_runtime_seconds is not None else 300,
        per_request_timeout_seconds=cfg.budget.per_request_timeout_seconds or 20,
        concurrency_limit=cfg.budget.max_concurrency or 3,
        allow_uploads=cfg.scope.allow_uploads,
        # CLI runs authorize the user-supplied origin explicitly.
        default_allow_same_origin=True,
    )


def _parse_kv_pairs(raw: str | None) -> dict[str, object]:
    """Parse 'key=value,key=value' into a dict. Ints are coerced when possible."""
    out: dict[str, object] = {}
    if not raw:
        return out
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            raise ValidationError(f"invalid key=value pair {chunk!r} (expected key=value)")
        k, v = chunk.split("=", 1)
        k, v = k.strip(), v.strip()
        if not k:
            raise ValidationError("empty key in key=value list")
        try:
            out[k] = int(v)
        except ValueError:
            if v.lower() in ("true", "false"):
                out[k] = v.lower() == "true"
            else:
                out[k] = v
    return out


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="qa-agent", description="Local autonomous QA engineer")
    sub = parser.add_subparsers(dest="command", required=True)

    def _common(p: argparse.ArgumentParser, *, with_target: bool = True) -> None:
        if with_target:
            p.add_argument("target", help="Project directory or target URL")
        p.add_argument("--url", default=None, help="Explicit origin URL for scope")
        p.add_argument("--profile", default="standard", choices=["safe", "standard", "deep", "ci"])
        p.add_argument("--risk", "--risk-level", dest="risk_level", default=None, choices=["low", "medium", "high"])
        p.add_argument("--browser", default=None, help="chromium | firefox | webkit")
        headed = p.add_mutually_exclusive_group()
        headed.add_argument("--headed", action="store_true", default=False)
        headed.add_argument("--headless", action="store_true", default=False)
        p.add_argument("--output", default="reports", help="Report output directory")
        p.add_argument("--budget", default=None, help="Budget overrides: max_pages=10,max_requests=20,...")
        p.add_argument("--scope", default=None, help="Scope overrides: origin=https://host,allow_external=true")
        p.add_argument("--config", default=None, help="JSON file merged into extra config")
        p.add_argument("--dry-run", action="store_true", default=False, help="Plan only; never execute")
        p.add_argument("--allow-external", action="store_true", default=False)
        p.add_argument("--max-pages", type=int, default=None)
        p.add_argument("--max-requests", type=int, default=None)
        p.add_argument("--max-depth", type=int, default=None)
        p.add_argument("--timeout", type=int, default=None, help="Per-request timeout seconds")
        p.add_argument("--max-runtime", type=int, default=None, help="Total runtime budget seconds")
        p.add_argument(
            "--min-coverage",
            type=float,
            default=None,
            help=(
                "Requirement-coverage floor for the quality gate, 0.0-1.0 "
                "(default: per-profile policy; 0 disables the floor)"
            ),
        )

    d = sub.add_parser("discover", help="Read-only discovery; prints the ProjectProfile")
    _common(d)

    pl = sub.add_parser("plan", help="Discover + requirements + risks + plan (no execution)")
    _common(pl)

    r = sub.add_parser("run", help="Discover, plan, execute, and report")
    _common(r)

    rep = sub.add_parser("report", help="Print/refresh reports for a previous run directory")
    rep.add_argument("run", help="Run output directory containing run_manifest.json")

    v = sub.add_parser("validate", help="Validate a run directory (crash recovery + gate check)")
    v.add_argument("run", help="Run output directory containing run_manifest.json")

    return parser


def _load_config(args: argparse.Namespace) -> AgentConfig:
    cfg = load_profile(args.profile, args.target, url=args.url)
    if args.risk_level:
        cfg.risk_level = args.risk_level
    if args.browser:
        cfg.browser = args.browser
    if args.headed:
        cfg.headed = True
        cfg.headless = False
    if args.headless:
        cfg.headless = True
        cfg.headed = False
    if args.output:
        cfg.output_dir = args.output
    if args.allow_external:
        cfg.allow_external = True
        cfg.scope.allow_external = True
    if args.dry_run:
        cfg.dry_run = True
    # Backward-compatible single overrides
    if args.max_pages is not None:
        cfg.budget.max_pages = args.max_pages
        cfg.scope.max_pages = args.max_pages
    if args.max_requests is not None:
        cfg.budget.max_requests = args.max_requests
        cfg.scope.max_requests = args.max_requests
    if args.max_depth is not None:
        cfg.budget.max_depth = args.max_depth
        cfg.scope.max_depth = args.max_depth
    if args.timeout is not None:
        cfg.budget.per_request_timeout_seconds = args.timeout
    if args.max_runtime is not None:
        cfg.budget.max_runtime_seconds = args.max_runtime
    if getattr(args, "min_coverage", None) is not None:
        floor = float(args.min_coverage)
        if not (0.0 <= floor <= 1.0):
            raise ValidationError(f"--min-coverage must be within [0.0, 1.0] (got {floor})")
        cfg.gate_policy.min_requirements_coverage = floor
        cfg.gate_policy.floor_enabled = floor > 0.0
    # Composite overrides
    budget_overrides = _parse_kv_pairs(getattr(args, "budget", None))
    for k, v in budget_overrides.items():
        if not hasattr(cfg.budget, k):
            raise ValidationError(f"unknown budget key {k!r}")
        setattr(cfg.budget, k, v)
    scope_overrides = _parse_kv_pairs(getattr(args, "scope", None))
    for k, v in scope_overrides.items():
        if k == "origin":
            cfg.url = str(v)
        elif hasattr(cfg.scope, k):
            setattr(cfg.scope, k, v)
        else:
            raise ValidationError(f"unknown scope key {k!r}")
    if args.config:
        path = Path(args.config)
        if not path.exists():
            raise ValidationError(f"config file not found: {path}")
        try:
            extra = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValidationError(f"config file is not valid JSON: {exc}")
        if not isinstance(extra, dict):
            raise ValidationError("config file must contain a JSON object")
        cfg.extra.update(extra)
    return validate_config(cfg, destructive=bool(cfg.extra.get("destructive", False)))


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def _make_context(cfg: AgentConfig) -> RunContext:
    output_dir = Path(cfg.output_dir).resolve()
    scope = build_scope(cfg)
    budget = Budget(scope=scope, config=cfg.budget)
    budget.start()
    evidence = EvidenceManager(
        temporary_dir=output_dir / "tmp",
        final_dir=output_dir / "final",
    )
    return RunContext(
        target=cfg.url or cfg.target,
        output_dir=output_dir,
        budget=budget,
        evidence=evidence,
        risk_level=cfg.risk_level,
        browser=cfg.browser,
        gate_policy=cfg.gate_policy,
    )


def _bootstrap_pipeline(ctx: RunContext, orchestrator: Orchestrator) -> None:
    """Run DISCOVER/UNDERSTAND/PLAN/GENERATE without executing (dry-run/plan helpers)."""
    from core.discovery import discover_project
    from core.requirements_engine import build_requirements
    from core.risk_engine import assess_risks

    target_path = ctx.target if Path(ctx.target).exists() else "."
    ctx.profile = discover_project(target_path)
    ctx.spec = orchestrator.planner.understand(ctx)
    ctx.requirements = build_requirements(ctx.profile, spec=ctx.spec).requirements
    ctx.risk_assessment = assess_risks(ctx.requirements, ctx.profile)
    ctx.strategy, ctx.plan = orchestrator.planner.plan(ctx)
    from core.planner import generate_test_cases

    generation = generate_test_cases(ctx.plan, profile_auth_mechanisms=ctx.profile.auth_mechanisms)
    ctx.test_cases = generation.test_cases
    ctx.actions = orchestrator.planner.generate(ctx)


def cmd_discover(cfg: AgentConfig) -> int:
    from core.discovery import discover_project

    target_path = cfg.url or cfg.target
    profile = discover_project(target_path if Path(target_path).exists() else ".")
    print(profile.summary())
    if profile.potential_risks:
        print("Potential risks:")
        for risk in profile.potential_risks:
            print(f"  - {risk}")
    if cfg.dry_run:
        print("(dry-run: no files were written)")
    return 0


def cmd_plan(cfg: AgentConfig) -> int:
    ctx = _make_context(cfg)
    orchestrator = Orchestrator()
    _bootstrap_pipeline(ctx, orchestrator)
    assert ctx.plan is not None and ctx.profile is not None
    print(ctx.plan.summary())
    print()
    print(f"Skills selected : {', '.join(ctx.strategy.selected_skills)}")
    print(f"Skills skipped  : {', '.join(ctx.strategy.skipped_skills) or '-'}")
    print(f"Requirements    : {len(ctx.requirements)}")
    print(f"Test cases      : {len(ctx.test_cases)} (actions: {len(ctx.actions)})")
    if ctx.risk_assessment is not None:
        print(f"Profile risk    : {ctx.risk_assessment.profile_risk.value} (score {ctx.risk_assessment.overall_score})")
    output_dir = ctx.output_dir
    if not cfg.dry_run:
        from core.atomic_write import atomic_write_json

        output_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "target": ctx.target,
            "profile": ctx.profile.model_dump(mode="json"),
            "requirements": [r.model_dump(mode="json") for r in ctx.requirements],
            "plan_items": [item.__dict__ for item in ctx.plan.items],
            "test_cases": [tc.model_dump(mode="json") for tc in ctx.test_cases],
        }
        if ctx.risk_assessment is not None:
            payload["risk"] = {
                "profile_risk": ctx.risk_assessment.profile_risk.value,
                "overall_score": ctx.risk_assessment.overall_score,
            }
        atomic_write_json(output_dir / "test_plan.json", payload)
        print(f"Plan written to {output_dir / 'test_plan.json'}")
    else:
        print("(dry-run: plan not persisted)")
    return 0


def cmd_run(cfg: AgentConfig) -> int:
    ctx = _make_context(cfg)
    orchestrator = Orchestrator()
    if cfg.dry_run:
        _bootstrap_pipeline(ctx, orchestrator)
        assert ctx.plan is not None
        print(ctx.plan.summary())
        print(f"(dry-run: {len(ctx.actions)} action(s) would execute; nothing was run)")
        return 0
    try:
        result = orchestrator.run(ctx)
    except KeyboardInterrupt:
        print("Interrupted — run manifest finalized as INTERRUPTED.", file=sys.stderr)
        return 130
    print(f"Run complete. Run ID: {ctx.run_id}")
    print(f"State history: {' -> '.join(result.history)}")
    print(f"Findings: {len(result.findings)}")
    if result.coverage is not None:
        print(f"Requirements coverage: {result.coverage.ratio('requirements'):.0%}")
    if result.escalation is not None or result.escalation_registry.has_halt():
        print("Escalation: human input required (see report)")
        if result.gate is not None:
            print(f"Quality gate: {result.gate.status.value}")
        return 2
    if result.gate is not None:
        print(f"Quality gate: {result.gate.status.value}")
        if result.gate.reasons and not result.gate.passed:
            print(f"Reasons: {'; '.join(result.gate.reasons)}")
        return 0 if result.gate.passed else 1
    return 0


def cmd_report(run_dir_raw: str) -> int:
    from core.atomic_write import atomic_write_json

    run_dir = Path(run_dir_raw)
    if not run_dir.exists():
        print(f"run directory not found: {run_dir}", file=sys.stderr)
        return 2
    report_json = run_dir / "audit_report.json"
    if not report_json.exists():
        print(f"no audit_report.json in {run_dir}", file=sys.stderr)
        return 2
    payload = json.loads(report_json.read_text(encoding="utf-8"))
    summary = payload.get("summary", {})
    gate = payload.get("quality_gate", {})
    print(f"Run: {payload.get('run_id', 'unknown')}")
    print(f"Target: {payload.get('target', 'unknown')}")
    print(f"Findings: {summary.get('total', 0)} (high-severity: {summary.get('high_severity', 0)})")
    if gate:
        print(f"Quality gate: {gate.get('status', 'UNKNOWN')}")
    # Refresh renderable artifacts if missing
    if not (run_dir / "audit_report.md").exists() or not (run_dir / "audit_report.html").exists():
        try:
            from core.models import Finding
            from core.report_builder import ReportBuilder

            findings = [Finding(**f) for f in payload.get("findings", [])]
            builder = ReportBuilder()
            (run_dir / "audit_report.md").write_text(builder.build(target=payload.get("target", ""), findings=findings), encoding="utf-8")
            atomic_write_json(run_dir / "audit_report.html", builder.build_html(target=payload.get("target", ""), findings=findings))
            print("Reports re-rendered from JSON.")
        except Exception as exc:  # noqa: BLE001
            print(f"re-render failed: {exc}", file=sys.stderr)
    return 0


def cmd_validate(run_dir_raw: str) -> int:
    run_dir = Path(run_dir_raw)
    manifest_path = run_dir / "run_manifest.json"
    if not manifest_path.exists():
        print(f"no run_manifest.json in {run_dir}", file=sys.stderr)
        return 2
    recovery = CrashRecoveryManager()
    ok, detail = recovery.validate_manifest(manifest_path)
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        print(f"manifest unreadable: {exc}", file=sys.stderr)
        return 2
    print(f"Run: {data.get('run_id', 'unknown')}")
    print(f"Manifest: {detail}")
    if data.get("interrupted"):
        print(f"Interrupted: {data.get('interrupt_reason', 'unspecified')}")
        return 1
    gate = data.get("quality_gate") or {}
    status = gate.get("status", "UNKNOWN")
    print(f"Quality gate: {status}")
    if not ok:
        return 1
    if status in ("PASS", "PASS_WITH_WARNINGS"):
        return 0
    if status == "NEEDS_HUMAN":
        return 2
    return 1


def main(argv: list[str] | None = None) -> int:
    # Windows consoles default to cp1252; box-drawing chars in summaries
    # would crash the CLI. Replace unencodable glyphs instead of failing.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except Exception:  # noqa: BLE001 — console reconfig is best-effort
                pass
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "report":
            return cmd_report(args.run)
        if args.command == "validate":
            return cmd_validate(args.run)
        cfg = _load_config(args)
    except ValidationError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    if args.command == "discover":
        return cmd_discover(cfg)
    if args.command == "plan":
        return cmd_plan(cfg)
    if args.command == "run":
        return cmd_run(cfg)
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
