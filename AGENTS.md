# QA_Automation_Agent — persistent agent memory

Scope: local-first autonomous QA engineer with zero-cloud data privacy.
Execution runtime: Playwright async, Pytest, Jinja2 reporting.
Architecture: BUILD-FIRST enterprise loop with strict planner / executor / decision separation.

---

## Operative cycle (planned execution)

1. Plan — scope the QA target: page set, forms, visual assertions, report format.
2. Verify — confirm permissions, local environment, and that sensitive artifacts (env, screenshots, logs) stay out of version control.
3. Implement — bind engines through skills; do not rewrite crawler, form tester, a11y, API, or report builder unless required.
4. Review — inspect diffs before staging; enforce strict gitignore before any git add.
5. Test — run pytest after the architecture is frozen (Phase 2 validates).
6. Remember — promote repeat wins into skills/ and this AGENTS.md when they are worth reusing.
7. Improve — refine prompts, payloads, and report templates from real findings.

## Autonomous decision loop (implemented)

`DISCOVER -> UNDERSTAND -> PLAN -> GENERATE -> EXECUTE -> OBSERVE -> ANALYZE -> RETRY -> VERIFY -> REPORT -> ESCALATE -> DONE`

- Loop is bounded: `MAX_LOOP_STEPS = 48` in `core/orchestrator.py` — the machine can never spin forever.
- Planner (`core/planner.py`) proposes work only; produces Requirements→Risks→TestPlan→TestCases→Actions.
- Executor (`core/orchestrator.py::Executor` + `core/skills_registry.py`) runs `Action` contracts and returns `Result`; skill crashes are contained and classified.
- DecisionAgent advances state, including human escalation (max 3 retry rounds).
- Retries: maximum 3 per failure signature via `core/failure_analyzer.py::RetryController`; transient types only (TIMEOUT, NETWORK, BROWSER, INFRASTRUCTURE). PRODUCT_BUG / AUTH / CONFIG / TEST_BUG / DATA are never auto-retried.
- Flaky: `FlakyDetector` reports PASS/FAIL oscillation as FLAKY — never auto-promoted to confirmed bug.
- Findings: `FindingManager` dedups by 6-field fingerprint; confidence scored LOW/MEDIUM/HIGH.
- Escalation: `core/escalation.py::HumanEscalationRegistry` records WHY / WHAT WAS ATTEMPTED / EVIDENCE / WHAT HUMAN INPUT IS REQUIRED.
- Crash recovery: `core/crash_recovery.py` finalizes interrupted runs with `interrupted=true` and gate BLOCKED — an interrupted run can never look successful.
- LLM boundary: `core/llm_boundary.py` — proposals only, validated, never executable directly.
- Standalone bounded state machine: `core/state_machine.py` (states DISCOVER/ANALYZE/PLAN/EXECUTE/ANALYZE_FAILURE/RETRY/CONTINUE/STOP/ESCALATE/REPORT/HALTED).

Mandatory halt / escalate when:
- credentials are missing for an inferred auth surface on high-risk runs
- runtime budget is exhausted (environment treated as broken)
- destructive actions are requested on a high-risk run

## Module map

- `core/models.py` — unified typed models: Project/ProjectProfile, Requirement(+category), Risk(+score), TestCase/Step(+status/fingerprint), TestResult, Finding, Evidence, ExecutionRun/Config, BudgetConfig, ResourceBudget, RetryDecision, Escalation, QualityGateResult, RunManifest, TraceabilityIndex. Backward-compat aliases: `Severity=FindingSeverity`, `ConfidenceLevel=Confidence`, `DiscoveredProject=ProjectProfile`.
- `core/scope.py` — DENY-UNKNOWN `Scope`, STOP-semaphore `Budget` (no auto-reset), `ResourceGovernor`.
- `core/config.py` — profiles safe/standard/deep/ci + fail-fast `validate_config` (`ValidationError`). Carries `QualityGatePolicy` per profile: the requirement-coverage floor is a profile decision (safe 10% / standard 20% / deep 30% / ci disabled), overridable via `--min-coverage`.
- `core/redaction.py` (+`core/security.py` shim) — central `[REDACTED]` layer; every write path calls it.
- `core/discovery.py` — read-only `ProjectProfile`; helpers `_has_e2e_tests`, `_infer_python_routes`; alias `DiscoveredProject`.
- `core/spec_analyzer.py` — README/API docs classified OBSERVED/INFERRED/UNKNOWN.
- `core/requirements_engine.py` — Requirement objects (explicit/inferred/unknown) from docs, routes, APIs, forms, configs, tests.
- `core/risk_engine.py` — 7-axis weighted scoring; UNKNOWN requirements capped at MEDIUM.
- `core/strategist.py` — selects skills from discovery signals; imports `DiscoveredProject` from `core.discovery`.
- `core/planner.py` — `TestPlan`/`PlanItem` + `generate_test_cases` (dedup, stable IDs, impossible detection).
- `core/test_generator.py` — facade over planner generation.
- `core/skills_registry.py` / `core/actions.py` — SkillContract registry + Action/Result contracts. Crawler/form_tester/a11y/api skills execute real bounded Playwright sessions against HTTP(S) targets via `core/live_session.py` (one open→audit→close cycle per operation, scope+budget enforced, redacted evidence); dry-run/local targets stay bind-level.
- `core/live_session.py` — bounded live browser driver. Playwright transports are loop-bound, so every public operation runs inside a single `asyncio.run()` cycle; cross-cycle audit memory (visited URLs, page HTML, probed endpoints) lives on the session object.
- `core/orchestrator.py` — state machine, Executor, DecisionAgent, escalation, atomic reports, crash recovery hook.
- `core/failure_analyzer.py` — 12-type taxonomy + RetryController + FlakyDetector.
- `core/analyzer.py` — DEPRECATED shim re-exporting failure_analyzer (legacy enum aliases APPLICATION_FAILURE/SELECTOR_FAILURE).
- `core/evidence.py` / `core/manifest.py` — EvidenceEntry(run/test/finding IDs), atomic RunManifest, `EvidenceManager.finalize`.
- `core/finding_manager.py` — dedup + `score_confidence` + status transitions.
- `core/quality_gate.py` — 5-state gate + CoverageEngine (requirements/tests/risks/execution). Gate thresholds resolve from `RunContext.gate_policy` via `Orchestrator._gate_for`; an explicitly injected gate keeps priority.
- `core/coverage_engine.py` — facade over quality_gate coverage.
- `core/state_machine.py`, `core/escalation.py`, `core/llm_boundary.py`, `core/crash_recovery.py` — bounded autonomy primitives.
- `core/logger.py` — StructuredLogger (DEBUG..CRITICAL, run_id, always redacted).
- `core/atomic_write.py` — tmp→flush→fsync→validate→rename artifact writes.
- `core/session_manager.py` — ANONYMOUS/AUTHENTICATED/EXPIRED_SESSION/INVALID_CREDENTIALS; `apply_to_playwright_context_options` returns a NEW dict (never mutates caller's).
- `core/crawler.py`, `core/form_tester.py`, `core/a11y_auditor.py`, `core/api_auditor.py`, `core/report_builder.py` — existing engines, reused not rewritten.
- `main.py` — CLI: `discover | plan | run | report | validate` with `--profile --risk --browser --headed/--headless --output --budget --scope --config --dry-run --allow-external` and single overrides.

## Commands

```bash
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\playwright install chromium
.venv\Scripts\python main.py discover .
.venv\Scripts\python main.py plan . --profile safe
.venv\Scripts\python main.py run samples/demo_site --profile safe --url http://127.0.0.1:8000 --output reports/demo_run
.venv\Scripts\python main.py validate reports/demo_run
.venv\Scripts\pytest -vv
```

Demo target: `samples/demo_site` (static site + bounded `server.py` on 127.0.0.1). It carries deliberate findings: broken link, missing alt, heading skips, duplicate IDs, unlabeled input, console errors, configurable 4xx/5xx + slow + malformed JSON endpoints, fragment/self loops, admin path, external link.

Exit codes: 0 pass/pass-with-warnings · 1 gate FAIL or interrupted · 2 escalation/needs-human or config error · 130 KeyboardInterrupt.

Limits: same-origin unless explicitly allowed; no cloud uploads; secrets never enter git or logs; budgets STOP without reset; redaction always on.

## Context discipline

- Keep the working context tight. Persist reusable decisions here rather than re-asking every session.
- Prefer local execution for any artifact that contains secrets, screenshots, traces, or logs.
- Never stage `.env`, `.venv`, `*.log`, `trace.zip`, screenshots, or rendered reports before confirming `.gitignore` coverage.
- Before every `git add`, inspect `git status` and confirm the diff contains only intentional files.

## Repo and deployment discipline

- Branch: main
- Remote: GitHub repo `QA_Automation_Agent`
- Commit strategy: milestone commits; single architecture completion commit, then a Phase 2 validation commit if needed.

## Skills directory convention (local)

`skills/` holds folder-shaped capabilities. Each skill folder contains a short SKILL.md (purpose, inputs, outputs, privacy). Engines stay in `core/` and are bound through `SkillRegistry`. New skills register via `SkillRegistry.register(SkillContract(...))` without touching the orchestrator.

## Local privacy rules

- `.env` and `.venv/` must never enter version control.
- Screenshots, traces, logs, and rendered HTML reports are temporary by default and must stay out of the repo.
- Any network call that leaves the local machine must be intentional and reviewed before execution.
- Redact tokens, cookies, passwords, API keys, and Authorization headers before writing evidence or reports (use `core.redaction`, never per-skill hacks).

## Review cues before push

- `git status` clean of sensitive files
- `.gitignore` covering env, venv, cache, screenshots, logs, traces, and rendered reports
- README and tests ready for the current milestone
- Commit message follows conventional-changelog style for the change type

## Debugging cues

- Import errors naming missing model symbols: check `core/models.py` first — it is the single source of truth; aliases exist for legacy names.
- `ValidationError` from `core.config`: fix the quoted config; it fails fast by design.
- A run that ends in ESCALATE is recorded in `run_manifest.json` escalations + `audit_report.json`.
- Interrupted runs: `python main.py validate <run-dir>` explains what was interrupted and why.
- `core/analyzer.py` is a shim — new code imports `core.failure_analyzer`.
