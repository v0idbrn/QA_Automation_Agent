# Autonomous QA Engineer & Bug Reporting Agent (Enterprise Edition)

Local-first autonomous QA agent that runs a full audit cycle —
**DISCOVERY → REQUIREMENTS → RISK → PLANNING → TEST GENERATION → EXECUTION →
EVIDENCE → FAILURE ANALYSIS → RETRY → FINDINGS → QUALITY GATE → REPORT →
HUMAN ESCALATION** — against a local project or an in-scope web target,
without sending page content, screenshots, logs, or reports outside the
local environment.

This is an **auditing assistant that amplifies QA engineers**. It does not
replace them: heuristic findings are evidence, not verdicts, and ambiguous
or dangerous situations escalate to a human by design.

## Legal & Compliance

- License: MIT. See `LICENSE`.
- Copyright (c) 2026 Gaetano (v0idbrn).
- Only run this tool against targets you own or have explicit written
  permission to test. You accept full responsibility for compliance with
  applicable laws, contracts, and site terms of service.

## Capabilities

- Read-only project discovery (framework, routes, APIs, forms, tests, auth, risk flags)
- Requirements extraction classified `explicit` / `inferred` / `unknown` — inferences are never presented as confirmed
- 7-axis risk scoring (impact, likelihood, complexity, exposure, auth, data sensitivity, business criticality)
- Risk-prioritized test planning with stable IDs and traceability `Requirement → Risk → Test → Execution → Evidence → Finding → Quality Gate`
- Deterministic, skill-registry-driven execution (crawler, form tester, a11y, API auditor)
- Bounded crawling: same-origin by default (DENY UNKNOWN), depth/page/request/runtime budgets, omit-reason logging
- Defensive form fuzzing: empty, whitespace, boundary lengths, Unicode, malformed values — synthetic and harmless only
- Accessibility heuristics (alt, labels, headings, ARIA, duplicate IDs) — explicitly *not* a WCAG compliance claim
- API interception: 4xx/5xx, malformed JSON, invalid content types; no secrets recorded
- 12-type failure taxonomy with bounded retries (max 3 per signature, transient-only)
- Flaky detection: PASS/FAIL oscillation is reported as FLAKY, never auto-promoted to a confirmed bug
- Finding deduplication via canonical 6-field fingerprints, with LOW/MEDIUM/HIGH confidence scoring
- Quality Gate: `PASS / PASS_WITH_WARNINGS / FAIL / BLOCKED / NEEDS_HUMAN`
- Coverage engine (requirements / tests / risks / execution) — this is *coverage of requirements by tests*, not code coverage
- Evidence manager with per-artifact `run_id` / `test_id` / `finding_id` association
- Crash recovery: an interrupted run is finalized as `INTERRUPTED` and can never look successful
- Atomic artifact writes (tmp → flush → fsync → validate → rename)
- Central redaction layer applied to logs, reports, evidence, and manifests
- Reports in Markdown, HTML, and JSON, plus Jira-compatible ticket export
- Profiles: `safe`, `standard`, `deep`, `ci` — all share the same security baseline

## Architecture

```text
QA_Automation_Agent
├── main.py                  # CLI: discover | plan | run | report | validate
├── core/
│   ├── models.py            # unified typed models + traceability index
│   ├── discovery.py         # READ-ONLY ProjectProfile
│   ├── spec_analyzer.py     # README/API doc classification
│   ├── requirements_engine.py
│   ├── risk_engine.py
│   ├── strategist.py        # skill selection from discovery signals
│   ├── planner.py           # TestPlan + TestCases (never executes)
│   ├── test_generator.py    # facade: dedup, stable IDs, impossible tests
│   ├── skills_registry.py   # declarative skill contracts + handlers
│   ├── actions.py           # Action / Result contracts
│   ├── orchestrator.py      # bounded state machine + Executor + DecisionAgent
│   ├── state_machine.py     # bounded autonomous state machine (standalone)
│   ├── scope.py             # Scope guard (DENY UNKNOWN) + Budget + ResourceGovernor
│   ├── config.py            # profiles + fail-fast validation
│   ├── failure_analyzer.py  # 12-type taxonomy + RetryController + FlakyDetector
│   ├── analyzer.py          # deprecated shim (kept for legacy imports)
│   ├── finding_manager.py   # dedup + confidence + status transitions
│   ├── escalation.py        # human escalation registry (WHY/ATTEMPTED/EVIDENCE/INPUT)
│   ├── evidence.py          # evidence store + RunManifest
│   ├── manifest.py          # re-export shim
│   ├── redaction.py         # central sensitive-data scrubbing
│   ├── logger.py            # structured 5-level logging, always redacted
│   ├── atomic_write.py      # atomic artifact writes
│   ├── crash_recovery.py    # interrupt classification + interrupted manifests
│   ├── llm_boundary.py      # LLM proposals: PROPOSE → VALIDATE → authorize
│   ├── quality_gate.py      # 5-state gate + coverage engine
│   ├── coverage_engine.py   # coverage facade
│   ├── observability.py     # why-omit / why-retry / budget-remaining explainers
│   ├── session_manager.py   # anonymous/authenticated/expired/invalid states
│   ├── security.py          # re-export shim for redaction
│   ├── crawler.py           # async Playwright crawler (existing engine)
│   ├── form_tester.py       # boundary + synthetic payloads (existing engine)
│   ├── a11y_auditor.py      # accessibility heuristics (existing engine)
│   ├── api_auditor.py       # network interception (existing engine)
│   └── report_builder.py    # Jinja2 MD/HTML/JSON + Jira export (existing engine)
├── reports/                 # Jinja2 templates + generated artifacts (gitignored)
├── samples/demo_site/       # synthetic target with deliberate findings
├── skills/                  # folder-shaped skill docs (SKILL.md)
├── tests/                   # pytest suite
└── AGENTS.md                # agent memory: rules, commands, conventions
```

Runtime artifacts (reports, screenshots, manifests, evidence) stay in
`reports/` and are excluded from version control.

## Installation

Requirements: Python 3.10+, Node.js runtime for Playwright browsers.

```bash
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\playwright install chromium
```

## CLI

```bash
.venv/Scripts/python main.py discover <target>     # read-only project profile
.venv/Scripts/python main.py plan <target>         # requirements + risks + plan (no execution)
.venv/Scripts/python main.py run <target>          # full autonomous cycle
.venv/Scripts/python main.py report <run-dir>      # summarize/refresh a previous run
.venv/Scripts/python main.py validate <run-dir>    # crash-recovery + gate check (exit code)
```

Common flags:

| Flag | Meaning |
|---|---|
| `--profile safe\|standard\|deep\|ci` | configuration profile |
| `--risk low\|medium\|high` | run-level risk knob |
| `--browser chromium\|firefox\|webkit` | Playwright engine |
| `--headed` / `--headless` | browser visibility |
| `--output DIR` | report output directory |
| `--budget max_pages=10,max_requests=20,max_tests=5,max_runtime=60` | budget overrides |
| `--scope origin=https://host,allow_external=true` | scope overrides |
| `--config FILE` | JSON file merged into extra config |
| `--min-coverage 0.0–1.0` | requirement-coverage floor for the quality gate (default: per-profile policy; `0` disables the floor) |
| `--dry-run` | plan only, never execute |
| `--allow-external` | permit out-of-origin URLs (still bounded) |
| `--max-pages/--max-requests/--max-depth/--timeout/--max-runtime` | single-value overrides |

Exit codes: `0` pass/pass-with-warnings, `1` gate fail or interrupted,
`2` escalation/needs-human or configuration error, `130` keyboard interrupt.

## Example run

```bash
# serve the synthetic demo (bounded, localhost only)
cd samples/demo_site
../../.venv/Scripts/python server.py --port 8000 --max-requests 200

# audit it
cd ../..
.venv/Scripts/python main.py run samples/demo_site --profile safe \
    --url http://127.0.0.1:8000 --output reports/demo_run
```

Outputs in `reports/demo_run/`: `audit_report.md`, `audit_report.html`,
`audit_report.json`, `jira_export.md`, `run_manifest.json`,
`run_evidence.json`.

## Report structure

Markdown/HTML/JSON reports contain: Executive Summary, Project Profile,
Scope, Environment, Risk Summary, Requirements, Coverage, Tests Planned /
Executed / Passed / Failed / Blocked / Flaky, Findings (severity, confidence,
evidence, reproduction), Retries, Escalations, Limitations, Quality Gate,
Recommendations, and the Run Manifest. The JSON report is machine-readable;
`jira_export.md` is a per-finding Jira ticket draft.

## Configuration profiles

| Profile | Pages | Requests | Depth | Runtime | Coverage floor | Use case |
|---|---|---|---|---|---|---|
| `safe` | 5 | 20 | 1 | 120 s | 10% | first contact, CI smoke |
| `standard` | 25 | 100 | 2 | 300 s | 20% | default |
| `deep` | 100 | 500 | 4 | 1800 s | 30% | owned-target deep audits |
| `ci` | standard + headless + 600 s cap | | | | disabled | pipelines |

All profiles enforce the same security baseline: same-origin, no uploads,
no filesystem writes, no destructive actions, redaction always on.

The **coverage floor** is the requirement-coverage ratio the quality gate
expects. It is a per-profile policy, not a fixed constant: engine-level runs
(HTTP-only skills, no live browser sessions) naturally cover a small fraction
of discovered requirements, so use `--profile ci` or `--min-coverage 0.05`
when auditing targets whose surface far exceeds what one bounded run can
execute. Override per run with `--min-coverage`; `--min-coverage 0` disables
the floor entirely (findings, budget, and scope still decide the gate).

## Safety model

Defaults are fail-closed:

- **READ-ONLY DISCOVERY** — discovery never writes to the target.
- **DENY UNKNOWN** — cross-origin URLs are refused unless explicitly allowed; blocked path tokens (`/admin`, `/delete`, `/drop`, `/reset`, `/logout`) are refused by default.
- **BOUNDED EXECUTION** — depth/pages/requests/tests/runtime/retries/artifacts budgets; once exhausted, the run STOPS (no auto-reset).
- **NO DESTRUCTIVE ACTIONS** — payloads are synthetic and harmless; destructive skills do not exist in the registry.
- **NO SECRET LOGGING** — one central redaction layer guards logs, evidence, manifests, and reports; credentials live only in `SessionManager` memory.
- **NO UNCONTROLLED FUZZING/CRAWLING** — every network action passes the scope guard and budget.
- **LLM BOUNDARY** — an LLM (if integrated) may only PROPOSE; proposals are validated and can only become actions through the authorized executor.

Never: delete data, modify production, DoS, exploit third parties, run
arbitrary commands against targets, or send target data to external services.

## Supported targets

- Local project directories (read-only discovery; static HTML auditing)
- HTTP/HTTPS origins you own or are authorized to test (bounded crawling)
- Static local HTML files

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `configuration error: ...` | Fail-fast validation. Fix the quoted profile/URL/budget combination. |
| Exit code 2 + "human input required" | The run escalated (missing credentials, ambiguous scope). Read the escalation section of the report. |
| Gate FAIL with coverage reasons | Too few requirements covered for the profile's floor — widen `--profile deep`, lower the floor with `--min-coverage`, or disable it with `--min-coverage 0`. |
| No findings from a live target | Ensure the server is reachable at `--url`, and that it serves the same origin. |
| `playwright install` errors | Run `.venv/Scripts/playwright install chromium`. |
| Interrupted run shows BLOCKED | Expected: `validate` reports interrupted runs; re-run to completion. |

## Limitations

- Accessibility checks are partial heuristics and do **not** certify WCAG compliance.
- Coverage measures requirements-to-tests mapping, not code coverage of the target.
- Live browser skills (`crawl`, `form_tester`, `a11y`, `api`) execute real Playwright
  sessions against HTTP(S) targets (each public operation is one bounded
  open→audit→close cycle; screenshots/DOM snapshots are stored as redacted
  evidence). Dry-run and local-project runs stay bind-level (INFO evidence only).
- Form exercise is defensive by design: empty submits with the form's declared
  method only — no payload injection or fuzzing against live targets.
- Findings derived from INFERRED requirements are hypotheses and need human confirmation.
- The crawler follows same-origin links; JS-heavy SPAs may require higher budgets.
- No cloud/CI integrations ship with the project; everything runs locally.

## Commercial positioning

For teams that need repeatable QA coverage without sending data outside
their machines: one command produces a professional, evidence-backed report
with a defensible quality gate. The agent amplifies QA engineers — it does
not replace human judgment, credentials handling, or exploratory testing.
