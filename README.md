# QA Automation Agent — AI-SDET & Quality Engineering Framework

[![CI Quality Gates](https://github.com/v0idbrn/QA_Automation_Agent/actions/workflows/ci-quality-gates.yml/badge.svg?branch=main)](https://github.com/v0idbrn/QA_Automation_Agent/actions/workflows/ci-quality-gates.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Pytest](https://img.shields.io/badge/tests-295%20passing-3ecf8e)](#quality-suites)
[![License: MIT](https://img.shields.io/badge/license-MIT-4da3ff)](LICENSE)

A local-first quality-engineering framework that combines deterministic
AI-SDET gates with an autonomous web QA agent. It demonstrates enterprise
practices for **LLM evaluation, RAG groundedness, MCP tool security, API
contract testing, Playwright layout auditing, dataset governance, and CI/CD
quality gates** — without sending target data to a cloud service.

> 🇪🇸 Spanish translation: [README.es.md](README.es.md). The Spanish file may lag
> behind this document.

---

## What this repository contains

Two layers, one repository:

1. **Deterministic AI-SDET framework** (`src/qa_agent/`)
   Reusable evaluators and validators that run fully offline. The four suites
   in `tests/evals`, `tests/security`, `tests/e2e`, and `tests/data` exercise
   them with `pytest` and no API keys.
2. **Autonomous QA agent** (`core/`, `main.py`, `gui.py`)
   An enterprise-oriented audit loop that performs discovery, risk-based
   planning, bounded browser execution, evidence capture, failure analysis,
   findings, and a five-state quality gate against local projects or
   authorized same-origin web targets.

The AI-SDET layer is deterministic by design: mocks are the default, live
model calls are opt-in, and every gate returns structured results that CI can
assert on.

---

## Architecture overview

```text
QA_Automation_Agent
├── src/qa_agent/                  # Deterministic AI-SDET framework
│   ├── llm_evals.py               # Mock/live LLM adapters, RAG groundedness,
│   │                              # structured JSON validation, prompt regression,
│   │                              # latency and token budgets
│   ├── mcp_validator.py           # MCP tool-call schema + input sanitizer,
│   │                              # mapped to OWASP LLM Top 10
│   ├── web_auditor.py             # HTTPX contract checks + Playwright console
│   │                              # and mobile-overflow auditing
│   └── data_gates.py              # Schema, null, duplicate, PII, and label-drift
│                                  # gates over pandas DataFrames
├── tests/
│   ├── evals/test_llm_rag.py      # 28 offline LLM/RAG evaluation tests
│   ├── security/test_mcp_guardrails.py  # 55 MCP/agent security tests
│   ├── e2e/test_web_api_audit.py  # 20 HTTPX + Playwright E2E tests
│   ├── data/test_dataset_quality.py  # 21 dataset-governance tests
│   └── test_*.py                  # Legacy autonomous-agent regression suite
├── core/                          # Autonomous agent engines (reused, not rewritten)
│   ├── discovery.py               # Read-only project profile
│   ├── requirements_engine.py     # Explicit / inferred / unknown requirements
│   ├── risk_engine.py             # Seven-axis risk scoring
│   ├── planner.py                 # Requirements → risks → plan → test cases
│   ├── orchestrator.py            # Bounded state machine + executor + decisions
│   ├── live_session.py            # Bounded Playwright audit sessions
│   ├── quality_gate.py            # PASS / WARN / FAIL / BLOCKED / NEEDS_HUMAN
│   ├── evidence.py                # Evidence entries + run manifest
│   ├── redaction.py               # Central secret/PII scrubbing layer
│   └── report_builder.py          # Markdown, HTML, JSON, and Jira export
├── samples/demo_site/             # Synthetic target with deliberate findings
├── scripts/                       # Demo runner and Windows exe build
├── .github/workflows/
│   └── ci-quality-gates.yml       # Push/PR quality gate on Python 3.11
├── cv_metrics.json                # Machine-readable suite metrics
├── pyproject.toml                 # Installable qa_agent package metadata
├── pytest.ini                     # src/ import path + test discovery
├── main.py                        # CLI: discover | plan | run | report | validate
└── gui.py                         # Desktop control center over the same CLI
```

### Execution flow

```text
                 ┌──────────────── deterministic AI-SDET gates ────────────────┐
commit / PR ───► │ LLM+RAG evals → MCP security → API+Playwright → data gates  │ ───► pytest
                 └──────────────────────────────────────────────────────────────┘

target ───► discover ───► requirements ───► risk ───► plan ───► execute
                                                                    │
                report ◄── quality gate ◄── findings ◄── analyze ◄──┘
```

---

## Quality suites

`pytest.ini` makes `src/` importable and limits discovery to `tests/`. The new
framework contributes **124 deterministic tests**; the complete repository
suite is **295 passing tests**.

| Suite | Tests | Focus |
|---|---:|---|
| `tests/evals/test_llm_rag.py` | 28 | LLM adapters, RAG groundedness, structured output, prompt regression, budgets |
| `tests/security/test_mcp_guardrails.py` | 55 | Tool schemas, sanitization, traversal, command injection, SSRF, prompt injection |
| `tests/e2e/test_web_api_audit.py` | 20 | HTTP contracts, error envelopes, console errors, mobile overflow, ASGI transport |
| `tests/data/test_dataset_quality.py` | 21 | Schema, nulls, duplicates, PII, label drift |
| Legacy agent suite (`tests/test_*.py`) | 171 | Discovery, planning, orchestration, safety, reporting, packaging |

### 1. LLM & RAG evaluation

`src/qa_agent/llm_evals.py` provides:

- `MockLLMAdapter` — deterministic, offline responses keyed by prompt; the
  default for every test.
- `OpenAICompatibleAdapter` — optional live adapter using
  `OPENAI_API_KEY` or `GROQ_KEY`, with an OpenAI-compatible base URL.
- `evaluate_groundedness()` — claim-level support against retrieved chunks,
  with explicit numeric-mismatch rejection.
- `validate_structured_output()` — JSON parsing plus strict Pydantic
  validation (`extra="forbid"` in the test schemas).
- `run_conversation()` — multi-turn scripted regression with
  `must_contain` / `must_not_contain` assertions.
- `assert_within_budget()` — latency and token thresholds.

The suite covers grounded answers, hallucinated entities, fabricated numbers,
partial grounding, fenced JSON, missing/extra fields, invalid ranges, multi-turn
regressions, budget failures, adapter credential handling, and mock
determinism. No network is used.

### 2. Agent & MCP tool security

`src/qa_agent/mcp_validator.py` validates MCP-style `ToolCall` objects against
a declared `ToolPolicy` and returns structured `Violation` records.

| Control | Examples blocked | OWASP LLM Top 10 |
|---|---|---|
| Path traversal | `../`, `%2e%2e/`, `..\`, absolute paths | LLM05 Improper Output Handling |
| Command injection | `;`, `&&`, `\|\|`, `\|`, `$()`, backticks, redirects, newlines | LLM06 Excessive Agency |
| SSRF | loopback, RFC1918, link-local, `169.254.169.254`, metadata hosts, decimal/hex IPs, userinfo tricks | LLM06 Excessive Agency |
| Unsafe schemes | `file:`, `gopher:`, `ftp:` | LLM06 Excessive Agency |
| Prompt injection | direct overrides, system-prompt exfiltration, indirect HTML/role markers | LLM01 Prompt Injection |
| Sensitive data | API-key, bearer-token, and password-shaped arguments | LLM02 Sensitive Information Disclosure |
| Schema abuse | unknown tools/arguments, missing required args, wrong types, oversized inputs | LLM06 Excessive Agency |

Inputs are NFKC-normalized and percent-decoded up to three times before
inspection. Control characters are stripped. A call is allowed only when it
matches the declared schema and produces zero violations.

### 3. API contract & Playwright web audit

`src/qa_agent/web_auditor.py` exposes:

- `audit_json_contract()` — status code, `application/json` content type, JSON
  parsing, and Pydantic schema validation through HTTPX.
- `audit_error_response()` — stable `{error, message}` envelope, correct status,
  and no leaked traceback/stack/exception fields.
- `audit_web_page()` — bounded Chromium session that collects `console` errors,
  uncaught page errors, and horizontal overflow at a **390×844** mobile
  viewport.

The E2E suite uses a local `ThreadingHTTPServer` fixture with clean, noisy,
malformed, and failing endpoints, plus a minimal ASGI app driven through
`httpx.ASGITransport`. Browser audits start and stop Playwright inside the
test, so no event loop leaks into the async agent suite. Transport failures
return a structured `ApiContractResult` instead of raising, so a dead endpoint
cannot crash an audit pipeline.

### 4. Dataset governance & drift gates

`src/qa_agent/data_gates.py` validates pandas DataFrames and returns a
`DatasetReport` instead of raising on the first problem:

- required columns and dtype contracts;
- per-column null ratios;
- duplicate-record ratio;
- PII detection for email, phone, SSN, Luhn-valid credit cards, API keys, and
  IPv4 addresses;
- label-distribution drift using total variation distance;
- unexpected or missing label categories.

PII values are never copied into the report — only counts by column and
category. Synthetic frames keep the suite deterministic and safe.

---

## Quickstart

Requirements: **Python 3.11+**, Node.js runtime for Playwright browsers.

```bash
python -m venv .venv

# Windows
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\playwright install chromium

# POSIX
source .venv/bin/activate
pip install -r requirements.txt
playwright install chromium
```

Install the reusable framework package for imports outside the test runner:

```bash
# Windows
.venv\Scripts\pip install -e .

# POSIX
pip install -e .
```

Run the full quality gate:

```bash
.venv\Scripts\python -m pytest -q
```

Run one suite:

```bash
.venv\Scripts\python -m pytest tests/evals -q
.venv\Scripts\python -m pytest tests/security -q
.venv\Scripts\python -m pytest tests/e2e -q
.venv\Scripts\python -m pytest tests/data -q
```

### Autonomous agent CLI

```bash
python main.py discover <target>          # read-only project profile
python main.py plan <target>              # requirements + risks + test plan
python main.py run <target>               # full bounded audit cycle
python main.py report <run-dir>           # refresh/summarize a previous run
python main.py validate <run-dir>         # crash recovery + gate verdict
```

Example audit of the bundled synthetic site:

```bash
# Terminal 1: bounded local demo server
cd samples/demo_site
../../.venv/Scripts/python server.py --port 8000 --max-requests 200

# Terminal 2: audit it
cd ../..
.venv/Scripts/python main.py run samples/demo_site --profile safe \
    --url http://127.0.0.1:8000 --output reports/demo_run
```

Or run the complete demo, including server lifecycle:

```bash
.venv/Scripts/python scripts/demo.py --port 8000
```

Common flags: `--profile safe|standard|deep|ci`, `--risk low|medium|high`,
`--browser chromium|firefox|webkit`, `--headed`/`--headless`, `--output DIR`,
`--budget`, `--scope`, `--min-coverage`, `--dry-run`, `--allow-external`.

Exit codes: `0` pass/pass-with-warnings · `1` gate fail or interrupted ·
`2` escalation/needs-human/config error · `130` keyboard interrupt.

### Desktop control center (Windows)

Double-click `QA_Agent.bat` (or run `python gui.py`). The GUI composes the same
CLI commands, streams the console, lets you stop a run, and renders the newest
valid report. It introduces no alternate execution path.

### Standalone Windows bundle

```bash
.venv/Scripts/python scripts/build_exe.py
```

Produces `dist/QA_Agent/` with a windowed `QA_Agent.exe` and a console
`qa-agent.exe`. Install browser engines once on the target with
`qa-agent.exe install-browsers`.

---

## CI/CD quality gates

`.github/workflows/ci-quality-gates.yml` runs on every push and pull request to
`main` (and on manual dispatch) across Python 3.11 and 3.12:

1. checkout and Python setup with pip cache;
2. install `requirements.txt` plus the editable `qa_agent` package;
3. verify dependency consistency with `pip check`;
4. install Playwright Chromium with system dependencies;
5. run **the complete pytest suite** with JUnit output;
6. upload `cv_metrics.json` and the JUnit report as build artifacts.

A failing test fails the workflow, so the suite can be used directly as a
required branch-protection check. The badge at the top of this README reflects
the latest run on `main`.

`cv_metrics.json` is the machine-readable snapshot of the local gate:

```json
{
  "total_tests": 295,
  "modules": ["llm_evals", "mcp_validator", "web_auditor", "data_gates"],
  "stack": ["Python", "Pytest", "Playwright", "Pydantic", "GitHub Actions"]
}
```

---

## Enterprise agent capabilities

- Read-only project discovery: framework, routes, APIs, forms, tests, auth,
  and risk flags.
- Requirements classified `explicit` / `inferred` / `unknown`; inferences are
  never presented as confirmed.
- Seven-axis risk scoring and risk-prioritized planning with stable test IDs.
- Traceability: `Requirement → Risk → Test → Execution → Evidence → Finding →
  Quality Gate`.
- Bounded execution: same-origin by default, page/request/depth/runtime/test
  budgets, no auto-reset after exhaustion.
- Defensive form exercise and accessibility heuristics.
- API interception for 4xx/5xx, malformed JSON, and invalid content types.
- Twelve-type failure taxonomy with transient-only retries (maximum three per
  failure signature); product/auth/config/test/data failures are not retried.
- Flaky detection reports PASS/FAIL oscillation without promoting it to a bug.
- Finding deduplication by six-field fingerprint with LOW/MEDIUM/HIGH
  confidence.
- Five-state quality gate and requirement-coverage engine.
- Human escalation with reason, attempts, evidence, and required input.
- Crash recovery finalizes interrupted runs as `INTERRUPTED` / `BLOCKED`.
- Atomic artifact writes and central redaction across logs and reports.
- Markdown, HTML, JSON reports plus Jira-compatible export.

### Safety model

Defaults are fail-closed:

- **Read-only discovery** — discovery never writes to the target.
- **Deny unknown** — cross-origin URLs and destructive path tokens are refused
  unless explicitly authorized.
- **Bounded execution** — every network action consumes a budget.
- **No destructive payloads** — form checks are synthetic and harmless.
- **No secret logging** — one redaction layer guards logs, evidence, manifests,
  and reports.
- **LLM boundary** — an LLM may propose, but proposals are validated and can
  only execute through the authorized executor.

Only test systems you own or have written permission to assess.

---

## Stack

- Python 3.11+
- Pytest (+ `pytest-asyncio`)
- Playwright (Chromium) and HTTPX
- Pydantic v2
- pandas
- Jinja2 reporting
- GitHub Actions
- tkinter desktop GUI and PyInstaller bundle (optional)

## Design principles

- **Offline-first:** CI never needs model credentials or third-party services.
- **Deterministic:** mocked LLM responses and fixed fixtures make failures
  reproducible.
- **Structured results:** gates return typed objects instead of print output.
- **Bounded autonomy:** execution limits and explicit escalation are part of
  the architecture, not afterthoughts.
- **Evidence over verdicts:** heuristic findings require human confirmation.

## Limitations

- RAG groundedness uses lexical claim support, not a semantic judge; it is a
  fast regression gate, not a substitute for human review.
- Label drift measures distribution shift, not causal data quality.
- Accessibility checks are heuristics and do not certify WCAG compliance.
- Coverage measures requirement-to-test mapping, not code coverage.
- The crawl surface is bounded; JavaScript-heavy SPAs may need higher budgets.
- No cloud integrations ship with the project. Live LLM evaluation is opt-in
  and requires environment credentials.

## License

MIT. See [LICENSE](LICENSE). Copyright (c) 2026 Gaetano (v0idbrn).
