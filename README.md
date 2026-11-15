# QA Automation Agent — AI-SDET & Quality Engineering Framework

[![CI Quality Gates](https://github.com/v0idbrn/QA_Automation_Agent/actions/workflows/ci-quality-gates.yml/badge.svg?branch=main)](https://github.com/v0idbrn/QA_Automation_Agent/actions/workflows/ci-quality-gates.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Pytest](https://img.shields.io/badge/tests-824%20passing-3ecf8e)](#quality-suites)
[![License: MIT](https://img.shields.io/badge/license-MIT-4da3ff)](LICENSE)

A local-first quality-engineering framework that combines deterministic
AI-SDET gates with an autonomous web QA agent. It demonstrates enterprise
practices for **LLM evaluation, RAG groundedness, MCP tool security, API
contract testing, Playwright layout auditing, dataset governance, and CI/CD
quality gates** — without sending target data to a cloud service.

The **Full-Spectrum v2.0** adds twelve client-facing audit engines (bounded
crawler, multi-viewport UX/a11y/Web-Vitals profiler, passive security +
checkout integrity, REST/GraphQL fuzzing with latency SLAs, self-healing
locators, generated Playwright suites, Pillow visual regression, APK static
analysis, PWA installability, CLI contract probes, RBAC/Workflow integrity,
SQLite/DDL constraint audit, bounded load testing, test inventory/RTM/planning)
plus a standalone executive reporter, a single `python -m qa_agent` CLI, and a
workspace-aware ATS CV builder (`tools/cv_builder/`).

> 🇪🇸 Spanish translation: [README.es.md](README.es.md).

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
├── src/qa_agent/                  # Deterministic AI-SDET framework + Full-Spectrum engines
│   ├── cli.py / __main__.py       # `python -m qa_agent audit|fuzz-api|gen-tests|
│   │                              #  visual-diff|eval-rag|audit-apk|audit-pwa|test-cli|
│   │                              #  audit-rbac|audit-workflow|audit-db|load-test|gen-test-plan`
│   ├── models.py                  # Shared Finding/Severity contract
│   ├── redaction.py               # Local `[REDACTED]` layer for URLs, texts, headers
│   ├── crawler.py                 # Bounded same-origin BFS/DFS crawl: links, assets,
│   │                              # console/page errors, XHR failures, redirect loops
│   ├── ux_a11y_perf.py            # 360/390/768/1440 viewports, WCAG 2.1 AA,
│   │                              # tap targets, overlays, TTFB/FCP/LCP/CLS
│   ├── security_checkout.py       # Passive headers/CSP/HSTS/CORS/cookies/sourcemaps/
│   │                              # secrets + cart & idempotency integrity
│   ├── api_fuzzer.py              # REST/OpenAPI boundary fuzzing, GraphQL probes,
│   │                              # p50/p95/p99 latency vs SLA
│   ├── self_healing.py            # Weighted DOM-similarity locator recovery
│   ├── test_generator.py          # Runnable Pytest+Playwright E2E generator
│   ├── visual_regression.py       # Pillow pixel tolerance, ignore regions, diff PNG
│   ├── reporter.py                # Standalone HTML + Markdown + SHA-256 manifest
│   ├── llm_evals.py               # Mock/live LLM adapters, RAG groundedness,
│   │                              # semantic + context + agent + safety evals
│   ├── mcp_validator.py           # MCP tool-call schema + input sanitizer,
│   │                              # mapped to OWASP LLM Top 10
│   ├── web_auditor.py             # HTTPX contract checks + Playwright console
│   │                              # and mobile-overflow auditing
│   ├── data_gates.py              # Schema, null, duplicate, PII, and label-drift
│   │                              # gates over pandas DataFrames
│   ├── mobile_qa.py               # APK static analysis (permissions, exported
│   │                              # components, debuggable, signatures, SDK) +
│   │                              # PWA installability audit (manifest, icons, SW)
│   ├── desktop_cli_qa.py          # Bounded CLI contract probes (--help/--version/
│   │                              # unknown-flag) + static AST desktop audit
│   ├── functional_qa.py           # RBAC matrix audit (over-privilege, gaps) +
│   │                              # workflow/state-machine integrity (dead ends, unreachable)
│   ├── db_qa.py                   # DDL parsing (PK/FK/UNIQUE/NOT NULL), money-type
│   │                              # float detection, SQLite PRAGMA audit (orphans, integrity)
│   ├── performance_qa.py          # ThreadPoolExecutor bounded load runs, p50/p95/p99
│   │                              # latency, error-rate/5xx gates
│   └── test_management.py         # AST test discovery (Python/JS), RTM coverage,
│                                  # risk-based test plans, JUnit XML health
├── tools/cv_builder/              # Workspace-aware ATS CV & Proposal builder
│   ├── workspace_scanner.py       # Sibling-repo discovery, manifest parsing, AST tests
│   ├── presets.py                 # 5 role presets + private profile (PII from env/file)
│   ├── jd_tailor.py               # ATS keyword match %, bullet/project re-rank, LLM tailor
│   ├── renderers.py               # reportlab PDF + python-docx DOCX (one-page/detailed)
│   └── cli.py                     # `python -m tools.cv_builder --preset all --jd job.txt --ai`
├── tests/
│   ├── evals/                     # LLM/RAG + semantic/context/agent/safety evals
│   ├── security/                  # MCP guardrails
│   ├── e2e/                       # HTTPX/Playwright audits + Workhorse live suite
│   ├── data/                      # Dataset-governance gates
│   ├── unit/                      # Pure offline tests for every engine (+ cv_builder)
│   ├── fixtures/vulnerable_saas_fixture.py  # Seeded-defect local target
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
│   └── ci-quality-gates.yml       # Push/PR quality gate on Python 3.11/3.12
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

Workhorse client audit (one command):

url ──► crawl ──► UX/a11y/vitals ──► passive security ──► findings
                                                           │
  audit_report.html ◄── bug_report.md ◄── SHA-256 manifest ◄┘
```

---

## Quality suites

`pytest.ini` makes `src/` importable and limits discovery to `tests/`. The
repository suite is **824 passing tests** in roughly 60 seconds, fully offline
except for local browser audits against a loopback fixture.

| Suite | Tests | Focus |
|---|---:|---|
| `tests/unit/test_models_redaction.py` | 23 | Finding contract, severity ordering, central redaction |
| `tests/unit/test_crawler_helpers.py` | 40 | URL normalization, same-origin, assets, link/asset extraction, config bounds |
| `tests/unit/test_ux_a11y_perf.py` | 67 | Colour math, layout defects, WCAG AA, Web Vitals budgets |
| `tests/unit/test_security_checkout.py` | 63 | Headers, CSP, cookies, CORS, secrets, stacktraces, cart/idempotency |
| `tests/unit/test_api_fuzzer.py` | 53 | Payload catalog, OpenAPI parsing, classification, GraphQL, latency/SLA |
| `tests/unit/test_self_healing_generator.py` | 43 | Similarity scoring, selector patches, generated-module correctness |
| `tests/unit/test_visual_regression.py` | 25 | Pixel tolerance, ignore regions, bbox/shift, diff and side-by-side output |
| `tests/unit/test_reporter_cli.py` | 35 | HTML/Markdown escaping, manifest hashing, CLI parsing and exit codes |
| `tests/unit/test_full_spectrum_qa.py` | 53 | Mobile/APK, PWA, CLI/desktop, RBAC, workflow, DB, load, test mgmt |
| `tests/unit/test_cv_builder.py` | 45 | Workspace scanner, presets, ATS matching, PII safety, LLM mock, PDF/DOCX |
| `tests/evals/test_llm_rag.py` | 28 | LLM adapters, RAG groundedness, structured output, prompt regression, budgets |
| `tests/evals/test_semantic_evals.py` | 60 | TF-IDF similarity, context precision/recall, agent traces, safety, cost |
| `tests/security/test_mcp_guardrails.py` | 55 | Tool schemas, sanitization, traversal, command injection, SSRF, prompt injection |
| `tests/e2e/test_web_api_audit.py` | 20 | HTTP contracts, error envelopes, console errors, mobile overflow, ASGI transport |
| `tests/e2e/test_workhorse_live.py` | 22 | Live crawl/UX/security/fuzz/generator/report run against the fixture |
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
- `semantic_similarity()` / `evaluate_semantic_groundedness()` — pure-Python
  TF-IDF char+word n-gram cosine that catches paraphrased hallucinations and
  mutated numbers offline.
- `evaluate_context_precision()` / `evaluate_context_recall()` — retrieval
  quality against known-relevant chunks.
- `evaluate_agent_trace()` — multi-agent loop, ping-pong handoff, missing-agent,
  and redundant tool-call detection.
- `evaluate_determinism()`, `evaluate_safety()` (PII/toxicity/bias),
  `evaluate_cost_budget()`, and an optional `evaluate_with_judge()`.

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

### 5. Bounded crawler

`crawler.py` drives one Chromium session per crawl (BFS or DFS), strictly
same-origin by default, with page/depth budgets. Per page it records status,
title, links, assets, interactive elements, console errors, uncaught page
errors, failed XHR, redirect chains, mixed content, broken links and broken
assets. Every URL passes through `redaction.redact_url` before it enters the
report, and a `CrawlReport` is serializable JSON with a severity gate.

### 6. Multi-viewport UX, WCAG 2.1 AA, and Web Vitals

`ux_a11y_perf.py` profiles the four real device widths (**360×800, 390×844,
768×1024, 1440×900**) and reports:

- horizontal overflow, clipped controls, overlapping interactive elements;
- touch targets below 44×44 CSS px;
- fixed/sticky overlays that cover the viewport or intercept clicks;
- missing `lang`, `alt`, labels, button names, heading skips, invalid ARIA;
- inline-style contrast below AA (4.5:1, 3:1 for large text);
- TTFB, FCP, LCP, CLS, DOM node bloat, JS and image payload budgets.

Pure functions (`analyze_layout`, `audit_accessibility`, `analyze_vitals`)
take captured snapshots, so the whole matrix is unit-testable without a
browser.

### 7. Passive security and checkout integrity

`security_checkout.py` performs **read-only** checks: CSP quality, HSTS
max-age, X-Frame-Options/frame-ancestors, nosniff, Referrer-Policy, CORS
wildcard-with-credentials, cookie `Secure`/`HttpOnly`/`SameSite`, exposed
source maps, mixed content, stacktrace leakage, and credential-shaped strings
in served HTML/JS (values are never echoed). The checkout analyzers cover
negative/zero/fractional quantities, negative/zero prices, float precision,
currency allow-lists, server-side total recomputation, and idempotency-key
replay divergence.

### 8. REST/GraphQL fuzzing and latency SLAs

`api_fuzzer.py` derives endpoints from an OpenAPI 3 document or explicit
paths, then sends a bounded catalog of empty, Unicode, SQL-metacharacter, XSS,
type-confusion, and oversized payloads. The verdict is behavioural: a clean
4xx is a pass, a 500 or a reflected payload is a defect. Missing-auth probes
and GraphQL introspection/depth/alias/error-leak probes are included, and
every case feeds p50/p95/p99, throughput, and SLA-breach reporting.

### 9. Self-healing locators, generated suites, visual diff, reports

- `self_healing.py` scores candidates against the original signature across
  test id, role, text, name, placeholder, tag, and parent, then returns a
  confidence score plus a resilient Playwright patch.
- `test_generator.py` emits self-contained Pytest+Playwright modules using
  `get_by_role` / `get_by_test_id` / `get_by_label`, plus title, visibility,
  390×844 overflow, and API assertions.
- `visual_regression.py` diffs with Pillow: pixel tolerance, ignore regions,
  bounding box, structural shift, red-highlight diff PNG, side-by-side sheet.
- `reporter.py` writes a standalone HTML executive report (inline CSS/JS,
  severity filters), a Markdown bug report, and a SHA-256 evidence manifest.
  All free text is HTML-escaped and redacted.

The seeded fixture `tests/fixtures/vulnerable_saas_fixture.py` is a loopback
`ThreadingHTTPServer` with deliberate defects: missing lang/alt/labels, low
contrast, mobile overflow, a cookie wall, a broken link and asset, console and
page errors, weak cookies, absent security headers, a client-side fake key, a
500 on SQL input, reflected XSS, a non-idempotent checkout, and an open
GraphQL endpoint.

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

### Workhorse client-audit CLI

A second, self-contained entry point lives in the installable package. It has
no dependency on the autonomous agent loop and works after
`pip install -e .` or directly via `python -m qa_agent`.

```bash
python -m qa_agent audit <url> --out-dir reports/audit            # crawl + UX + security + report
python -m qa_agent fuzz-api <url|openapi.json> --endpoint /api/validate --sla-ms 500
python -m qa_agent gen-tests <url> --out generated_tests --max-pages 3
python -m qa_agent visual-diff baseline.png current.png --out reports/visual/diff.png
python -m qa_agent eval-rag dataset.json --min-score 0.6 --min-recall 0.8

# Full-Spectrum v2.0 additions:
python -m qa_agent audit-apk <path/to/app.apk> --out-dir reports/apk
python -m qa_agent audit-pwa <build-dir|https://url> --out-dir reports/pwa
python -m qa_agent test-cli -- python -m mycli --out-dir reports/cli
python -m qa_agent audit-rbac matrix.json --out-dir reports/rbac
python -m qa_agent audit-workflow transitions.json --out-dir reports/workflow
python -m qa_agent audit-db <schema.sql|app.db> --out-dir reports/db
python -m qa_agent load-test https://api.example.com --requests 50 --concurrency 10 --sla-ms 800
python -m qa_agent gen-test-plan <repo-root> --requirements reqs.json --junit junit.xml
```

Each command prints one JSON summary line and writes artifacts under
`--out-dir`. Exit codes match the agent: `0` gate passed · `1` findings
breached the gate · `2` the command could not run.

`audit` produces the client deliverables:

```text
reports/audit/
├── audit_report.html   # standalone executive report, inline CSS/JS
├── bug_report.md       # severity-ordered, reproducible findings
├── manifest.json       # SHA-256 + byte size per artifact
└── evidence/           # optional screenshots copied in
```

Useful flags: `--auth-state storage.json`, `--max-pages`, `--max-depth`,
`--strategy bfs|dfs`, `--no-ux`, `--no-security`, `--ignore x,y,w,h`.

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
  "total_tests": 824,
  "modules": [
    "api_fuzzer",
    "cli",
    "crawler",
    "data_gates",
    "db_qa",
    "desktop_cli_qa",
    "functional_qa",
    "llm_evals",
    "mcp_validator",
    "mobile_qa",
    "performance_qa",
    "reporter",
    "security_checkout",
    "self_healing",
    "test_generator",
    "test_management",
    "ux_a11y_perf",
    "visual_regression",
    "web_auditor"
  ],
  "cli": [
    "audit",
    "audit-apk",
    "audit-db",
    "audit-pwa",
    "audit-rbac",
    "audit-workflow",
    "eval-rag",
    "fuzz-api",
    "gen-test-plan",
    "gen-tests",
    "load-test",
    "test-cli",
    "visual-diff"
  ],
  "stack": [
    "Python",
    "Pytest",
    "Playwright",
    "Pydantic",
    "HTTPX",
    "Pillow",
    "GitHub Actions",
    "reportlab",
    "python-docx"
  ]
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
- Pillow (visual regression)
- Jinja2 reporting
- GitHub Actions
- tkinter desktop GUI and PyInstaller bundle (optional)
- reportlab (PDF rendering) and python-docx (DOCX rendering)

## Design principles

- **Offline-first:** CI never needs model credentials or third-party services.
- **Deterministic:** mocked LLM responses and fixed fixtures make failures
  reproducible.
- **Structured results:** gates return typed objects instead of print output.
- **Bounded autonomy:** execution limits and explicit escalation are part of
  the architecture, not afterthoughts.
- **Evidence over verdicts:** heuristic findings require human confirmation.

## Limitations

- RAG groundedness combines lexical claim support with a TF-IDF semantic
  similarity gate; it catches paraphrase and number mutation but is not a
  substitute for human review.
- Label drift measures distribution shift, not causal data quality.
- Accessibility and layout checks are heuristics and do not certify WCAG
  compliance.
- Coverage measures requirement-to-test mapping, not code coverage.
- The crawl surface is bounded; JavaScript-heavy SPAs may need higher budgets.
- Self-healing proposes locators with a confidence score; recovered selectors
  should be reviewed before they are committed back into the suite.
- Fuzzing payloads are validation probes, not exploit chains.
- No cloud integrations ship with the project. Live LLM evaluation is opt-in
  and requires environment credentials.

## License

MIT. See [LICENSE](LICENSE). Copyright (c) 2026 Gaetano (v0idbrn).
