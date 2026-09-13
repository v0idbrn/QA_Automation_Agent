# Autonomous QA Engineer & Bug Reporting Agent (Enterprise Edition)

Local-first autonomous QA agent for interface crawling, defensive form fuzzing,
accessibility (WCAG) checks, API traffic interception, and executive reporting
with Jira-compatible bug ticket export.

Designed for teams that want repeatable QA coverage without sending page content,
screenshots, logs, or reports outside the local environment unless explicitly
intended.

## Legal & Compliance

- License: MIT. See `LICENSE`.
- Copyright (c) 2026 Gaetano (v0idbrn).
- This tool is an auditing framework, not an authorization tool. Only run it
  against targets you own or have explicit written permission to test.
- By using this project, you accept full responsibility for ensuring that any
  crawl, scan, or payload injection complies with applicable laws, contracts,
  and site terms of service.

## Capabilities Checklist

- End-to-end async crawling with Playwright
- HTTP status and navigation failure capture (4xx/5xx, timeouts, errors)
- Uncaught JavaScript console error capture
- Defensive form fuzzing with boundary and synthetic payloads
- Basic WCAG-focused accessibility inspection (alt text, ARIA roles,
  heading hierarchy)
- API/network request interception for backend error spotting
- Visual evidence capture on failures
- Jinja2-based executive reports in Markdown and HTML
- Jira-compatible bug ticket export

## Architecture

```text
QA_Automation_Agent
├── core/
│   ├── crawler.py        # async Playwright crawler + console/network findings
│   ├── form_tester.py    # boundary + synthetic payload fuzzer
│   ├── a11y_auditor.py   # accessibility DOM checks + visual evidence
│   ├── api_auditor.py    # background request/response interceptor
│   └── report_builder.py # Jinja2 Markdown/HTML reports + Jira export
├── tests/
│   ├── test_crawler.py
│   ├── test_form_tester.py
│   ├── test_a11y.py
│   └── test_report_builder.py
├── skills/               # extensible skill folders (local-first)
├── samples/              # sample targets/pages for local validation
├── reports/              # report templates and generated outputs
├── LICENSE
├── README.md
├── AGENTS.md
├── requirements.txt
└── .gitignore
```

## Quickstart

Requirements:
- Python 3.10+
- Node.js runtime available for Playwright browsers

Setup:
```bash
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\playwright install chromium
```

Run tests:
```bash
.venv\Scripts\pytest
```

## Configuration Principles

- Keep secrets out of version control. `.env` and `.venv/` are ignored.
- Keep evidence local by default. Screenshots, traces, logs, and rendered
  reports are excluded from the repository.
- Review before push. Inspect `git status` before staging anything.

## Enterprise Use Notes

- This project is intended for repeatable QA workflows, not for blind
  exploration of external systems.
- Treat every finding as evidence, not as a verdict. Validate failed requests,
  console errors, and accessibility warnings in context.
- If you integrate Jira export, sanitize or redact any sensitive URL,
  payload, or environment-specific detail before sharing externally.
