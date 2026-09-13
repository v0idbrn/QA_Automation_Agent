# QA_Automation_Agent — persistent agent memory

Scope: local-first QA automation agent with zero-cloud data privacy.
Execution runtime: Playwright async, Pytest, Jinja2 reporting.
Context discipline: ECC-plan cycle adapted for QA automation workflows.

---

## Operative cycle (planned execution)

1. Plan — scope the QA target: page set, forms, visual assertions, report format.
2. Verify — confirm permissions, local environment, and that sensitive artifacts (env, screenshots, logs) stay out of version control.
3. Implement — build the core modules: crawler, form tester, visual auditor, report builder.
4. Review — inspect diffs before staging; enforce strict gitignore before any git add.
5. Test — run pytest to confirm the suite is clean.
6. Remember — promote repeat wins into skills/ and this AGENTS.md when they are worth reusing.
7. Improve — refine prompts, payloads, and report templates from real findings.

## Context discipline

- Keep the working context tight. Persist reusable decisions here rather than re-asking every session.
- Prefer local execution for any artifact that contains secrets, screenshots, traces, or logs.
- Never stage `.env`, `.venv`, `*.log`, `trace.zip`, screenshots, or rendered reports before confirming `.gitignore` coverage.
- Before every `git add`, inspect `git status` and confirm the diff contains only intentional files.

## Repo and deployment discipline

- Branch: main
- Remote: GitHub repo `QA_Automation_Agent` (created locally and pushed incrementally)
- Commit strategy: one commit and push per milestone so the public commit history shows the live construction process.
- Milestone order:
  - Hito 1: AGENTS.md
  - Hito 2: project scaffolding + strict .gitignore
  - Hito 3: requirements.txt + environment setup
  - Hito 4: core engines (crawler, form tester, visual auditor, report builder)
  - Hito 5: README.md B2B enterprise + verified pytest suite

## QA automation knowledge retained from inspection

Sources reviewed:
- `affaan-m/ECC` — agent harness performance optimization system with plan → test → implement → review → verify → remember → improve cycle, specialized agents, AgentShield security scanning, and rules/selective standards.
- `openai/skills` — catalog for Codex; noted as deprecated in favor of the current plugins path, but the skill-as-folder pattern (instructions + scripts + resources per task) is a useful local template.
- `github.com/trending` (daily / weekly / monthly) — current attention on context-window optimization, multi-agent coordination, sandboxing/agent isolation, and local-first tooling.

Practices extracted for this agent:
- Research before build; verify before implement; review before push.
- Treat skills as reusable, folder-shaped workflows rather than long ad-hoc prompts.
- Keep data local unless a push is explicitly intentional and reviewed.
- Track the build in public commits as a live development trace.

## Skills directory convention (local)

`skills/` may contain folder-shaped capabilities such as:
- `skills/broken-link-check/SKILL.md`
- `skills/form-boundary-test/SKILL.md`
- `skills/visual-audit/SKILL.md`

Each skill folder should hold:
- A short SKILL.md with purpose, inputs, outputs, and local privacy notes.
- Reusable scripts or helpers that stay inside the local environment.
- No hardcoded secrets; secrets live in `.env` and stay out of version control.

## Local privacy rules

- `.env` and `.venv/` must never enter version control.
- Screenshots, traces, logs, and rendered HTML reports are temporary by default and must stay out of the repo.
- Any network call that leaves the local machine must be intentional and reviewed before execution.

## Review cues before push

- `git status` clean of sensitive files
- `.gitignore` covering env, venv, cache, screenshots, logs, traces, and rendered reports
- README and tests ready for the current milestone
- Commit message follows conventional-changelog style for the change type
