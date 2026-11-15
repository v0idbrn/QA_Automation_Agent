# CV Builder — Workspace-Aware ATS Resume & Proposal Engine

A privacy-first, deterministic career automation package that builds tailored, recruiter-ready CVs and proposals from your **actual local repositories**. No cloud, no hallucination, no external dependencies beyond `reportlab` and `python-docx`.

## Features

- **Live Workspace Scanner** — Parses `cv_metrics.json`, `pyproject.toml`, `requirements.txt`, `package.json`, `.github/workflows/`, `README.md`, and AST test definitions (`def test_*`, `async def test_*`, JS/TS `it/test` blocks) across `QA_Automation_Agent` and all sibling repos in `../*`.
- **5 Role Presets** — `ai-sdet-en`, `qa-ia-es`, `qa-software-en`, `qa-software-es`, `python-automation-en` with truthful, verifiable background (UNSa AI Engineering, Electronics Technician, Pearson Versant C2, Google LLM/Responsible AI certs, CDA/Turing/Chicos.net experience).
- **ATS Keyword Matcher** — Exact match % against a curated technical dictionary, prints matched vs missing skills, re-ranks bullets and projects by relevance.
- **Optional LLM Tailoring** — `--ai` auto-discovers OpenAI-compatible keys from `GROQ_KEY`, `NVIDIA_KEY`, `MISTRAL_KEY`, `CEREBRAS_KEY`, `OPENROUTER_KEY`, `../.jarvis_7keys.json`, `.jarvis_7keys.json`, `.env` — **never commits or logs secrets**. Graceful deterministic fallback when offline.
- **Clean Renderers** — Single-column ATS-parseable PDF (reportlab) + editable DOCX (python-docx), `--one-page` compact (default) or `--detailed` 2-page, clickable links, UTF-8 Spanish accents, zero orphan headers.
- **Deterministic Tests** — 30+ offline unit tests in `tests/unit/test_cv_builder.py` covering scanner, presets, ATS scoring, PII/secret non-leakage, mocked `--ai`, valid PDF/DOCX generation.

## Installation

```bash
pip install -e .  # installs qa_agent + reportlab + python-docx
# or
pip install reportlab>=4.0.0 python-docx>=1.1.0
```

## Quick Start

```bash
# Scan workspace and generate all 5 preset CVs (PDF + DOCX)
python -m tools.cv_builder --preset all --workspace-dir ..

# Tailor a specific preset to a job description (deterministic)
python -m tools.cv_builder --preset ai-sdet-en --jd job.txt --workspace-dir ..

# Tailor with optional LLM (auto-discovers key from env/keyfiles)
python -m tools.cv_builder --preset ai-sdet-en --jd job.txt --ai --workspace-dir ..

# Scan only (produces tools/cv_builder/workspace_snapshot.json)
python -m tools.cv_builder --scan-only --workspace-dir ..
```

## Privacy

- **Contact PII** (`email`, `phone`, `location`, `linkedin`, `github`, `portfolio`) is read from **environment variables** (`CV_EMAIL`, `CV_PHONE`, etc.) or an untracked `.cv_private.json` file.
- **`.cv_private.json`**, `output_cvs/`, `tools/cv_builder/workspace_snapshot.json`, and any local keyfiles (`.jarvis_7keys.json`, `.env`) are **gitignored** by default.
- **No secrets are ever logged or committed**. The `--ai` key discovery runs in-memory only.
- **Snapshot sanitization** replaces absolute paths with repo names only (`sanitize_snapshot()`).

## Presets

| Preset | Language | Target Role |
|--------|----------|-------------|
| `ai-sdet-en` | English | AI-SDET, LLM/RAG Evals, MCP Security, Playwright/Pytest CI/CD |
| `qa-ia-es` | Spanish | Sr. QA Engineer IA, Validación LLMs/Datasets, APIs & MLOps |
| `qa-software-en` | English | Full-Spectrum Software QA (Web, Mobile/APK, Desktop/CLI, REST/GraphQL, SQL, Load, Test Mgmt) |
| `qa-software-es` | Spanish | QA Automation Engineer (Web, Mobile, APIs, SQL, Performance, Gestión de Pruebas/RTM) |
| `python-automation-en` | English | Python Automation, Scraping, PDF/Excel ETL & B2B Workflows (Upwork/Consulting) |

## Output

```
output_cvs/
├── ai-sdet-en.pdf
├── ai-sdet-en.docx
├── ai-sdet-en_proposal.md      # (when --jd provided)
├── qa-software-en.pdf
├── qa-software-en.docx
└── ...
```

## Architecture

```
tools/cv_builder/
├── __init__.py           # Package exports
├── __main__.py           # python -m tools.cv_builder entrypoint
├── cli.py                # Argument parsing & orchestration
├── workspace_scanner.py  # Repo discovery + manifest parsing + AST test extraction
├── presets.py            # 5 role presets + private profile loader
├── jd_tailor.py          # ATS keyword matching + bullet/project re-ranking + LLM tailoring
├── renderers.py          # PDF (reportlab) + DOCX (python-docx) renderers
└── README.md             # This file
```

## Testing

```bash
pytest tests/unit/test_cv_builder.py -v
# 30+ deterministic tests, no network, no browser
```

## Integration with QA_Automation_Agent

This package lives under `tools/cv_builder/` so the **root `README.md` stays focused on the enterprise QA platform** — hiring managers see a pure engineering product. The CV builder is a separate, self-contained module that demonstrates the same quality-engineering practices (deterministic tests, privacy-first, CI gates) that the main agent embodies.

## License

MIT — see `LICENSE` in the repository root.