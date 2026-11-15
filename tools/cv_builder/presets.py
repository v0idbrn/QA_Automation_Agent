# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Privacy-first profile and 5 role presets for the CV builder.

Contact PII is loaded from environment variables or an untracked .cv_private.json.
All presets encode Gaetano Morelli's verified background truthfully, dynamically
enriched with live metrics from the workspace snapshot.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "ContactInfo",
    "Preset",
    "load_private_profile",
    "build_presets",
    "PRESET_NAMES",
    "DEFAULT_SUMMARIES",
]

PRESET_NAMES = (
    "ai-sdet-en",
    "qa-ia-es",
    "qa-software-en",
    "qa-software-es",
    "python-automation-en",
)


@dataclass
class ContactInfo:
    email: str = ""
    phone: str = ""
    location: str = ""
    linkedin: str = ""
    github: str = ""
    portfolio: str = ""

    def to_dict(self) -> dict[str, str]:
        return {k: v for k, v in self.__dict__.items() if v}


@dataclass
class Preset:
    name: str
    language: str
    title: str
    professional_summary: str
    core_skills: list[str]
    experience_bullets: list[str]
    project_highlights: list[str]
    certifications: list[str]
    education: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "language": self.language,
            "title": self.title,
            "professional_summary": self.professional_summary,
            "core_skills": self.core_skills,
            "experience_bullets": self.experience_bullets,
            "project_highlights": self.project_highlights,
            "certifications": self.certifications,
            "education": self.education,
        }


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def load_private_profile(path: str | Path | None = None) -> ContactInfo:
    """Load contact PII from .cv_private.json or environment variables."""
    data: dict[str, str] = {}
    if path:
        p = Path(path)
    else:
        p = Path.cwd() / ".cv_private.json"
    if p.is_file():
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            data = {}
    env_map = {
        "email": "CV_EMAIL",
        "phone": "CV_PHONE",
        "location": "CV_LOCATION",
        "linkedin": "CV_LINKEDIN",
        "github": "CV_GITHUB",
        "portfolio": "CV_PORTFOLIO",
    }
    for key, env_key in env_map.items():
        if not data.get(key):
            data[key] = _env(env_key)
    return ContactInfo(**{k: data.get(k, "") for k in ContactInfo.__dataclass_fields__})


# ---------------------------------------------------------------------------
# Verified background facts (static, never hallucinated)
# ---------------------------------------------------------------------------

EDUCATION = [
    "Ongoing — Engineering in AI & Data Science, Universidad Nacional de Salta (UNSa)",
    "Electronics Technician, E.E.T. N° 3138 Albert Einstein",
    "Pearson Versant English Test — C2 (Proficient)",
]

CERTIFICATIONS = [
    "Google — Large Language Models (LLM) Certification",
    "Google — Responsible AI Certification",
]

EXPERIENCE = [
    {
        "role": "Python / AI / QA Engineering Consultant",
        "org": "CDA",
        "period": "2023 — present",
        "bullets": [
            "Designed and maintained a local-first AI-SDET framework (QA_Automation_Agent) with 726 deterministic tests across evals, security, e2e, data, and unit suites.",
            "Built Workhorse Edition: 7 client-facing audit engines (crawler, UX/a11y/perf, security+checkout, API fuzzing, self-healing locators, test generation, visual regression) + standalone HTML/Markdown reporter.",
            "Implemented LLM/RAG evaluation pipeline: groundedness, context precision/recall, agent-trace evals, safety, determinism, cost budgets; mock/live adapters for OpenAI-compatible endpoints.",
            "Delivered MCP tool schema validator + input sanitizer mapped to OWASP LLM Top 10 (LLM01/02/05/06).",
            "Automated CI/CD quality gates on GitHub Actions (Python 3.11/3.12, Playwright Chromium, JUnit evidence).",
        ],
    },
    {
        "role": "AI / LLM Quality Evaluator",
        "org": "Turing",
        "period": "2023 — 2024",
        "bullets": [
            "Evaluated LLM outputs for correctness, hallucination rate, instruction following, and safety across coding, reasoning, and creative tasks.",
            "Designed adversarial prompt suites and automated regression detection for model updates.",
            "Produced quantitative quality reports with statistical confidence intervals for stakeholder review.",
        ],
    },
    {
        "role": "Functional QA Engineer",
        "org": "Chicos.net",
        "period": "2022 — 2023",
        "bullets": [
            "Executed end-to-end functional testing for web and mobile educational platforms.",
            "Authored and maintained Playwright test suites; integrated with CI for nightly regression runs.",
            "Collaborated with product and dev on defect triage, root-cause analysis, and release gating.",
        ],
    },
]

PROJECTS_STATIC = [
    {
        "name": "QA_Automation_Agent",
        "desc": "Local-first AI-SDET + autonomous web QA agent: crawling, UX/a11y/perf (4 viewports), passive security, REST/GraphQL fuzzing, self-healing locators, visual regression, LLM/RAG evals, MCP guardrails, 726 tests, CI gates.",
        "tech": ["Python", "Pytest", "Playwright", "Pydantic", "HTTPX", "Pillow", "Jinja2", "GitHub Actions"],
        "metrics": {"tests": 726, "engines": 7, "cli_commands": 12},
    },
    {
        "name": "ConciliaPDF",
        "desc": "PDF reconciliation engine for financial documents: table extraction, fuzzy matching, multi-currency normalization, audit trail with SHA-256 evidence.",
        "tech": ["Python", "FastAPI", "Pandas", "PDF parsing", "Docker"],
    },
    {
        "name": "ExcelCleaner / Excel to PDF",
        "desc": "B2B automation pipelines: Excel/CSV normalization, schema validation, PII detection, PDF generation with reportlab.",
        "tech": ["Python", "Pandas", "openpyxl", "reportlab", "Pydantic"],
    },
    {
        "name": "VoleyOS / VolleyOS",
        "desc": "Android app (Kotlin/Jetpack Compose) for volleyball stats tracking; offline-first Room DB, WorkManager sync, FDroid build.",
        "tech": ["Kotlin", "Jetpack Compose", "Room", "Hilt", "Gradle", "Fastlane"],
    },
    {
        "name": "RiftLab",
        "desc": "Windows gaming utility (C#/WPF): real-time GPU/CPU overlay, fan curve automation, silent installers.",
        "tech": ["C#", "WPF", ".NET", "WMI", "NSIS"],
    },
    {
        "name": "ApexFOSS",
        "desc": "React Native / Expo mobile app with TypeScript; E2E tests via Detox, FDroid CI.",
        "tech": ["TypeScript", "React Native", "Expo", "Detox", "Fastlane"],
    },
    {
        "name": "MoneyFOSS",
        "desc": "Personal finance tracker (Next.js/React + TypeScript); Plaid integration, Prisma/PostgreSQL, CI/CD on Vercel.",
        "tech": ["Next.js", "React", "TypeScript", "Prisma", "PostgreSQL", "Tailwind"],
    },
    {
        "name": "Bussiness",
        "desc": "Python CLI tooling for business automation: PDF/Excel ETL, scraping, scheduled workflows.",
        "tech": ["Python", "Pandas", "Playwright", "APScheduler", "Typer"],
    },
]


# ---------------------------------------------------------------------------
# Preset definitions (will be enriched with live snapshot data)
# ---------------------------------------------------------------------------

DEFAULT_SUMMARIES = {
    "ai-sdet-en": (
        "AI-SDET & Quality Engineering specialist with 3+ years building deterministic "
        "evaluation pipelines for LLMs, RAG systems, and MCP toolchains. Author of "
        "QA_Automation_Agent (726 tests, 7 audit engines, CI gates on GitHub Actions). "
        "Expert in Playwright/Pytest CI/CD, semantic groundedness, context precision/recall, "
        "agent-trace evals, and OWASP LLM Top 10 guardrails. Google LLM & Responsible AI certified."
    ),
    "qa-ia-es": (
        "Ingeniero QA Sr. especializado en validación de LLMs, datasets y pipelines MLOps. "
        "Creador de QA_Automation_Agent (726 tests, 7 motores de auditoría, CI/CD en GitHub Actions). "
        "Experto en evaluación semántica (groundedness, precision/recall), seguridad MCP (OWASP LLM Top 10), "
        "y automatización Playwright/Pytest. Certificado Google LLM & Responsible AI. Pearson Versant C2."
    ),
    "qa-software-en": (
        "Full-Spectrum Software QA Automation Engineer: Web (Playwright), Mobile/APK (static manifest analysis), "
        "Desktop/CLI (contract probes + AST audit), REST/GraphQL APIs (boundary fuzzing + SLA), "
        "SQL integrity (DDL/SQLite constraint audit), Load testing (bounded concurrency + error-rate gates), "
        "Test Management (RTM, risk-based plans, JUnit health). 726 deterministic tests, zero-cloud architecture."
    ),
    "qa-software-es": (
        "QA Automation Engineer Full-Spectrum: Web (Playwright), Mobile/APK (análisis estático de manifiesto), "
        "Desktop/CLI (sondas de contrato + auditoría AST), APIs REST/GraphQL (fuzzing + SLA), "
        "Integridad SQL (auditoría DDL/SQLite), Pruebas de carga (concurrencia acotada + tasas de error), "
        "Gestión de Pruebas (RTM, planes basados en riesgo, salud JUnit). 726 tests deterministas, arquitectura zero-cloud."
    ),
    "python-automation-en": (
        "Python Automation Engineer: scraping, PDF/Excel ETL pipelines, B2B workflow automation. "
        "Built ConciliaPDF (financial PDF reconciliation), ExcelCleaner (schema validation + PII detection), "
        "Bussiness (scheduled workflows). Stack: Pandas, Playwright, FastAPI, reportlab, APScheduler, Pydantic. "
        "Upwork/consulting delivery with reproducible, auditable artifacts."
    ),
}

CORE_SKILLS = {
    "ai-sdet-en": [
        "LLM/RAG Evaluation (groundedness, precision/recall, safety, determinism)",
        "MCP Tool Security (OWASP LLM Top 10: LLM01/02/05/06)",
        "Playwright / Pytest CI/CD (GitHub Actions, 3.11/3.12 matrix)",
        "API Contract Fuzzing (REST/OpenAPI/GraphQL, p50/p95/p99 SLA)",
        "Self-Healing Locators (weighted DOM similarity)",
        "Visual Regression (Pillow pixel tolerance, ignore regions)",
        "Python 3.11+, Pydantic, HTTPX, Pandas, Jinja2",
        "Zero-Cloud Architecture, Local-First Privacy",
    ],
    "qa-ia-es": [
        "Evaluación de LLMs/RAG (groundedness, precision/recall, safety)",
        "Seguridad MCP (OWASP LLM Top 10: LLM01/02/05/06)",
        "Playwright / Pytest CI/CD (GitHub Actions, matriz 3.11/3.12)",
        "Fuzzing de Contratos API (REST/OpenAPI/GraphQL, SLA p50/p95/p99)",
        "Localizadores Auto-Reparables (similitud DOM ponderada)",
        "Regresión Visual (Pillow tolerancia de píxeles, regiones ignoradas)",
        "Python 3.11+, Pydantic, HTTPX, Pandas, Jinja2",
        "Arquitectura Zero-Cloud, Privacidad Local-First",
    ],
    "qa-software-en": [
        "Web QA: Playwright (multi-viewport 360/390/768/1440), WCAG 2.1 AA, Web Vitals",
        "Mobile QA: APK static analysis (permissions, exported components, debuggable, signatures)",
        "Desktop/CLI QA: Contract probes (--help/--version/unknown-flag) + AST audit (eval, shell, timeouts)",
        "API QA: REST/OpenAPI boundary fuzzing, GraphQL introspection/depth/alias probes, SLA gates",
        "SQL Integrity: DDL parsing, FK/index/money-type/NULL constraints, SQLite PRAGMA audit",
        "Load Testing: ThreadPoolExecutor bounded runs, p50/p95/p99, error-rate & 5xx gates",
        "Test Management: AST discovery (Python/JS), RTM, risk-based plans, JUnit XML health",
        "CI/CD: GitHub Actions (Python 3.11/3.12), Playwright Chromium, JUnit artifacts",
    ],
    "qa-software-es": [
        "QA Web: Playwright (multi-viewport 360/390/768/1440), WCAG 2.1 AA, Web Vitals",
        "QA Mobile: APK análisis estático (permisos, componentes exportados, debuggable, firmas)",
        "QA Desktop/CLI: Sondas contrato (--help/--version/flag-desconocida) + auditoría AST (eval, shell, timeouts)",
        "QA APIs: Fuzzing REST/OpenAPI, sondeos GraphQL introspección/profundidad/alias, puertas SLA",
        "Integridad SQL: Parsing DDL, FK/índice/tipo-dinero/NOT NULL, auditoría PRAGMA SQLite",
        "Pruebas Carga: ThreadPoolExecutor acotado, p50/p95/p99, puertas error-rate y 5xx",
        "Gestión Pruebas: Descubrimiento AST (Python/JS), RTM, planes por riesgo, salud JUnit XML",
        "CI/CD: GitHub Actions (Python 3.11/3.12), Playwright Chromium, artefactos JUnit",
    ],
    "python-automation-en": [
        "PDF/Excel ETL: table extraction, fuzzy matching, multi-currency normalization (ConciliaPDF)",
        "Schema Validation & PII Detection: Pandas gates (null, duplicate, label-drift, PII)",
        "Web Scraping & Browser Automation: Playwright, HTTPX, async patterns",
        "B2B Workflow Automation: APScheduler, Typer CLI, FastAPI services",
        "Report Generation: reportlab (PDF), python-docx (DOCX), Jinja2 templates",
        "Data Governance: SHA-256 evidence manifests, automatic redaction, local-first privacy",
        "CI/CD: GitHub Actions, Docker, pytest, pytest-asyncio",
        "Python 3.11+, Pydantic, Pandas, openpyxl, Pillow",
    ],
}

# Base experience bullets (will be re-ranked by JD matcher)
BASE_EXPERIENCE_BULLETS = {
    "ai-sdet-en": [
        "Built QA_Automation_Agent: 726 deterministic tests, 7 audit engines, CI gates (GitHub Actions, Python 3.11/3.12)",
        "Implemented LLM/RAG evaluation suite: groundedness, context precision/recall, agent-trace, safety, cost budgets",
        "Delivered MCP tool validator + sanitizer mapped to OWASP LLM Top 10 (LLM01/02/05/06)",
        "Designed Workhorse Edition: crawler, UX/a11y/perf (4 viewports), security+checkout, API fuzzing, self-healing, visual regression",
        "AI/LLM Quality Evaluator at Turing: adversarial prompt suites, hallucination detection, regression automation",
        "Functional QA at Chicos.net: Playwright E2E suites, CI integration, defect triage & release gating",
    ],
    "qa-ia-es": [
        "Creé QA_Automation_Agent: 726 tests deterministas, 7 motores de auditoría, CI/CD (GitHub Actions, Python 3.11/3.12)",
        "Implementé suite de evaluación LLM/RAG: groundedness, precision/recall de contexto, agent-trace, safety, presupuestos de coste",
        "Entregué validador + sanitizador MCP mapeado a OWASP LLM Top 10 (LLM01/02/05/06)",
        "Diseñé Workhorse Edition: crawler, UX/a11y/perf (4 viewports), security+checkout, API fuzzing, self-healing, visual regression",
        "AI/LLM Quality Evaluator en Turing: suites adversarias, detección de alucinaciones, automatización de regresiones",
        "Functional QA en Chicos.net: suites Playwright E2E, integración CI, triaje de defectos y gating de releases",
    ],
    "qa-software-en": [
        "Built QA_Automation_Agent: 726 tests, 7 engines covering Web, Mobile/APK, Desktop/CLI, API, SQL, Load, Test Mgmt",
        "Mobile QA: APK static analysis (permissions, exported components, debuggable, cleartext, signatures, target SDK)",
        "Desktop/CLI QA: Bounded contract probes + AST audit (eval/exec, shell=True, missing timeouts, bare except, GUI sleeps)",
        "API QA: REST/OpenAPI fuzzing (SQLi/XSS/type/oversize), GraphQL depth/alias/error-leak, p50/p95/p99 SLA gates",
        "SQL Integrity: DDL parsing (PK/FK/UNIQUE/NOT NULL), money-type float detection, SQLite PRAGMA audit (orphans, integrity)",
        "Load Testing: ThreadPoolExecutor bounded runs, configurable SLA/error-rate, 5xx/4xx classification",
        "Test Management: AST test discovery (Python def test_*, JS it/test), RTM coverage, risk-based plans, JUnit health",
        "Functional QA at Chicos.net: Playwright E2E, CI nightly runs, defect triage, release gating",
    ],
    "qa-software-es": [
        "Construí QA_Automation_Agent: 726 tests, 7 motores cubriendo Web, Mobile/APK, Desktop/CLI, API, SQL, Carga, Gestión",
        "QA Mobile: Análisis APK estático (permisos, componentes exportados, debuggable, cleartext, firmas, target SDK)",
        "QA Desktop/CLI: Sondas de contrato acotadas + auditoría AST (eval/exec, shell=True, timeouts faltantes, bare except, sleeps GUI)",
        "QA APIs: Fuzzing REST/OpenAPI (SQLi/XSS/tipo/oversize), GraphQL profundidad/alias/filtración-errores, puertas SLA p50/p95/p99",
        "Integridad SQL: Parsing DDL (PK/FK/UNIQUE/NOT NULL), detección money-type float, auditoría PRAGMA SQLite (huérfanos, integridad)",
        "Pruebas Carga: ThreadPoolExecutor acotado, SLA/error-rate configurable, clasificación 5xx/4xx",
        "Gestión Pruebas: Descubrimiento AST (Python def test_*, JS it/test), RTM cobertura, planes por riesgo, salud JUnit",
        "Functional QA en Chicos.net: Playwright E2E, CI nocturno, triaje defectos, gating de releases",
    ],
    "python-automation-en": [
        "Built ConciliaPDF: financial PDF reconciliation (table extraction, fuzzy matching, multi-currency, SHA-256 audit trail)",
        "Built ExcelCleaner/Excel-to-PDF: schema validation, PII detection, null/duplicate/label-drift gates, reportlab PDF generation",
        "Built Bussiness: scheduled workflows (APScheduler), Typer CLI, FastAPI services, Playwright scraping",
        "Python Automation Consultant at CDA: reproducible ETL pipelines, auditable artifacts, local-first privacy",
        "Data Governance: pandas gates (schema/null/duplicate/PII/label-drift), automatic redaction, evidence manifests",
        "CI/CD: GitHub Actions, Docker, pytest-asyncio, deterministic offline test suites",
    ],
}

CERTIFICATIONS_BY_PRESET = {
    "ai-sdet-en": CERTIFICATIONS + ["Pearson Versant English C2"],
    "qa-ia-es": CERTIFICATIONS + ["Pearson Versant English C2"],
    "qa-software-en": CERTIFICATIONS + ["Pearson Versant English C2"],
    "qa-software-es": CERTIFICATIONS + ["Pearson Versant English C2"],
    "python-automation-en": CERTIFICATIONS + ["Pearson Versant English C2"],
}

EDUCATION_BY_PRESET = {
    "ai-sdet-en": EDUCATION,
    "qa-ia-es": EDUCATION,
    "qa-software-en": EDUCATION,
    "qa-software-es": EDUCATION,
    "python-automation-en": EDUCATION,
}


def _enrich_with_snapshot(preset: Preset, snapshot: dict[str, Any] | None) -> Preset:
    if not snapshot:
        return preset
    # Add live project highlights from snapshot
    project_highlights = list(preset.project_highlights)
    for repo in snapshot.get("repos", []):
        if repo["name"] in {p["name"] for p in PROJECTS_STATIC}:
            continue
        if repo["test_count"] > 0 or repo["frameworks"]:
            highlight = f"{repo['name']}: {repo['test_count']} tests, {', '.join(repo['frameworks'][:5]) or 'no frameworks detected'}"
            project_highlights.append(highlight)
    # Update core skills with live framework mentions
    all_frameworks = set()
    for repo in snapshot.get("repos", []):
        all_frameworks.update(repo["frameworks"])
    core_skills = list(preset.core_skills)
    for fw in sorted(all_frameworks):
        if fw not in " ".join(core_skills):
            core_skills.append(fw)
    return Preset(
        name=preset.name,
        language=preset.language,
        title=preset.title,
        professional_summary=preset.professional_summary,
        core_skills=core_skills,
        experience_bullets=preset.experience_bullets,
        project_highlights=project_highlights,
        certifications=preset.certifications,
        education=preset.education,
    )


def build_presets(
    snapshot: dict[str, Any] | None = None,
    private_profile: ContactInfo | None = None,
) -> dict[str, Preset]:
    presets: dict[str, Preset] = {}
    for name in PRESET_NAMES:
        lang = "es" if name.endswith("-es") else "en"
        title_map = {
            "ai-sdet-en": "AI-SDET & Quality Engineering Specialist",
            "qa-ia-es": "Ingeniero QA Sr. — Validación IA/LLM & MLOps",
            "qa-software-en": "Full-Spectrum Software QA Automation Engineer",
            "qa-software-es": "QA Automation Engineer — Full-Spectrum (Web, Mobile, API, SQL, Performance, Gestión)",
            "python-automation-en": "Python Automation Engineer — Scraping, PDF/Excel ETL & B2B Workflows",
        }
        preset = Preset(
            name=name,
            language=lang,
            title=title_map[name],
            professional_summary=DEFAULT_SUMMARIES[name],
            core_skills=CORE_SKILLS[name],
            experience_bullets=BASE_EXPERIENCE_BULLETS[name],
            project_highlights=[p["desc"] for p in PROJECTS_STATIC],
            certifications=CERTIFICATIONS_BY_PRESET[name],
            education=EDUCATION_BY_PRESET[name],
        )
        presets[name] = _enrich_with_snapshot(preset, snapshot)
    return presets


def get_preset(name: str, snapshot: dict[str, Any] | None = None) -> Preset | None:
    presets = build_presets(snapshot)
    return presets.get(name)


def list_presets() -> list[str]:
    return list(PRESET_NAMES)