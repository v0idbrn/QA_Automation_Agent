# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Project discovery — READ-ONLY.

Inspects a local project directory or URL surface and produces a
structured ProjectProfile (from core.models). NEVER modifies the target.

Detects (when evidence exists locally):
  * language, framework, frontend/backend split
  * package manager + dependencies (top-N from requirements/package.json)
  * entry points (Python app/cli files; JS export-default files)
  * routes / API endpoints / forms detected (HTML <form> patterns)
  * test infrastructure (framework, E2E vs unit)
  * configuration files (.env, config.py, settings.py, etc.)
  * documentation surface (README, API specs)
  * authentication requirements (oauth/jwt/session/basic markers)
  * potential risk flags (hardcoded secrets, admin paths, file upload endpoints)
"""

from __future__ import annotations

import ast
import json as _json
import os
import re
from pathlib import Path
from typing import Any

from core.models import ProjectProfile, Project


_SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    "dist",
    "build",
    ".tox",
    ".mypy_cache",
    ".next",
    ".nuxt",
    "coverage",
    "htmlcov",
}

_FORM_RE = re.compile(r"<form\b", re.IGNORECASE)
_ALT_MISSING_IMG_RE = re.compile(r"<img\b(?![^>]*\balt=)", re.IGNORECASE)
_DUPE_ID_RE = re.compile(r'\bid=["\']([^"\']+)["\']')
_HARDCODED_SECRET_RE = re.compile(
    r"(?i)(password|token|api[-_ ]?key|secret)\s*[:=]\s*[\"'](?![\"']|\$\{|%\()[^\"'\s]{4,}[\"']"
)
_UPLOAD_RE = re.compile(r'type=["\']?file["\']?', re.IGNORECASE)
_ADMIN_PATH_RE = re.compile(r"(/admin|/dashboard-admin|/manage)", re.IGNORECASE)


def _iter_files(root: Path, suffix: str | None = None, *, max_files: int = 4096):
    count = 0
    for path in root.rglob("*"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        if suffix is not None and path.suffix != suffix:
            continue
        yield path
        count += 1
        if count >= max_files:
            return


def _looks_like_python(root: Path) -> bool:
    return any(
        p.exists()
        for p in (
            root / "pyproject.toml",
            root / "setup.py",
            root / "requirements.txt",
            root / "Pipfile",
        )
    ) or any(True for _ in _iter_files(root, ".py", max_files=32))


def _looks_like_node(root: Path) -> bool:
    return any(
        p.exists()
        for p in (
            root / "package.json",
            root / "pnpm-lock.yaml",
            root / "yarn.lock",
            root / "package-lock.json",
        )
    ) or (root / "node_modules").exists()


def _python_package_manager(root: Path) -> str:
    if (root / "pyproject.toml").exists():
        return "python/pyproject"
    if (root / "requirements.txt").exists():
        return "python/requirements"
    if (root / "Pipfile").exists():
        return "python/pipenv"
    if (root / "setup.py").exists():
        return "python/setup.py"
    return "unknown"


def _node_package_manager(root: Path) -> str:
    if (root / "pnpm-lock.yaml").exists():
        return "node/pnpm"
    if (root / "yarn.lock").exists():
        return "node/yarn"
    if (root / "package-lock.json").exists():
        return "node/npm"
    if (root / "package.json").exists():
        return "node/npm"
    return "unknown"


def _read_top_level_deps(root: Path, language: str) -> list[str]:
    deps: list[str] = []
    if language == "python":
        for fname in ("requirements.txt", "Pipfile", "pyproject.toml"):
            path = root / fname
            if not path.exists():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if fname == "requirements.txt":
                for line in text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    pkg = re.split(r"[<>=!~; \t]", line, maxsplit=1)[0].strip()
                    if pkg:
                        deps.append(pkg.lower())
            break
        return deps[:30]
    if language == "javascript":
        pkg = root / "package.json"
        if pkg.exists():
            try:
                data = _json.loads(pkg.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                data = {}
            if isinstance(data, dict):
                for key in ("dependencies", "devDependencies", "peerDependencies"):
                    section = data.get(key) or {}
                    if isinstance(section, dict):
                        deps.extend(f"{k}".lower() for k in section.keys())
        return deps[:30]
    return []


def _detect_framework(root: Path, language: str, deps: list[str]) -> tuple[str, str, str]:
    """Return (framework, frontend_detected, backend_detected)."""
    frontend = "unknown"
    backend = "unknown"
    framework = "unknown"
    if language == "python":
        d = {d.lower() for d in deps}
        if "django" in d:
            backend = "django"
            framework = "django"
        if "flask" in d:
            backend = "flask"
            framework = framework if framework != "unknown" else "flask"
        if "fastapi" in d:
            backend = "fastapi"
            framework = framework if framework != "unknown" else "fastapi"
        # Python UI deps
        if "streamlit" in d:
            frontend = "streamlit"
            framework = framework if framework != "unknown" else "streamlit"
        # Node-compat python
        if (root / "manage.py").exists():
            backend = "django"
            framework = "django"
    elif language == "javascript":
        d = {x.lower() for x in deps}
        if "next" in d or "next.js" in d or (root / "next.config.js").exists() or (root / "next.config.mjs").exists():
            framework = "nextjs"
            frontend = "nextjs"
        if "vite" in d:
            frontend = "vite" if frontend == "unknown" else frontend
            framework = framework if framework != "unknown" else "vite"
        if "react" in d:
            frontend = "react" if frontend == "unknown" else frontend
            framework = framework if framework != "unknown" else "react"
        if "vue" in d:
            frontend = "vue"
        if "angular" in d or (root / "angular.json").exists():
            frontend = "angular"
        if "express" in d:
            backend = "express"
            framework = framework if framework != "unknown" else "express"
    return framework, frontend, backend


def _collect_config_files(root: Path) -> list[str]:
    names = {
        ".env",
        ".env.example",
        ".env.local",
        "config.py",
        "settings.py",
        "config.yaml",
        "config.yml",
        "config.json",
        "settings.json",
        "settings.yaml",
        "settings.yml",
        "pyproject.toml",
        "package.json",
        "tsconfig.json",
        "jest.config.js",
        "pytest.ini",
        ".pylintrc",
        "tox.ini",
    }
    found: list[str] = []
    for path in _iter_files(root, max_files=2048):
        if path.name in names or path.name.startswith(".env"):
            found.append(str(path))
    return sorted(found)[:50]


def _detect_forms(root: Path) -> list[str]:
    """Detect HTML files containing <form> elements. Returns list of paths."""
    hits: list[str] = []
    for path in _iter_files(root):
        if path.suffix.lower() not in (".html", ".htm", ".jinja", ".jinja2", ".hbs", ".ejs", ".jsx", ".tsx", ".vue"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if _FORM_RE.search(text):
            hits.append(str(path))
        if len(hits) >= 256:
            break
    return hits


def _detect_test_framework(root: Path, language: str) -> str:
    if language != "python":
        if language == "javascript":
            for path in _iter_files(root, max_files=64):
                if path.name in {"jest.config.js", "vitest.config.js", "vitest.config.ts", "playwright.config.js", "playwright.config.ts"}:
                    return path.name.replace(".config.js", "").replace(".config.ts", "")
            return "unknown"
        return "unknown"
    found_pytest = False
    found_unittest = False
    for path in _iter_files(root, ".py", max_files=128):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if "import pytest" in text or "from pytest" in text:
            found_pytest = True
        if "import unittest" in text or "from unittest" in text:
            found_unittest = True
    if (root / "pytest.ini").exists() or (root / "pyproject.toml").exists():
        found_pytest = True
    if found_pytest:
        return "pytest"
    if found_unittest:
        return "unittest"
    return "unknown"


def _collect_test_files(root: Path, framework: str) -> list[str]:
    tests: list[str] = []
    for path in _iter_files(root):
        name = path.name
        if path.suffix == ".py":
            if framework == "pytest":
                if name.startswith("test_") or name.endswith("_test.py"):
                    tests.append(str(path))
            elif "test" in name.lower():
                tests.append(str(path))
        elif path.suffix in (".js", ".ts", ".jsx", ".tsx"):
            if ".test." in name or ".spec." in name or name.startswith("test."):
                tests.append(str(path))
    return sorted(tests)[:1024]


def _infer_python_routes(root: Path, routes: list[str], api_endpoints: list[str]) -> None:
    route_markers = (
        "@app.",
        "@router.",
        "@bp.",
        "@blueprint.",
        "@route(",
        "@get(",
        "@post(",
        "@put(",
        "@delete(",
        "@patch(",
        "add_url_rule(",
        "path(",
        "re_path(",
    )
    for path in _iter_files(root, ".py", max_files=256):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line in text.splitlines():
            stripped = line.strip()
            if any(stripped.startswith(m) for m in route_markers):
                routes.append(stripped[:240])
            # quoted literal containing /api/*
            if '"' in stripped or "'" in stripped:
                for qchar in ('"', "'"):
                    start = stripped.find(qchar)
                    while start != -1:
                        end = stripped.find(qchar, start + 1)
                        if end == -1:
                            break
                        candidate = stripped[start + 1 : end]
                        if (
                            candidate.startswith("/")
                            and len(candidate) < 200
                            and " " not in candidate
                            and ("api/" in candidate or candidate.startswith("/api") or candidate.startswith("/v1") or candidate.startswith("/v2"))
                        ):
                            if candidate not in api_endpoints:
                                api_endpoints.append(candidate)
                        start = stripped.find(qchar, end + 1)


def _infer_node_framework(root: Path) -> str:
    if (root / "next.config").exists() or (root / "next.config.js").exists() or (root / "next.config.mjs").exists():
        return "nextjs"
    if (root / "vite.config").exists() or (root / "vite.config.ts").exists() or (root / "vite.config.js").exists():
        return "vite"
    if (root / "angular.json").exists():
        return "angular"
    if (root / ".nuxt").exists() or (root / "nuxt.config").exists() or (root / "nuxt.config.ts").exists():
        return "nuxt"
    return "unknown"


def _detect_auth(root: Path) -> list[str]:
    hints: list[str] = []
    markers = {
        "oauth": ("oauth", "openid", "oidc"),
        "jwt": ("jwt", "bearer"),
        "session": ("session", "csrf", "cookie-session"),
        "basic": ("httpbasic", "basic auth", "basic-auth"),
        "api_key": ("x-api-key", "api_key", "apikey"),
    }
    scan_names = {
        "readme.md",
        ".env.example",
        "openapi.yaml",
        "openapi.json",
        "swagger.json",
    }
    for path in _iter_files(root, max_files=512):
        if not path.is_file():
            continue
        if (
            path.name.lower() not in scan_names
            and path.suffix not in {".py", ".ts", ".js", ".md", ".yml", ".yaml", ".json", ".env"}
            and not path.name.startswith(".env")
        ):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore").lower()
        except OSError:
            continue
        for name, tokens in markers.items():
            if any(token in text for token in tokens) and name not in hints:
                hints.append(name)
    return hints


def _collect_spec_files(root: Path) -> list[str]:
    names = {
        "readme.md",
        "readme",
        "openapi.yaml",
        "openapi.yml",
        "openapi.json",
        "swagger.yaml",
        "swagger.json",
        "swagger.yml",
        "api.md",
        "api.yaml",
        "api.yml",
    }
    found: list[str] = []
    for path in _iter_files(root, max_files=1024):
        if path.is_file() and path.name.lower() in names:
            found.append(str(path))
    return sorted(found)


def _detect_potential_risks(root: Path) -> list[str]:
    risks: list[str] = []
    html_forms = 0
    hardcoded_secret_hits = 0
    upload_fields = 0
    admin_paths = 0
    for path in _iter_files(root, max_files=1024):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if path.suffix.lower() in {".html", ".htm", ".jinja", ".jinja2", ".hbs", ".ejs", ".jsx", ".tsx", ".vue"}:
            if _FORM_RE.search(text):
                html_forms += 1
            if _UPLOAD_RE.search(text):
                upload_fields += 1
            if _ADMIN_PATH_RE.search(text):
                admin_paths += 1
        if path.suffix.lower() in {".py", ".js", ".ts", ".jsx", ".tsx", ".env"} and not path.name.endswith((".pyc",)):
            if _HARDCODED_SECRET_RE.search(text) and path.name not in {"__init__.py", "redaction.py", "security.py"}:
                hardcoded_secret_hits += 1
    if html_forms:
        risks.append(f"{html_forms} file(s) contain <form> elements")
    if upload_fields:
        risks.append(f"{upload_fields} file upload field(s) detected (requires scope.allow_uploads)")
    if admin_paths:
        risks.append(f"{admin_paths} admin-style path(s) detected")
    if hardcoded_secret_hits:
        risks.append(f"{hardcoded_secret_hits} potential hardcoded secret assignment(s) in source files")
    return risks


def discover_project(target: str | Path) -> ProjectProfile:
    """READ-ONLY project discovery. Never writes to `target`."""
    root = Path(target).resolve()
    if not root.exists():
        return ProjectProfile(
            project_id=f"proj_missing_{abs(hash(str(root))) % 100000:05d}",
            name=root.name or "missing-project",
            path=str(root),
            language="unknown",
            notes=["target does not exist locally"],
        )

    language = "unknown"
    package_manager = "unknown"
    framework = "unknown"
    frontend = "unknown"
    backend = "unknown"
    entry_points: list[str] = []
    routes: list[str] = []
    api_endpoints: list[str] = []

    if _looks_like_python(root):
        language = "python"
        package_manager = _python_package_manager(root)
        for path in _iter_files(root, ".py", max_files=512):
            if path.name in {"main.py", "app.py", "wsgi.py", "asgi.py", "manage.py", "cli.py", "run.py", "server.py"}:
                entry_points.append(str(path))
        _infer_python_routes(root, routes, api_endpoints)
    elif _looks_like_node(root):
        language = "javascript"
        package_manager = _node_package_manager(root)
        framework = _infer_node_framework(root)
        for path in _iter_files(root, max_files=512):
            if path.is_file() and path.suffix in {".js", ".ts", ".mjs", ".cjs"}:
                try:
                    text = path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                if "export default" in text or "export function" in text or "export const" in text:
                    entry_points.append(str(path))
                if len(entry_points) >= 128:
                    break
    else:
        try:
            entry_points = sorted(str(p) for p in root.iterdir() if p.is_file())[:32]
        except OSError:
            entry_points = []

    dependencies = _read_top_level_deps(root, language)
    framework_detected, frontend, backend = _detect_framework(root, language, dependencies)
    if framework == "unknown" and framework_detected != "unknown":
        framework = framework_detected

    test_framework = _detect_test_framework(root, language) if language in {"python", "javascript"} else "unknown"
    test_files = _collect_test_files(root, test_framework)
    has_e2e_tests = _has_e2e_tests(test_files)

    auth_mechanisms = _detect_auth(root)
    spec_files = _collect_spec_files(root)
    config_files = _collect_config_files(root)
    forms_detected = _detect_forms(root)
    potential_risks = _detect_potential_risks(root)

    return ProjectProfile(
        name=root.name or "local-project",
        path=str(root),
        language=language or "unknown",
        framework=framework or "unknown",
        frontend=frontend or "unknown",
        backend=backend or "unknown",
        package_manager=package_manager or "unknown",
        entry_points=sorted(set(entry_points)),
        test_framework=test_framework or "unknown",
        test_files=test_files,
        api_endpoints=sorted(set(api_endpoints)),
        routes=sorted(set(routes)),
        has_e2e_tests=has_e2e_tests,
        auth_mechanisms=auth_mechanisms,
        spec_files=spec_files,
        forms_detected=forms_detected,
        config_files=config_files,
        dependencies=dependencies,
        potential_risks=potential_risks,
    )


DiscoveredProject = ProjectProfile  # backward-compat alias


def _has_e2e_tests(test_files: list[str]) -> bool:
    """True when any discovered test file looks like end-to-end coverage."""
    return any(
        "e2e" in p.lower().replace("_", "").replace("-", "") or "endtoend" in p.lower()
        for p in (test_files or [])
    )
