# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Workspace & sibling-repo scanner for the CV builder.

Discovers local repositories, parses manifests (pyproject.toml, requirements.txt,
package.json, cv_metrics.json, README.md, .github/workflows), extracts test
definitions via AST/regex, and produces a sanitized JSON snapshot.
"""

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

__all__ = [
    "DEFAULT_IGNORE_DIRS",
    "RepoFacts",
    "WorkspaceSnapshot",
    "load_cv_metrics",
    "load_pyproject",
    "load_requirements",
    "load_package_json",
    "load_readme",
    "load_github_workflows",
    "extract_python_tests",
    "extract_js_tests",
    "scan_repo",
    "scan_workspace",
    "sanitize_snapshot",
    "write_snapshot",
]

DEFAULT_IGNORE_DIRS = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "build",
        "dist",
        ".next",
        "android-sdk",
        "coverage",
        "htmlcov",
        ".expo",
        ".tooling",
        "fastlane",
        "metadata",
        "plugins",
        "stubs",
        "assets",
        "docs",
        "marketing",
        "demo_portfolio",
        "demo_scripts",
        "graphify-out",
        ".freebuff",
        ".claude",
        ".agents",
        ".opencode",
        ".tmp",
        "PRIVATE_APK",
        "voleyos-creator-unlocked-apk",
    }
)

_TEST_FUNCTION_RE = re.compile(r"^\s*(?:async\s+)?def\s+(test_[a-zA-Z0-9_]+)\s*\(")
_JS_TEST_RE = re.compile(
    r"""\b(?:it|test)(?:\.(?:only|skip|each\([^)]*\)|concurrent))?\s*\(\s*['"`]([^'"`]{1,160})['"`]"""
)
_PYTHON_FILE_SUFFIXES = {".py"}
_JS_FILE_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
_MANIFEST_FILES = {
    "pyproject.toml",
    "requirements.txt",
    "package.json",
    "cv_metrics.json",
    "README.md",
    "README.es.md",
}


@dataclass
class RepoFacts:
    name: str
    path: str
    languages: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    test_count: int = 0
    python_tests: int = 0
    js_tests: int = 0
    ci_matrix: list[str] = field(default_factory=list)
    has_cv_metrics: bool = False
    has_pyproject: bool = False
    has_requirements: bool = False
    has_package_json: bool = False
    has_github_workflows: bool = False
    readme_preview: str = ""
    security_features: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class WorkspaceSnapshot:
    root: str
    repos: list[RepoFacts] = field(default_factory=list)
    generated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"root": self.root, "repos": [repo.to_dict() for repo in self.repos], "generated_at": self.generated_at}


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def load_cv_metrics(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        return json.loads(_read_text(path))
    except json.JSONDecodeError:
        return {}


def load_pyproject(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except (tomllib.TOMLDecodeError, OSError):
        return {}


def load_requirements(path: Path) -> list[str]:
    if not path.is_file():
        return []
    lines = []
    for line in _read_text(path).splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            lines.append(line.split()[0])
    return lines


def load_package_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        return json.loads(_read_text(path))
    except json.JSONDecodeError:
        return {}


def load_readme(path: Path) -> str:
    return _read_text(path)[:2000] if path.is_file() else ""


def load_github_workflows(root: Path) -> list[dict[str, Any]]:
    workflows_dir = root / ".github" / "workflows"
    if not workflows_dir.is_dir():
        return []
    workflows = []
    for wf in workflows_dir.glob("*.yml"):
        try:
            import yaml

            workflows.append({"file": wf.name, "content": yaml.safe_load(_read_text(wf))})
        except Exception:
            workflows.append({"file": wf.name, "content": {}})
    return workflows


def _infer_frameworks(pyproject: dict[str, Any], requirements: list[str], package_json: dict[str, Any]) -> list[str]:
    frameworks: set[str] = set()
    deps = set(requirements)
    deps.update(pyproject.get("project", {}).get("dependencies", []))
    deps.update(pyproject.get("project", {}).get("optional-dependencies", {}).get("test", []))
    dep_map = {
        "pytest": "Pytest",
        "playwright": "Playwright",
        "fastapi": "FastAPI",
        "pydantic": "Pydantic",
        "pandas": "Pandas",
        "sqlalchemy": "SQLAlchemy",
        "httpx": "HTTPX",
        "beautifulsoup4": "BeautifulSoup",
        "pillow": "Pillow",
        "jinja2": "Jinja2",
        "pyinstaller": "PyInstaller",
        "pyside6": "PySide6",
        "pyqt5": "PyQt5",
        "pyqt6": "PyQt6",
        "wxpython": "wxPython",
        "kivy": "Kivy",
        "reportlab": "ReportLab",
        "python-docx": "python-docx",
        "pytest-asyncio": "pytest-asyncio",
    }
    for dep in deps:
        name = dep.split(">=")[0].split("==")[0].split("[")[0].strip().lower()
        if name in dep_map:
            frameworks.add(dep_map[name])
    pkg_deps = {**package_json.get("dependencies", {}), **package_json.get("devDependencies", {})}
    js_map = {
        "next": "Next.js",
        "react": "React",
        "react-native": "React Native",
        "vue": "Vue",
        "svelte": "Svelte",
        "jest": "Jest",
        "vitest": "Vitest",
        "playwright": "Playwright",
        "cypress": "Cypress",
        "typescript": "TypeScript",
        "expo": "Expo",
        "detox": "Detox",
        "android": "Android",
        "fastlane": "Fastlane",
    }
    for dep in pkg_deps:
        if dep in js_map:
            frameworks.add(js_map[dep])
    return sorted(frameworks)


def _infer_languages(root: Path) -> list[str]:
    languages: set[str] = set()
    for path in root.rglob("*"):
        if not path.is_file() or any(part in DEFAULT_IGNORE_DIRS for part in path.parts):
            continue
        if path.suffix in _PYTHON_FILE_SUFFIXES:
            languages.add("Python")
        elif path.suffix in _JS_FILE_SUFFIXES:
            languages.add("TypeScript" if path.suffix in {".ts", ".tsx"} else "JavaScript")
        elif path.suffix in {".java", ".kt", ".kts"}:
            languages.add("Kotlin/Java")
        elif path.suffix in {".dart"}:
            languages.add("Dart")
        elif path.suffix in {".go"}:
            languages.add("Go")
        elif path.suffix in {".rs"}:
            languages.add("Rust")
    return sorted(languages)


def extract_python_tests(root: Path, max_files: int = 500) -> tuple[int, list[str]]:
    count = 0
    names: list[str] = []
    files = [
        p
        for p in root.rglob("*.py")
        if p.is_file() and not any(part in DEFAULT_IGNORE_DIRS for part in p.parts)
    ]
    for path in files[:max_files]:
        try:
            tree = ast.parse(_read_text(path))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                count += 1
                names.append(f"{path.relative_to(root)}::{node.name}")
    return count, names


def extract_js_tests(root: Path, max_files: int = 500) -> tuple[int, list[str]]:
    count = 0
    names: list[str] = []
    files = [
        p
        for p in root.rglob("*")
        if p.is_file() and p.suffix in _JS_FILE_SUFFIXES and not any(part in DEFAULT_IGNORE_DIRS for part in p.parts)
    ]
    for path in files[:max_files]:
        text = _read_text(path)
        for match in _JS_TEST_RE.finditer(text):
            count += 1
            names.append(f"{path.relative_to(root)}::{match.group(1)}")
    return count, names


def _detect_security_features(
    pyproject: dict[str, Any], requirements: list[str], workflows: list[dict[str, Any]], readme: str
) -> list[str]:
    features: set[str] = set()
    all_deps = set(requirements)
    all_deps.update(pyproject.get("project", {}).get("dependencies", []))
    if any("mcp" in dep.lower() for dep in all_deps):
        features.add("MCP tool validation")
    if any("llm" in dep.lower() or "openai" in dep.lower() for dep in all_deps):
        features.add("LLM/RAG evaluations")
    if any("sha256" in dep.lower() or "hashlib" in readme.lower() for dep in all_deps):
        features.add("SHA-256 evidence logging")
    for wf in workflows:
        content = str(wf.get("content", {})).lower()
        if "codeql" in content or "security" in content:
            features.add("Security scanning (CodeQL)")
        if "bandit" in content or "semgrep" in content:
            features.add("SAST (Bandit/Semgrep)")
    if "redact" in readme.lower() or "redaction" in readme.lower():
        features.add("Automatic PII redaction")
    return sorted(features)


def _infer_ci_matrix(workflows: list[dict[str, Any]]) -> list[str]:
    matrix: set[str] = set()
    for wf in workflows:
        content = wf.get("content", {})
        jobs = content.get("jobs", {})
        for job in jobs.values():
            strategy = job.get("strategy", {})
            matrix_config = strategy.get("matrix", {})
            for key, values in matrix_config.items():
                if isinstance(values, list):
                    matrix.update(f"{key}: {v}" for v in values)
    return sorted(matrix)


def scan_repo(path: Path) -> RepoFacts:
    name = path.name
    rel_path = str(path)

    pyproject = load_pyproject(path / "pyproject.toml")
    requirements = load_requirements(path / "requirements.txt")
    package_json = load_package_json(path / "package.json")
    cv_metrics = load_cv_metrics(path / "cv_metrics.json")
    readme = load_readme(path / "README.md")
    workflows = load_github_workflows(path)

    languages = _infer_languages(path)
    frameworks = _infer_frameworks(pyproject, requirements, package_json)
    python_count, _ = extract_python_tests(path)
    js_count, _ = extract_js_tests(path)

    security_features = _detect_security_features(pyproject, requirements, workflows, readme)
    ci_matrix = _infer_ci_matrix(workflows)

    return RepoFacts(
        name=name,
        path=rel_path,
        languages=languages,
        frameworks=frameworks,
        test_count=python_count + js_count,
        python_tests=python_count,
        js_tests=js_count,
        ci_matrix=ci_matrix,
        has_cv_metrics=bool(cv_metrics),
        has_pyproject=bool(pyproject),
        has_requirements=bool(requirements),
        has_package_json=bool(package_json),
        has_github_workflows=bool(workflows),
        readme_preview=readme[:500],
        security_features=security_features,
    )


def scan_workspace(root: str | Path, *, include_pattern: str | None = None) -> WorkspaceSnapshot:
    base = Path(root).resolve()
    if not base.is_dir():
        raise ValueError(f"workspace root not found: {root}")

    repos: list[RepoFacts] = []
    for entry in sorted(base.iterdir()):
        if not entry.is_dir() or entry.name.startswith("."):
            continue
        if include_pattern and not re.search(include_pattern, entry.name):
            continue
        if entry.name in DEFAULT_IGNORE_DIRS:
            continue
        if (entry / ".git").is_dir() or any((entry / f).is_file() for f in _MANIFEST_FILES):
            try:
                repos.append(scan_repo(entry))
            except Exception:
                pass

    from datetime import datetime, timezone

    return WorkspaceSnapshot(
        root=str(base),
        repos=repos,
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )


def sanitize_snapshot(snapshot: WorkspaceSnapshot) -> WorkspaceSnapshot:
    """Replace absolute paths with repo names only."""
    sanitized_repos = []
    for repo in snapshot.repos:
        sanitized = RepoFacts(
            name=repo.name,
            path=repo.name,
            languages=repo.languages,
            frameworks=repo.frameworks,
            test_count=repo.test_count,
            python_tests=repo.python_tests,
            js_tests=repo.js_tests,
            ci_matrix=repo.ci_matrix,
            has_cv_metrics=repo.has_cv_metrics,
            has_pyproject=repo.has_pyproject,
            has_requirements=repo.has_requirements,
            has_package_json=repo.has_package_json,
            has_github_workflows=repo.has_github_workflows,
            readme_preview=repo.readme_preview,
            security_features=repo.security_features,
        )
        sanitized_repos.append(sanitized)
    return WorkspaceSnapshot(root=snapshot.root, repos=sanitized_repos, generated_at=snapshot.generated_at)


def write_snapshot(snapshot: WorkspaceSnapshot, path: str | Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(snapshot.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")


def _cli() -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="cv-builder-scan", description="Scan workspace and emit workspace_snapshot.json")
    parser.add_argument("--workspace-dir", default="..", help="Root directory containing sibling repos")
    parser.add_argument("--output", default="tools/cv_builder/workspace_snapshot.json", help="Output JSON path")
    parser.add_argument("--include", help="Regex filter for repo names")
    parser.add_argument("--sanitize", action="store_true", help="Replace absolute paths with repo names")
    args = parser.parse_args()

    snapshot = scan_workspace(args.workspace_dir, include_pattern=args.include)
    if args.sanitize:
        snapshot = sanitize_snapshot(snapshot)
    write_snapshot(snapshot, args.output)
    print(f"Scanned {len(snapshot.repos)} repos -> {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(_cli())