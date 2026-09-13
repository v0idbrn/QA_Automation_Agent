# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Project discovery for local QA targets.

Discovery is strictly read-only. It inspects a project directory or endpoint
surface and produces a structured representation without modifying anything.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class DiscoveredProject:
    root: Path
    language: str = "unknown"
    framework: str = "unknown"
    package_manager: str = "unknown"
    entry_points: list[str] = field(default_factory=list)
    test_framework: str = "unknown"
    test_files: list[str] = field(default_factory=list)
    api_endpoints: list[str] = field(default_factory=list)
    routes: list[str] = field(default_factory=list)
    has_e2e_tests: bool = False
    notes: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"Project\n"
            f"├── {self.language or 'unknown'}\n"
            f"├── {self.framework or 'unknown'}\n"
            f"├── {self.package_manager or 'unknown'}\n"
            f"├── {len(self.routes)} routes\n"
            f"├── {len(self.api_endpoints)} endpoints\n"
            f"├── {len(self.test_files)} test files\n"
            f"└── {'E2E' if self.has_e2e_tests else 'no E2E detected'}\n"
        )


def _looks_like_python(root: Path) -> bool:
    return (root / "pyproject.toml").exists() or (root / "setup.py").exists() or (root / "requirements.txt").exists() or any(p.suffix == ".py" for p in root.rglob("*") if p.is_file())


def _looks_like_node(root: Path) -> bool:
    return (root / "package.json").exists() or (root / "pnpm-lock.yaml").exists() or (root / "yarn.lock").exists() or (root / "node_modules").exists()


def _python_package_manager(root: Path) -> str:
    if (root / "pyproject.toml").exists():
        return "python/pyproject"
    if (root / "requirements.txt").exists():
        return "python/requirements"
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


def _detect_test_framework(root: Path, language: str) -> str:
    if language != "python":
        return "unknown"
    names = {"pytest": [], "unittest": [], "nose": []}
    for path in root.rglob("*.py"):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if "pytest" in text or "pytest.ini" in text or "pyproject.toml" in text and "pytest" in text:
            names["pytest"].append(str(path))
        if "unittest" in text:
            names["unittest"].append(str(path))
    if names["pytest"]:
        return "pytest"
    if names["unittest"]:
        return "unittest"
    return "unknown"


def _collect_test_files(root: Path, framework: str) -> list[str]:
    tests: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        name = path.name
        if framework == "pytest":
            if name.startswith("test_") and path.suffix == ".py":
                tests.append(str(path))
        elif framework == "unittest":
            if "test" in name.lower() and path.suffix == ".py":
                tests.append(str(path))
        else:
            if "test" in name.lower() and path.suffix == ".py":
                tests.append(str(path))
    return sorted(tests)


def discover_project(target: str | Path) -> DiscoveredProject:
    root = Path(target).resolve()
    if not root.exists():
        return DiscoveredProject(root=root, notes=["target does not exist locally"])

    language = "unknown"
    package_manager = "unknown"
    framework = "unknown"
    entry_points: list[str] = []
    routes: list[str] = []
    api_endpoints: list[str] = []

    if _looks_like_python(root):
        language = "python"
        package_manager = _python_package_manager(root)
        framework = _detect_test_framework(root, language)
        for path in root.rglob("*.py"):
            if path.name in {"main.py", "app.py", "wsgi.py", "asgi.py", "manage.py", "cli.py"}:
                entry_points.append(str(path))
        _infer_python_routes(root, routes, api_endpoints)
    elif _looks_like_node(root):
        language = "javascript"
        package_manager = _node_package_manager(root)
        _infer_node_framework(root, framework)
        for path in root.rglob("*"):
            if path.is_file() and path.suffix in {".js", ".ts", ".mjs", ".cjs"}:
                try:
                    text = path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                if "export default" in text or "export function" in text or "export const" in text:
                    entry_points.append(str(path))
    else:
        entry_points = [str(p) for p in root.iterdir() if p.is_file()]

    test_framework = _detect_test_framework(root, language) if language == "python" else "unknown"
    test_files = _collect_test_files(root, test_framework)
    has_e2e_tests = any("e2e" in path.lower() or " EndToEnd" in path lower() for path in test_files) or any("e2e" in path.lower() for path in test_files)

    return DiscoveredProject(
        root=root,
        language=language,
        framework=framework,
        package_manager=package_manager,
        entry_points=sorted(set(entry_points)),
        test_framework=test_framework,
        test_files=test_files,
        api_endpoints=sorted(set(api_endpoints)),
        routes=sorted(set(routes)),
        has_e2e_tests=has_e2e_tests,
    )


def _infer_python_routes(root: Path, routes: list[str], api_endpoints: list[str]) -> None:
    for path in root.rglob("*.py"):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("@app.") or stripped.startswith("@route") or stripped.startswith("@get") or stripped.startswith("@post"):
                routes.append(stripped)
            if '"' in stripped and ("/api/" in stripped or "/v1/" in stripped or "/v2/" in stripped):
                start = stripped.find('"')
                end = stripped.find('"', start + 1)
                if start != -1 and end != -1 and start < end:
                    candidate = stripped[start + 1 : end]
                    if candidate.startswith("/"):
                        api_endpoints.append(candidate)


def _infer_node_framework(root: Path, framework: list[str]) -> None:
    if (root / "next.config").exists() or (root / "next.config.js").exists() or (root / "next.config.mjs").exists():
        framework.append("nextjs")
    if (root / "vite.config").exists() or (root / "vite.config.ts").exists():
        framework.append("vite")
    if (root / "angular.json").exists():
        framework.append("angular")
    if (root / ".nuxt").exists() or (root / "nuxt.config").exists():
        framework.append("nuxt")


def _has_e2e_tests(test_files: list[str]) -> bool:
    lowered = [path.lower() for path in test_files]
    return any("e2e" in path for path in lowered) or any("endtoend" in path for path in lowered) or any("interface" in path for path in lowered)
