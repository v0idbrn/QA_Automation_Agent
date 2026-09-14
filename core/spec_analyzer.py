# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Specification analyzer.

Reads local README/API docs and classifies statements as OBSERVED, INFERRED,
or UNKNOWN. Never mutates the target project.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class SpecConfidence(str, Enum):
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"


@dataclass
class SpecStatement:
    statement: str
    confidence: SpecConfidence
    source: str
    kind: str = "requirement"


@dataclass
class SpecAnalysis:
    statements: list[SpecStatement] = field(default_factory=list)

    def by_confidence(self, confidence: SpecConfidence) -> list[SpecStatement]:
        return [item for item in self.statements if item.confidence == confidence]


_SPEC_NAMES = {
    "readme.md",
    "readme",
    "openapi.yaml",
    "openapi.yml",
    "openapi.json",
    "swagger.yaml",
    "swagger.yml",
    "swagger.json",
    "api.md",
}


def analyze_specs(root: str | Path) -> SpecAnalysis:
    base = Path(root)
    analysis = SpecAnalysis()
    if not base.exists():
        analysis.statements.append(
            SpecStatement(
                statement="No local specification surface was found",
                confidence=SpecConfidence.UNKNOWN,
                source=str(base),
                kind="availability",
            )
        )
        return analysis

    spec_files = [path for path in base.rglob("*") if path.is_file() and path.name.lower() in _SPEC_NAMES]
    if not spec_files:
        analysis.statements.append(
            SpecStatement(
                statement="Specification files were not observed in the project root",
                confidence=SpecConfidence.UNKNOWN,
                source=str(base),
                kind="availability",
            )
        )
        return analysis

    for path in spec_files[:12]:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            analysis.statements.append(
                SpecStatement(
                    statement=f"Could not read {path.name}",
                    confidence=SpecConfidence.UNKNOWN,
                    source=str(path),
                )
            )
            continue
        analysis.statements.extend(_classify_document(path, text))
    return analysis


def _classify_document(path: Path, text: str) -> list[SpecStatement]:
    statements: list[SpecStatement] = []
    name = path.name.lower()
    lowered = text.lower()

    if name.startswith("readme"):
        statements.append(
            SpecStatement(
                statement=f"README observed ({len(text.splitlines())} lines)",
                confidence=SpecConfidence.OBSERVED,
                source=str(path),
                kind="docs",
            )
        )
        if "pytest" in lowered or "playwright" in lowered:
            statements.append(
                SpecStatement(
                    statement="Test toolchain is documented",
                    confidence=SpecConfidence.OBSERVED,
                    source=str(path),
                    kind="toolchain",
                )
            )
        elif "test" in lowered:
            statements.append(
                SpecStatement(
                    statement="Testing is mentioned but toolchain is not explicit",
                    confidence=SpecConfidence.INFERRED,
                    source=str(path),
                    kind="toolchain",
                )
            )
        if "auth" in lowered or "login" in lowered:
            statements.append(
                SpecStatement(
                    statement="Authentication surface is mentioned",
                    confidence=SpecConfidence.INFERRED,
                    source=str(path),
                    kind="auth",
                )
            )

    if "openapi" in name or "swagger" in name or name == "api.md":
        statements.append(
            SpecStatement(
                statement="API specification file observed",
                confidence=SpecConfidence.OBSERVED,
                source=str(path),
                kind="api",
            )
        )
        if "/health" in lowered or "paths:" in lowered or '"paths"' in lowered:
            statements.append(
                SpecStatement(
                    statement="API paths are present in the specification",
                    confidence=SpecConfidence.OBSERVED,
                    source=str(path),
                    kind="api",
                )
            )
        else:
            statements.append(
                SpecStatement(
                    statement="API document exists but path inventory is incomplete",
                    confidence=SpecConfidence.INFERRED,
                    source=str(path),
                    kind="api",
                )
            )

    if not statements:
        statements.append(
            SpecStatement(
                statement=f"Document {path.name} was found but could not be classified",
                confidence=SpecConfidence.UNKNOWN,
                source=str(path),
            )
        )
    return statements
