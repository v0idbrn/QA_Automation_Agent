# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Test management: inventory discovery, traceability, risk-based plans, JUnit health.

Everything here is deterministic and offline: tests are discovered by AST
(Python) and a conservative regex (JS/TS), the traceability matrix is built from
declared requirement/test links, and JUnit XML is parsed with the stdlib. The
same report feeds the CLI summary and the release gate.
"""

from __future__ import annotations

import ast
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from qa_agent.models import Finding, Severity
from qa_agent.redaction import redact_text

__all__ = [
    "JUnitHealth",
    "Requirement",
    "RtmReport",
    "TestInventory",
    "TestCaseFacts",
    "build_rtm",
    "discover_tests",
    "generate_test_plan",
    "parse_junit",
    "parse_junit_file",
]

_IGNORED_DIRS = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        "build",
        "dist",
        ".next",
        "android-sdk",
        "coverage",
    }
)
_JS_TEST_RE = re.compile(r"""\b(?:it|test)(?:\.(?:only|skip|each\([^)]*\)|concurrent))?\s*\(\s*['"`]([^'"`]{1,160})['"`]""")
_JS_FILE_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}


def _finding(
    title: str,
    severity: Severity,
    category: str,
    description: str,
    evidence: str = "",
    recommendation: str = "",
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        category=category,
        description=description,
        evidence=redact_text(evidence),
        recommendation=recommendation,
    )


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TestCaseFacts:
    name: str
    path: str
    line: int = 0
    language: str = "python"
    suite: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "line": self.line,
            "language": self.language,
            "suite": self.suite,
        }


@dataclass
class TestInventory:
    root: str = ""
    files_scanned: int = 0
    tests: list[TestCaseFacts] = field(default_factory=list)
    by_language: dict[str, int] = field(default_factory=dict)
    by_suite: dict[str, int] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    passed: bool = False

    @property
    def count(self) -> int:
        return len(self.tests)

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "files_scanned": self.files_scanned,
            "count": self.count,
            "by_language": dict(self.by_language),
            "by_suite": dict(self.by_suite),
            "tests": [test.to_dict() for test in self.tests],
            "passed": self.passed,
            "findings": [finding.to_dict() for finding in self.findings],
        }


def _python_tests(tree: ast.AST, relative: str) -> list[TestCaseFacts]:
    discovered: list[TestCaseFacts] = []

    def visit(nodes: Sequence[ast.stmt], prefix: str = "") -> None:
        for node in nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test"):
                discovered.append(
                    TestCaseFacts(
                        name=f"{prefix}{node.name}",
                        path=relative,
                        line=node.lineno,
                        language="python",
                    )
                )
            elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
                visit(node.body, prefix=f"{node.name}::")

    visit(tree.body)
    return discovered


def discover_tests(root: str | Path, *, include_js: bool = True, max_files: int = 2000) -> TestInventory:
    """Discover Python and JS/TS tests under ``root``."""
    base = Path(root)
    inventory = TestInventory(root=str(base))
    if not base.is_dir():
        inventory.findings.append(
            _finding(
                "Test root not found",
                Severity.HIGH,
                "test-inventory-path",
                "The directory does not exist, so nothing could be inventoried.",
                str(base),
                "Point the command at the repository root.",
            )
        )
        return inventory

    files = [
        path
        for path in sorted(base.rglob("*"))
        if path.is_file()
        and not any(part in _IGNORED_DIRS for part in path.parts)
        and (path.suffix == ".py" or (include_js and path.suffix in _JS_FILE_SUFFIXES))
    ]
    for path in files[:max_files]:
        relative = path.relative_to(base).as_posix()
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        inventory.files_scanned += 1
        if path.suffix == ".py":
            try:
                tree = ast.parse(source)
            except SyntaxError as exc:
                inventory.findings.append(
                    _finding(
                        "Test module has a syntax error",
                        Severity.MEDIUM,
                        "test-inventory-parse",
                        f"{relative} could not be parsed, so its tests are invisible.",
                        f"{relative}:{exc.lineno}: {exc.msg}",
                        "Fix the syntax error so CI can collect the suite.",
                    )
                )
                continue
            found = _python_tests(tree, relative)
        else:
            found = [
                TestCaseFacts(name=match.group(1), path=relative, language="javascript")
                for match in _JS_TEST_RE.finditer(source)
            ]
        for test in found:
            suite = relative.split("/", 1)[0] if "/" in relative else relative
            inventory.tests.append(
                TestCaseFacts(test.name, test.path, test.line, test.language, suite)
            )

    for test in inventory.tests:
        inventory.by_language[test.language] = inventory.by_language.get(test.language, 0) + 1
        inventory.by_suite[test.suite] = inventory.by_suite.get(test.suite, 0) + 1

    if not inventory.tests:
        inventory.findings.append(
            _finding(
                "No tests discovered",
                Severity.HIGH,
                "test-inventory-empty",
                "No Python or JS/TS test definitions were found.",
                f"files_scanned={inventory.files_scanned}",
                "Add tests or point the inventory at the suite directory.",
            )
        )
    if files and len(files) > max_files:
        inventory.findings.append(
            _finding(
                "Test discovery was bounded",
                Severity.INFO,
                "test-inventory-bounded",
                f"Only {max_files} of {len(files)} candidate files were scanned.",
                f"files={len(files)} scanned={max_files}",
                "Narrow the scan root or raise the bound.",
            )
        )
    python_tests = inventory.by_language.get("python", 0)
    if inventory.tests and python_tests == 0:
        inventory.findings.append(
            _finding(
                "No Python tests discovered",
                Severity.LOW,
                "test-inventory-language",
                "Only JS/TS tests were found; the Python suite is empty or misconfigured.",
                f"by_language={inventory.by_language}",
                "Confirm pytest discovery paths.",
            )
        )
    inventory.passed = not any(
        finding.severity in {Severity.CRITICAL, Severity.HIGH} for finding in inventory.findings
    )
    return inventory


# ---------------------------------------------------------------------------
# Traceability matrix
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Requirement:
    id: str
    title: str = ""
    tests: tuple[str, ...] = ()
    risk: float = 0.0


@dataclass
class RtmReport:
    requirements: list[Requirement] = field(default_factory=list)
    test_ids: tuple[str, ...] = ()
    covered: dict[str, tuple[str, ...]] = field(default_factory=dict)
    uncovered: tuple[str, ...] = ()
    orphan_tests: tuple[str, ...] = ()
    coverage: float = 0.0
    findings: list[Finding] = field(default_factory=list)
    passed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "requirements": [
                {"id": item.id, "title": item.title, "tests": list(item.tests), "risk": item.risk}
                for item in self.requirements
            ],
            "coverage": round(self.coverage, 4),
            "covered": {key: list(value) for key, value in self.covered.items()},
            "uncovered": list(self.uncovered),
            "orphan_tests": list(self.orphan_tests),
            "passed": self.passed,
            "findings": [finding.to_dict() for finding in self.findings],
        }


def _coerce_requirement(item: Any, index: int) -> Requirement:
    if isinstance(item, Requirement):
        return item
    if isinstance(item, str):
        return Requirement(id=item, title=item)
    if isinstance(item, Mapping):
        return Requirement(
            id=str(item.get("id") or f"REQ-{index:03d}"),
            title=str(item.get("title") or item.get("description") or ""),
            tests=tuple(str(value) for value in item.get("tests") or ()),
            risk=float(item.get("risk") or 0.0),
        )
    raise ValueError(f"unsupported requirement entry: {item!r}")


def build_rtm(
    requirements: Iterable[Any],
    test_ids: Sequence[str],
    *,
    min_coverage: float = 0.8,
) -> RtmReport:
    """Build a requirements-to-tests traceability matrix."""
    report = RtmReport(
        requirements=[_coerce_requirement(item, index) for index, item in enumerate(requirements, start=1)],
        test_ids=tuple(dict.fromkeys(str(test) for test in test_ids)),
    )
    known = set(report.test_ids)
    linked: set[str] = set()
    for requirement in report.requirements:
        valid = tuple(test for test in requirement.tests if test in known)
        missing = tuple(test for test in requirement.tests if test not in known)
        report.covered[requirement.id] = valid
        linked.update(valid)
        if requirement.tests and missing:
            report.findings.append(
                _finding(
                    "Requirement links an unknown test",
                    Severity.MEDIUM,
                    "rtm-broken-link",
                    f"{requirement.id} references tests that do not exist.",
                    f"{requirement.id}: {', '.join(missing)}",
                    "Fix the test id or remove the link so the matrix stays truthful.",
                )
            )
        if not requirement.tests:
            report.findings.append(
                _finding(
                    "Requirement has no linked test",
                    Severity.HIGH if requirement.risk >= 7 else Severity.MEDIUM,
                    "rtm-uncovered",
                    f"{requirement.id} is not verified by any test.",
                    f"{requirement.id}: {requirement.title or 'n/a'}",
                    "Add a test that fails when the requirement regresses.",
                )
            )
    report.uncovered = tuple(item.id for item in report.requirements if not report.covered.get(item.id))
    report.orphan_tests = tuple(sorted(known - linked))
    if report.orphan_tests:
        report.findings.append(
            _finding(
                "Tests are not traced to a requirement",
                Severity.LOW,
                "rtm-orphan-test",
                "Some tests do not prove a declared requirement.",
                ", ".join(report.orphan_tests[:20]),
                "Link the tests or delete the duplicates.",
            )
        )
    report.coverage = (
        (len(report.requirements) - len(report.uncovered)) / len(report.requirements)
        if report.requirements
        else 1.0
    )
    if report.requirements and report.coverage < min_coverage:
        report.findings.append(
            _finding(
                "Requirement coverage below the gate",
                Severity.HIGH,
                "rtm-coverage",
                f"Coverage is {report.coverage:.0%} against a {min_coverage:.0%} gate.",
                f"coverage={report.coverage:.2f} gate={min_coverage:.2f}",
                "Cover the high-risk requirements first, then the remainder.",
            )
        )
    report.passed = not any(
        finding.severity in {Severity.CRITICAL, Severity.HIGH} for finding in report.findings
    )
    return report


# ---------------------------------------------------------------------------
# Risk-based test plan
# ---------------------------------------------------------------------------


def generate_test_plan(
    items: Iterable[Mapping[str, Any]],
    *,
    max_items: int = 40,
    coverage_floor: float = 0.0,
) -> dict[str, Any]:
    """Order planned test items by risk, then by declared priority."""
    scored: list[dict[str, Any]] = []
    for index, item in enumerate(items, start=1):
        risk = float(item.get("risk", item.get("risk_score", 0.0)) or 0.0)
        priority = str(item.get("priority", "")).lower()
        priority_weight = {"critical": 25.0, "high": 15.0, "medium": 5.0, "low": 0.0}.get(priority, 0.0)
        identifier = str(item.get("id") or f"TC-{index:03d}")
        scored.append(
            {
                "id": identifier,
                "title": str(item.get("title") or item.get("name") or identifier),
                "risk": round(risk, 2),
                "priority": priority or ("high" if risk >= 7 else "medium" if risk >= 4 else "low"),
                "score": round(risk + priority_weight, 2),
                "tests": [str(test) for test in item.get("tests") or ()],
            }
        )
    scored.sort(key=lambda entry: (-entry["score"], entry["id"]))
    planned = scored[: max(1, max_items)]
    covered = {test for entry in planned for test in entry["tests"]}
    total_tests = {test for entry in scored for test in entry["tests"]}
    coverage = (len(covered) / len(total_tests)) if total_tests else 1.0
    findings: list[Finding] = []
    if not scored:
        findings.append(
            _finding(
                "Test plan is empty",
                Severity.HIGH,
                "plan-empty",
                "No requirement or risk was supplied, so there is nothing to execute.",
                "items=0",
                "Feed the discovery/risk engines into the planner first.",
            )
        )
    if coverage_floor and coverage < coverage_floor:
        findings.append(
            _finding(
                "Planned selection misses the coverage floor",
                Severity.HIGH,
                "plan-coverage",
                f"The bounded plan covers {coverage:.0%} of tests against a {coverage_floor:.0%} floor.",
                f"coverage={coverage:.2f} floor={coverage_floor:.2f}",
                "Raise max_items or reduce scope deliberately.",
            )
        )
    if len(scored) > len(planned):
        findings.append(
            _finding(
                "Plan was bounded",
                Severity.INFO,
                "plan-bounded",
                f"{len(scored) - len(planned)} lower-risk items were deferred.",
                f"planned={len(planned)} total={len(scored)}",
                "Track the deferred items for the next cycle.",
            )
        )
    return {
        "items": planned,
        "total": len(scored),
        "deferred": max(0, len(scored) - len(planned)),
        "test_coverage": round(coverage, 4),
        "passed": not any(
            finding.severity in {Severity.CRITICAL, Severity.HIGH} for finding in findings
        ),
        "findings": [finding.to_dict() for finding in findings],
    }


# ---------------------------------------------------------------------------
# JUnit XML health
# ---------------------------------------------------------------------------


@dataclass
class JUnitHealth:
    suites: int = 0
    tests: int = 0
    failures: int = 0
    errors: int = 0
    skipped: int = 0
    duration_s: float = 0.0
    slowest: tuple[str, float] = ("", 0.0)
    findings: list[Finding] = field(default_factory=list)
    passed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "suites": self.suites,
            "tests": self.tests,
            "failures": self.failures,
            "errors": self.errors,
            "skipped": self.skipped,
            "duration_s": round(self.duration_s, 3),
            "slowest": {"name": self.slowest[0], "duration_s": round(self.slowest[1], 3)},
            "passed": self.passed,
            "findings": [finding.to_dict() for finding in self.findings],
        }


def parse_junit(xml_text: str, *, max_skip_ratio: float = 0.2) -> JUnitHealth:
    """Summarize a JUnit XML document and flag unhealthy patterns."""
    report = JUnitHealth()
    if not (xml_text or "").strip():
        report.findings.append(
            _finding(
                "JUnit report is empty",
                Severity.HIGH,
                "junit-empty",
                "No test results were supplied.",
                "document is blank",
                "Upload the JUnit XML produced by the CI test step.",
            )
        )
        return report
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        report.findings.append(
            _finding(
                "JUnit report is malformed",
                Severity.HIGH,
                "junit-parse",
                "The XML could not be parsed.",
                str(exc),
                "Confirm the reporter writes valid JUnit XML.",
            )
        )
        return report

    cases = [node for node in root.iter() if node.tag in {"testcase", "testCase"}]
    suites = [node for node in root.iter() if node.tag in {"testsuite", "testSuite"}]
    report.suites = len(suites) or (1 if cases else 0)
    report.tests = len(cases)
    slowest_name, slowest_time = "", 0.0
    for case in cases:
        name = "::".join(
            part
            for part in (
                case.get("classname") or case.get("className") or "",
                case.get("name") or "",
            )
            if part
        ) or "unnamed"
        if any(child.tag in {"failure", "failed"} for child in case):
            report.failures += 1
        if any(child.tag == "error" for child in case):
            report.errors += 1
        if any(child.tag == "skipped" for child in case):
            report.skipped += 1
        try:
            duration = float(case.get("time") or case.get("duration") or 0.0)
        except ValueError:
            duration = 0.0
        if duration > slowest_time:
            slowest_name, slowest_time = name, duration
    report.slowest = (slowest_name, slowest_time)
    for suite in suites:
        try:
            report.duration_s += float(suite.get("time") or 0.0)
        except ValueError:
            continue

    if report.failures or report.errors:
        report.findings.append(
            _finding(
                "JUnit results contain failures",
                Severity.CRITICAL if report.errors else Severity.HIGH,
                "junit-failures",
                f"{report.failures} failure(s) and {report.errors} error(s) were reported.",
                f"tests={report.tests} failures={report.failures} errors={report.errors}",
                "Fix the regressions before promoting the build.",
            )
        )
    if report.tests == 0:
        report.findings.append(
            _finding(
                "JUnit report ran no tests",
                Severity.HIGH,
                "junit-zero-tests",
                "A green report with zero tests is not evidence.",
                "tests=0",
                "Fail the pipeline when the suite collects nothing.",
            )
        )
    if report.tests and report.skipped / report.tests > max_skip_ratio:
        report.findings.append(
            _finding(
                "Too many skipped tests",
                Severity.MEDIUM,
                "junit-skips",
                f"{report.skipped}/{report.tests} tests were skipped.",
                f"skip_ratio={report.skipped / report.tests:.0%} limit={max_skip_ratio:.0%}",
                "Delete dead tests or fix the gating conditions.",
            )
        )
    report.passed = not any(
        finding.severity in {Severity.CRITICAL, Severity.HIGH} for finding in report.findings
    )
    return report


def parse_junit_file(path: str | Path, *, max_skip_ratio: float = 0.2) -> JUnitHealth:
    return parse_junit(Path(path).read_text(encoding="utf-8", errors="replace"), max_skip_ratio=max_skip_ratio)
