# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Desktop and command-line quality: CLI contract probes + static GUI audit.

The CLI runner is bounded (timeout, captured streams, no shell) and every
assertion is expressed as a :class:`CommandCase`, so the same checks run in CI
and in a client engagement. The desktop audit is static AST analysis: no GUI
window ever opens during a test run.
"""

from __future__ import annotations

import ast
import json
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from qa_agent.models import Finding, Severity
from qa_agent.redaction import redact_text

__all__ = [
    "CliCase",
    "CliReport",
    "CliRun",
    "DesktopReport",
    "audit_desktop_source",
    "check_cli_case",
    "default_cli_cases",
    "run_cli_audit",
    "run_command",
]

_SECRET_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|secret|password|token)\b\s*[:=]\s*[\"'][^\"']{8,}[\"']"
)
_IGNORED_DIRS = frozenset(
    {".git", ".venv", "venv", "__pycache__", "build", "dist", "node_modules", ".mypy_cache", ".pytest_cache"}
)
_GUI_FRAMEWORKS = {
    "tkinter": "Tkinter",
    "PySide6": "PySide6",
    "PyQt5": "PyQt5",
    "PyQt6": "PyQt6",
    "wx": "wxPython",
    "kivy": "Kivy",
}


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
# CLI contract probes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CliCase:
    name: str
    args: tuple[str, ...] = ()
    expect_exit: int | None = 0
    stdout_contains: str = ""
    stderr_contains: str = ""
    stdout_regex: str = ""
    stdin: str = ""
    json_keys: tuple[str, ...] = ()
    timeout_s: float = 30.0


@dataclass(frozen=True)
class CliRun:
    name: str
    argv: tuple[str, ...]
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    duration_ms: float = 0.0
    timed_out: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "argv": list(self.argv),
            "exit_code": self.exit_code,
            "duration_ms": round(self.duration_ms, 2),
            "timed_out": self.timed_out,
            "stdout": redact_text(self.stdout[:2000]),
            "stderr": redact_text(self.stderr[:2000]),
        }


@dataclass
class CliReport:
    command: tuple[str, ...]
    runs: list[CliRun] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    passed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": list(self.command),
            "passed": self.passed,
            "runs": [run.to_dict() for run in self.runs],
            "findings": [finding.to_dict() for finding in self.findings],
        }


def default_cli_cases(*, version_args: Sequence[str] = ("--version",)) -> tuple[CliCase, ...]:
    cases = [
        CliCase("help", ("--help",), 0, stdout_regex=r"(?i)usage|options|commands"),
        CliCase("unknown-flag", ("--qa-unknown-flag",), None, stderr_contains=""),
    ]
    if version_args:
        cases.append(CliCase("version", tuple(version_args), 0, stdout_regex=r"\d+\.\d+"))
    return tuple(cases)


def run_command(
    command: Sequence[str],
    case: CliCase,
    *,
    cwd: str | Path | None = None,
    env: Mapping[str, str] | None = None,
) -> CliRun:
    argv = [*command, *case.args]
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            argv,
            input=case.stdin or None,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=case.timeout_s,
            cwd=str(cwd) if cwd else None,
            env=dict(env) if env else None,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return CliRun(case.name, tuple(argv), -1, "", "", (time.perf_counter() - started) * 1000, True)
    except (OSError, ValueError) as exc:
        return CliRun(
            case.name,
            tuple(argv),
            -2,
            "",
            f"{type(exc).__name__}: {exc}",
            (time.perf_counter() - started) * 1000,
        )
    return CliRun(
        name=case.name,
        argv=tuple(argv),
        exit_code=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
        duration_ms=(time.perf_counter() - started) * 1000,
    )


def check_cli_case(run: CliRun, case: CliCase) -> list[Finding]:
    findings: list[Finding] = []
    label = f"CLI case '{case.name}'"
    if run.timed_out:
        findings.append(
            _finding(
                f"{label} timed out",
                Severity.HIGH,
                "desktop-cli-timeout",
                f"The command exceeded {case.timeout_s:.0f}s.",
                " ".join(run.argv),
                "Bound the command and fail fast instead of hanging.",
            )
        )
        return findings
    if run.exit_code == -2:
        findings.append(
            _finding(
                f"{label} could not start",
                Severity.HIGH,
                "desktop-cli-launch",
                "The executable was not found or could not be spawned.",
                run.stderr[:200],
                "Verify the entry point and its interpreter.",
            )
        )
        return findings
    if case.expect_exit is not None and run.exit_code != case.expect_exit:
        findings.append(
            _finding(
                f"{label} returned exit {run.exit_code}",
                Severity.HIGH,
                "desktop-cli-exit-code",
                f"Expected exit {case.expect_exit}.",
                f"stdout={run.stdout[:200]} stderr={run.stderr[:200]}",
                "Return documented exit codes and keep stderr for diagnostics.",
            )
        )
    if case.stdout_contains and case.stdout_contains not in run.stdout:
        findings.append(
            _finding(
                f"{label} missing stdout text",
                Severity.MEDIUM,
                "desktop-cli-stdout",
                "The expected confirmation was not printed.",
                f"expected={case.stdout_contains}",
                "Print a stable, scriptable confirmation line.",
            )
        )
    if case.stderr_contains and case.stderr_contains not in run.stderr:
        findings.append(
            _finding(
                f"{label} missing stderr text",
                Severity.MEDIUM,
                "desktop-cli-stderr",
                "The expected diagnostic was not printed to stderr.",
                f"expected={case.stderr_contains}",
                "Route actionable errors to stderr.",
            )
        )
    if case.stdout_regex and not re.search(case.stdout_regex, run.stdout):
        findings.append(
            _finding(
                f"{label} stdout does not match",
                Severity.MEDIUM,
                "desktop-cli-output",
                "The output contract is not satisfied.",
                f"regex={case.stdout_regex}",
                "Keep machine-readable output stable.",
            )
        )
    if case.json_keys:
        try:
            payload = json.loads(run.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            payload = None
        if not isinstance(payload, Mapping):
            findings.append(
                _finding(
                    f"{label} did not print JSON",
                    Severity.MEDIUM,
                    "desktop-cli-json",
                    "The command is expected to emit one JSON summary line.",
                    run.stdout[:200],
                    "Emit a single parseable JSON object on the last line.",
                )
            )
        else:
            missing = [key for key in case.json_keys if key not in payload]
            if missing:
                findings.append(
                    _finding(
                        f"{label} JSON keys missing",
                        Severity.MEDIUM,
                        "desktop-cli-json",
                        "The JSON contract is incomplete.",
                        f"missing={missing}",
                        "Document and preserve the JSON keys.",
                    )
                )
    if "Traceback (most recent call last)" in run.stderr and case.expect_exit not in (None, 0):
        findings.append(
            _finding(
                f"{label} leaked a traceback",
                Severity.MEDIUM,
                "desktop-cli-traceback",
                "A handled error should not dump an implementation traceback.",
                run.stderr[:300],
                "Catch expected errors and print a concise message.",
            )
        )
    if _SECRET_RE.search(run.stdout) or _SECRET_RE.search(run.stderr):
        findings.append(
            _finding(
                f"{label} printed a credential",
                Severity.CRITICAL,
                "desktop-cli-secret",
                "Command output contains a secret-shaped value.",
                redact_text(run.stdout + run.stderr)[:300],
                "Never print credentials; rely on environment variables.",
            )
        )
    return findings


def run_cli_audit(
    command: Sequence[str],
    cases: Iterable[CliCase] | None = None,
    *,
    cwd: str | Path | None = None,
    env: Mapping[str, str] | None = None,
) -> CliReport:
    argv = tuple(str(part) for part in command)
    report = CliReport(command=argv)
    for case in cases if cases is not None else default_cli_cases():
        run = run_command(argv, case, cwd=cwd, env=env)
        report.runs.append(run)
        report.findings.extend(check_cli_case(run, case))
    report.passed = not any(
        finding.severity in {Severity.CRITICAL, Severity.HIGH} for finding in report.findings
    )
    return report


# ---------------------------------------------------------------------------
# Desktop static audit
# ---------------------------------------------------------------------------


@dataclass
class DesktopReport:
    root: str
    files_scanned: int = 0
    frameworks: tuple[str, ...] = ()
    findings: list[Finding] = field(default_factory=list)
    passed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "files_scanned": self.files_scanned,
            "frameworks": list(self.frameworks),
            "passed": self.passed,
            "findings": [finding.to_dict() for finding in self.findings],
        }


def _python_files(root: Path, max_files: int) -> list[Path]:
    files: list[Path] = []
    for path in sorted(root.rglob("*.py")):
        if any(part in _IGNORED_DIRS for part in path.parts):
            continue
        files.append(path)
        if len(files) >= max_files:
            break
    return files


def audit_desktop_source(root: str | Path, *, max_files: int = 400) -> DesktopReport:
    """Static checks over a desktop/CLI Python codebase."""
    base = Path(root)
    report = DesktopReport(root=str(base))
    if not base.is_dir():
        report.findings.append(
            _finding(
                "Desktop source path not found",
                Severity.HIGH,
                "desktop-path",
                "The source directory does not exist.",
                str(base),
                "Point the audit at the project root.",
            )
        )
        return report

    frameworks: set[str] = set()
    for path in _python_files(base, max_files):
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source)
        except (OSError, SyntaxError) as exc:
            report.findings.append(
                _finding(
                    "Desktop source could not be parsed",
                    Severity.MEDIUM,
                    "desktop-parse",
                    "A Python module has a syntax error, so its checks were skipped.",
                    f"{path.name}: {type(exc).__name__}",
                    "Fix the syntax error and re-run the audit.",
                )
            )
            continue
        report.files_scanned += 1
        relative = path.relative_to(base).as_posix()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in _GUI_FRAMEWORKS:
                        frameworks.add(_GUI_FRAMEWORKS[alias.name.split(".")[0]])
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module.split(".")[0] in _GUI_FRAMEWORKS:
                    frameworks.add(_GUI_FRAMEWORKS[node.module.split(".")[0]])
            elif isinstance(node, ast.Call):
                name = _call_name(node.func)
                if name in {"eval", "exec"}:
                    report.findings.append(
                        _finding(
                            "Dynamic code execution",
                            Severity.HIGH,
                            "desktop-dynamic-code",
                            f"{name}() can execute untrusted input.",
                            f"{relative}:{node.lineno}",
                            "Remove dynamic execution or restrict it to a vetted allow-list.",
                        )
                    )
                if name in {"os.system", "os.popen"}:
                    report.findings.append(
                        _finding(
                            "Shell command execution",
                            Severity.HIGH,
                            "desktop-shell",
                            f"{name}() passes a string to the shell.",
                            f"{relative}:{node.lineno}",
                            "Use subprocess with an argument list and shell=False.",
                        )
                    )
                if name in {"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output"}:
                    keywords = {keyword.arg for keyword in node.keywords}
                    if "timeout" not in keywords:
                        report.findings.append(
                            _finding(
                                "Subprocess without timeout",
                                Severity.MEDIUM,
                                "desktop-cli-timeout",
                                "A child process can block the UI or a CI job indefinitely.",
                                f"{relative}:{node.lineno} {name}",
                                "Pass an explicit timeout and handle TimeoutExpired.",
                            )
                        )
                    if any(
                        keyword.arg == "shell"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is True
                        for keyword in node.keywords
                    ):
                        report.findings.append(
                            _finding(
                                "subprocess called with shell=True",
                                Severity.HIGH,
                                "desktop-shell",
                                "Shell interpolation enables command injection.",
                                f"{relative}:{node.lineno}",
                                "Pass an argument list with shell=False.",
                            )
                        )
                if name in {"time.sleep", "asyncio.sleep"} and "gui" in relative.lower():
                    report.findings.append(
                        _finding(
                            "Blocking sleep in GUI module",
                            Severity.MEDIUM,
                            "desktop-blocking-ui",
                            "A synchronous sleep freezes the interface.",
                            f"{relative}:{node.lineno}",
                            "Move long work to a worker thread or Qt signal.",
                        )
                    )
            elif isinstance(node, ast.ExceptHandler) and node.type is None:
                report.findings.append(
                    _finding(
                        "Bare except clause",
                        Severity.MEDIUM,
                        "desktop-error-handling",
                        "A bare except hides programming errors and interrupts.",
                        f"{relative}:{node.lineno}",
                        "Catch specific exception types and log them.",
                    )
                )
        if _SECRET_RE.search(source):
            report.findings.append(
                _finding(
                    "Hardcoded credential in source",
                    Severity.CRITICAL,
                    "desktop-secret",
                    "A secret-shaped literal is committed in the desktop codebase.",
                    relative,
                    "Move credentials to environment variables or a local untracked file.",
                )
            )
        tree_body = tree.body
        has_main_guard = any(
            isinstance(node, ast.If)
            and isinstance(node.test, ast.Compare)
            and "__name__" in ast.dump(node.test)
            for node in tree_body
        )
        if (
            not has_main_guard
            and re.search(r"\b(QApplication|tk\.Tk\(|wx\.App\()", source)
            and path.name in {"main.py", "app.py", "gui.py"}
        ):
            report.findings.append(
                _finding(
                    "GUI entry point has no main guard",
                    Severity.LOW,
                    "desktop-main-guard",
                    "Importing the module can start the application.",
                    relative,
                    "Wrap startup in if __name__ == '__main__'.",
                )
            )

    report.frameworks = tuple(sorted(frameworks))
    report.passed = not any(
        finding.severity in {Severity.CRITICAL, Severity.HIGH} for finding in report.findings
    )
    return report


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""
