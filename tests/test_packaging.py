# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Packaging / frozen-mode regressions.

The exe bundle must behave identically to the source checkout:
  * report templates resolve under PyInstaller (sys.frozen, _MEIPASS);
  * the GUI composes self-spawn argv when frozen (the windowed exe is also
    the headless runner);
  * `install-browsers` forwards exit codes and cleans up sys.argv/sys.exit;
  * gui.main dispatches agent subcommands to main.main, and anything else
    goes to the GUI window.
"""

from __future__ import annotations

import builtins
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import gui  # noqa: E402
import main as agent_main_mod  # noqa: E402
from core.report_builder import ReportBuilder, _default_template_dir  # noqa: E402


# ---------------------------------------------------------------------------
# Template resolution
# ---------------------------------------------------------------------------


def test_template_dir_source_mode_resolves_repo_reports() -> None:
    assert _default_template_dir() == Path(__file__).resolve().parent.parent / "reports"


def test_template_dir_frozen_prefers_meipass(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    meipass = tmp_path / "_MEIPASS"
    (meipass / "reports").mkdir(parents=True)
    (meipass / "reports" / "audit_report.html.jinja").write_text("x", encoding="utf-8")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(meipass), raising=False)
    monkeypatch.setattr(sys, "_MEIPASS2", None, raising=False)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "QA_Agent.exe"))
    assert _default_template_dir() == meipass / "reports"


def test_template_dir_frozen_falls_back_to_exe_sidecar(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # onedir without _MEIPASS (or a user-placed reports/ next to the exe): the
    # exe-sidecar directory wins so users can tweak templates without rebuilding.
    exe_dir = tmp_path / "portable"
    (exe_dir / "reports").mkdir(parents=True)
    (exe_dir / "reports" / "audit_report.html.jinja").write_text("x", encoding="utf-8")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", None, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS2", None, raising=False)
    monkeypatch.setattr(sys, "executable", str(exe_dir / "QA_Agent.exe"))
    assert _default_template_dir() == exe_dir / "reports"


def test_report_builder_accepts_frozen_style_dir(tmp_path: Path) -> None:
    (tmp_path / "reports").mkdir()
    (tmp_path / "reports" / "audit_report.md.jinja").write_text(
        "# {{ report.target }} ({{ findings|length }})", encoding="utf-8"
    )
    builder = ReportBuilder(template_dir=tmp_path / "reports")
    out = builder.build("target-x", [])
    assert "target-x" in out and "(0)" in out


# ---------------------------------------------------------------------------
# GUI frozen plumbing
# ---------------------------------------------------------------------------


def test_agent_invocation_source_mode() -> None:
    if gui.FROZEN:
        pytest.skip("source-mode contract")
    assert gui.agent_invocation() == [sys.executable, str(gui.MAIN_PY)]


def test_agent_invocation_frozen_is_self_spawn(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gui, "FROZEN", True)
    monkeypatch.setattr(sys, "argv", [r"C:\Tools\QA Agent\QA_Agent.exe"])
    assert gui.agent_invocation() == [r"C:\Tools\QA Agent\QA_Agent.exe"]


def test_agent_cwd_frozen_is_exe_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gui, "FROZEN", True)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "QA_Agent.exe"))
    assert gui.agent_cwd() == tmp_path


def test_build_command_self_spawns_when_frozen(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gui, "FROZEN", True)
    monkeypatch.setattr(sys, "argv", [r"D:\dist\QA_Agent.exe"])
    cmd = gui.build_command("run", "samples/demo_site", "safe")
    assert cmd[0] == r"D:\dist\QA_Agent.exe"
    assert cmd[1:3] == ["run", "samples/demo_site"]
    assert "main.py" not in cmd


def test_build_command_explicit_python_exe_still_supported() -> None:
    cmd = gui.build_command("plan", ".", "safe", python_exe="/x/python")
    assert cmd[:2] == ["/x/python", str(gui.MAIN_PY)]


# ---------------------------------------------------------------------------
# install-browsers
# ---------------------------------------------------------------------------


def test_install_browsers_success_exit_code(monkeypatch: pytest.MonkeyPatch) -> None:
    mod = types.ModuleType("playwright.__main__")
    mod.main = lambda: sys.exit(0)
    monkeypatch.setitem(sys.modules, "playwright.__main__", mod)
    assert agent_main_mod.cmd_install_browsers() == 0


def test_install_browsers_propagates_playwright_exit_code(monkeypatch: pytest.MonkeyPatch) -> None:
    mod = types.ModuleType("playwright.__main__")
    mod.main = lambda: sys.exit(3)
    monkeypatch.setitem(sys.modules, "playwright.__main__", mod)
    assert agent_main_mod.cmd_install_browsers() == 3


def test_install_browsers_missing_playwright_is_clean_error(monkeypatch: pytest.MonkeyPatch) -> None:
    real_import = builtins.__import__

    def _no_playwright(name: str, *a: object, **k: object):
        if name.startswith("playwright"):
            raise ImportError(name)
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", _no_playwright)
    assert agent_main_mod.cmd_install_browsers() == 2


def test_install_browsers_restores_sys_argv_and_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    mod = types.ModuleType("playwright.__main__")
    seen: dict[str, object] = {}

    def _spy() -> None:
        seen["argv"] = list(sys.argv)
        sys.exit(0)

    mod.main = _spy
    monkeypatch.setitem(sys.modules, "playwright.__main__", mod)
    argv_before = list(sys.argv)
    agent_main_mod.cmd_install_browsers(all_browsers=True)
    assert seen["argv"][:2] == ["playwright", "install"]
    assert "chromium" in seen["argv"] and "firefox" in seen["argv"]
    assert sys.argv == argv_before  # restored
    # sys.exit restored: raising SystemExit propagates normally again
    with pytest.raises(SystemExit):
        sys.exit(5)


def test_install_browsers_parser_wiring() -> None:
    parser = agent_main_mod.build_parser()
    args = parser.parse_args(["install-browsers", "--all"])
    assert args.command == "install-browsers" and args.all is True
    args2 = parser.parse_args(["install-browsers"])
    assert args2.all is False


# ---------------------------------------------------------------------------
# gui.main subcommand dispatch
# ---------------------------------------------------------------------------


def test_gui_main_dispatches_agent_subcommands(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[list[str]] = []

    fake_main = types.ModuleType("main")
    fake_main.main = lambda argv=None: (sent.append(argv), 7)[1]
    monkeypatch.setitem(sys.modules, "main", fake_main)
    monkeypatch.setattr(gui, "FROZEN", True)  # skip MAIN_PY existence check

    assert gui.main(["report", "some/run"]) == 7
    assert sent == [["report", "some/run"]]


def test_gui_main_non_subcommand_goes_to_window(monkeypatch: pytest.MonkeyPatch) -> None:
    """Anything that is not an agent subcommand must open the GUI, never run
    the agent. QAGui is stubbed: instantiating it raises a sentinel that we
    catch — proving the window path was taken without blocking on mainloop."""
    called = {"agent": False}

    fake_main = types.ModuleType("main")
    fake_main.main = lambda argv=None: (called.__setitem__("agent", True), 0)[1]
    monkeypatch.setitem(sys.modules, "main", fake_main)
    monkeypatch.setattr(gui, "FROZEN", True)

    class _WindowOpened(BaseException):
        pass

    class FakeGui:
        def __init__(self) -> None:
            raise _WindowOpened()

    monkeypatch.setattr(gui, "QAGui", FakeGui)
    with pytest.raises(_WindowOpened):
        gui.main(["--frobnicate"])
    assert called["agent"] is False
