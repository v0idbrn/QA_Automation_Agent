# -*- mode: python ; coding: utf-8 -*-
# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
PyInstaller spec — QA Automation Agent.

Builds TWO executables from ONE onedir bundle (shared runtime, half the size
of two onefiles):

  dist/QA_Agent/QA_Agent.exe   windowed GUI control center (no console box)
  dist/QA_Agent/qa-agent.exe   console CLI (same flags as `main.py`)

The GUI exe re-invokes ITSELF with a subcommand to run audits (see
`gui.agent_invocation`), so both binaries stay the same agent.

Data:
  reports/*.jinja            report templates (bundled for frozen rendering)
  playwright/driver/*        the Node driver — required for live browser runs

Deliberately EXCLUDED: the agent's own test tooling (pytest) — the product
binary ships the auditor, not its test suite.

Both exes receive the data: the windowed GUI exe doubles as the headless
runner (it re-invokes itself with a subcommand), so it must also be able to
render reports and drive browsers.
"""

from pathlib import Path
import sys

from PyInstaller.utils.hooks import collect_submodules

PROJECT = Path(SPECPATH).resolve()

# --- data -----------------------------------------------------------------
datas = []
for template in sorted((PROJECT / "reports").glob("*.jinja")):
    datas.append((str(template), "reports"))

import playwright  # noqa: E402 — resolved against the build interpreter

driver_dir = Path(playwright.__file__).resolve().parent / "driver"
if driver_dir.is_dir():
    datas.append((str(driver_dir), "playwright/driver"))

# --- hidden imports ---------------------------------------------------------
# pydantic v2 imports some submodules dynamically (e.g. inside
# pydantic.deprecated); collect_submodules keeps the frozen import honest.
agent_hidden = [
    "playwright",
    "playwright._impl._driver",
    "jinja2.ext",
    *collect_submodules("pydantic"),
]

# The product ships without the agent's own test stack.
excludes = ["pytest", "_pytest", "pytest_asyncio", "setuptools", "pip", "wheel"]

# --- analyses ----------------------------------------------------------------
# BOTH exes need the data + hidden imports: the windowed GUI exe doubles as
# the headless runner (gui.agent_invocation self-spawns it with a subcommand),
# so it also renders reports from bundled templates and drives Playwright.
gui_a = Analysis(
    ["gui.py"],
    pathex=[str(PROJECT)],
    binaries=[],
    datas=datas,
    hiddenimports=agent_hidden,
    hookspath=[],
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
)

cli_a = Analysis(
    ["main.py"],
    pathex=[str(PROJECT)],
    binaries=[],
    datas=datas,
    hiddenimports=agent_hidden,
    hookspath=[],
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
)

pyz_gui = PYZ(gui_a.pure)
pyz_cli = PYZ(cli_a.pure)

exe_gui = EXE(
    pyz_gui,
    gui_a.scripts,
    [],
    exclude_binaries=True,
    name="QA_Agent",
    console=False,
    disable_windowed_traceback=False,
    icon=None,
)

exe_cli = EXE(
    pyz_cli,
    cli_a.scripts,
    [],
    exclude_binaries=True,
    name="qa-agent",
    console=True,
    icon=None,
)

coll = COLLECT(
    exe_gui,
    exe_cli,
    gui_a.binaries,
    gui_a.zipfiles,
    gui_a.datas,
    cli_a.binaries,
    cli_a.zipfiles,
    cli_a.datas,
    strip=False,
    upx=False,
    name="QA_Agent",
)
