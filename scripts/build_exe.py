# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Build the standalone Windows bundle: dist/QA_Agent/{QA_Agent.exe, qa-agent.exe}.

Usage:
    python scripts/build_exe.py           # build + smoke-test
    python scripts/build_exe.py --no-test # build only

Prereqs: PyInstaller in the venv (`pip install pyinstaller`), and Playwright
browsers installed on the TARGET machine at first `run` (the bundle ships the
driver; engines download once via `qa-agent.exe install-browsers`).
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist" / "QA_Agent"


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the standalone exe bundle")
    ap.add_argument("--no-test", action="store_true", help="Skip post-build smoke tests")
    args = ap.parse_args()

    py = sys.executable
    if shutil.which(py) is None and not Path(py).exists():
        print(f"python not found: {py}", file=sys.stderr)
        return 2

    # 1. prereqs -------------------------------------------------------------
    try:
        import PyInstaller  # noqa: F401

        print(f"[1/4] PyInstaller {PyInstaller.__version__} present")
    except ImportError:
        print("PyInstaller missing — installing into the venv ...")
        subprocess.check_call([py, "-m", "pip", "install", "pyinstaller"])

    # 2. templates must exist (the bundle needs them) --------------------------
    templates = sorted((ROOT / "reports").glob("*.jinja"))
    if not {"audit_report.html.jinja", "audit_report.md.jinja"} <= {t.name for t in templates}:
        print("missing report templates in reports/ — cannot bundle", file=sys.stderr)
        return 2
    print(f"[2/4] templates found: {', '.join(t.name for t in templates)}")

    # 3. build -----------------------------------------------------------------
    print("[3/4] running PyInstaller (takes a couple of minutes) ...")
    subprocess.check_call([py, "-m", "PyInstaller", "qa_agent.spec", "--noconfirm", "--clean"], cwd=ROOT)

    gui_exe = DIST / "QA_Agent.exe"
    cli_exe = DIST / "qa-agent.exe"
    for exe in (gui_exe, cli_exe):
        if not exe.is_file():
            print(f"build finished but {exe.name} is missing", file=sys.stderr)
            return 1
    print(f"[3/4] built: {DIST}")

    # 4. smoke tests ------------------------------------------------------------
    if args.no_test:
        print("[4/4] skipped (--no-test)")
        return 0

    print("[4/4] smoke-testing CLI exe ...")
    help_out = subprocess.run(
        [str(cli_exe), "--help"], capture_output=True, text=True, timeout=120, cwd=DIST
    )
    if help_out.returncode != 0 or "run" not in help_out.stdout:
        print("qa-agent.exe --help failed:\n" + help_out.stdout + help_out.stderr, file=sys.stderr)
        return 1
    print("      qa-agent.exe --help: OK")

    bad = subprocess.run(
        [str(cli_exe), "report", "does-not-exist"], capture_output=True, text=True, timeout=120, cwd=DIST
    )
    if bad.returncode == 0:
        print("qa-agent.exe report <missing> must exit non-zero", file=sys.stderr)
        return 1
    print(f"      qa-agent.exe error path: OK (exit {bad.returncode})")

    print("[4/4] smoke-testing GUI exe (launch + auto-close) ...")
    try:
        proc = subprocess.Popen([str(gui_exe)], cwd=DIST)
        try:
            rc = proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            print("      GUI stayed open >15s: treating as OK (window shown)")
            return 0
        if rc == 0:
            print("      GUI exe: OK")
            return 0
        print(f"      GUI exe exited early with {rc}", file=sys.stderr)
        return 1
    except FileNotFoundError:
        print("      could not launch GUI exe", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
