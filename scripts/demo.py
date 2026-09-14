# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
One-command reproducible demo.

INPUT  -> the bundled synthetic site (samples/demo_site) with deliberate,
          harmless defects (broken link, console errors, missing alt,
          500 endpoint, malformed JSON, blocked /admin path).
PROCESS-> a full autonomous audit cycle (discovery -> requirements -> risk ->
          plan -> generate -> live browser execution -> findings -> gate).
OUTPUT -> a professional report set in reports/demo_run/ (Markdown, HTML,
          JSON, Jira draft, run manifest, evidence).

Safety: the demo server binds 127.0.0.1 only, has a hard request cap, and is
always stopped in a finally block — including on Ctrl+C.

Usage:
    .venv/Scripts/python scripts/demo.py [--port 8000] [--profile standard]
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEMO_DIR = ROOT / "samples" / "demo_site"
SERVER = DEMO_DIR / "server.py"
OUTPUT = ROOT / "reports" / "demo_run"
PYTHON = Path(sys.executable)
MAX_DEMO_REQUESTS = 250


def wait_for_server(port: int, timeout_s: float = 15.0) -> bool:
    """Poll until the demo server answers. Returns True when ready."""
    import urllib.request

    deadline = time.monotonic() + timeout_s
    url = f"http://127.0.0.1:{port}/index.html"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status == 200:
                    return True
        except Exception:  # noqa: BLE001 — not ready yet; keep polling
            time.sleep(0.3)
    return False


def main() -> int:
    # Windows consoles may default to cp1252; keep the output robust.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except Exception:  # noqa: BLE001 — best-effort console fix
                pass
    parser = argparse.ArgumentParser(description="Run the reproducible QA demo end-to-end")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--profile", default="standard", choices=["safe", "standard", "deep", "ci"])
    args = parser.parse_args()

    if not SERVER.exists():
        print(f"demo server not found: {SERVER}", file=sys.stderr)
        return 2

    venv_scripts = PYTHON.parent
    main_py = ROOT / "main.py"
    cmd = [
        str(PYTHON),
        str(main_py),
        "run",
        "samples/demo_site",
        "--profile",
        args.profile,
        "--url",
        f"http://127.0.0.1:{args.port}",
        "--output",
        str(OUTPUT.relative_to(ROOT)),
        "--min-coverage",
        "0.02",
    ]

    print(f"[demo] starting bounded demo server on 127.0.0.1:{args.port} (max {MAX_DEMO_REQUESTS} requests)")
    server_proc: subprocess.Popen | None = None
    try:
        server_proc = subprocess.Popen(
            [str(PYTHON), str(SERVER), "--port", str(args.port), "--max-requests", str(MAX_DEMO_REQUESTS)],
            cwd=DEMO_DIR,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if not wait_for_server(args.port):
            print("[demo] demo server did not become ready in time", file=sys.stderr)
            return 1
        print("[demo] server ready — launching the autonomous audit")
        result = subprocess.run(cmd, cwd=ROOT)
        print(f"[demo] audit finished with exit code {result.returncode}")
        print(f"[demo] reports: {OUTPUT}")
        print("[demo] open reports/demo_run/audit_report.html in a browser to review")
        return result.returncode
    except KeyboardInterrupt:
        print("\n[demo] interrupted — run manifest records the interruption", file=sys.stderr)
        return 130
    finally:
        if server_proc is not None and server_proc.poll() is None:
            server_proc.terminate()
            try:
                server_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_proc.kill()
            print("[demo] demo server stopped")


if __name__ == "__main__":
    raise SystemExit(main())
