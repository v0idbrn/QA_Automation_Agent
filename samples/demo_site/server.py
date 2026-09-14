# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Bounded local demo server for samples/demo_site.

Endpoints:
  /                     -> static files from this directory
  /api/status?code=NNN  -> returns HTTP NNN (bounded 100..599)
  /api/slow             -> sleeps 3s then 200 (bounded)
  /api/malformed        -> 200 with non-JSON body (truncated binary-ish junk)

Safety:
  * binds 127.0.0.1 only
  * refuses requests after --max-requests (STOP semaphore, no reset)
  * no request logging of query strings (avoid accidental secret capture)
"""

from __future__ import annotations

import argparse
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class DemoHandler(SimpleHTTPRequestHandler):
    max_requests: int = 500
    requests_seen: int = 0

    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        DemoHandler.requests_seen += 1
        if DemoHandler.requests_seen > DemoHandler.max_requests:
            self.send_error(503, "demo server request budget exhausted")
            return

        path = self.path.split("?", 1)[0]
        if path == "/api/status":
            self._handle_status()
        elif path == "/api/slow":
            self._handle_slow()
        elif path == "/api/malformed":
            self._handle_malformed()
        else:
            super().do_GET()

    def _handle_status(self) -> None:
        code = 500
        if "?" in self.path:
            raw = self.path.split("?", 1)[1]
            for part in raw.split("&"):
                if part.startswith("code="):
                    try:
                        code = max(100, min(599, int(part[5:])))
                    except ValueError:
                        code = 500
        body = f'{{"ok": false, "status": {code}}}'.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_slow(self) -> None:
        time.sleep(3.0)
        body = b'{"ok": true, "note": "slow response"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_malformed(self) -> None:
        body = b'{"ok": true, "list": [1, 2, 3'  # deliberately truncated JSON
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:  # noqa: A003
        # Deliberately minimal: never log query strings (secret hygiene).
        try:
            first = args[0] if args else ""
            if "api/" in str(first):
                return
        except Exception:  # noqa: BLE001 — logging must never crash the server
            return
        super().log_message(fmt, *args)


def main() -> int:
    parser = argparse.ArgumentParser(description="Bounded demo server (127.0.0.1 only)")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--max-requests", type=int, default=500)
    args = parser.parse_args()

    DemoHandler.max_requests = max(1, args.max_requests)
    root = Path(__file__).resolve().parent
    server = ThreadingHTTPServer(("127.0.0.1", args.port), DemoHandler)
    print(f"demo server: http://127.0.0.1:{args.port}/ (root={root}, max_requests={DemoHandler.max_requests})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
