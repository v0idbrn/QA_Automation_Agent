# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Session fixture: a bounded local HTTP server for deterministic E2E tests."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

import pytest

from tests.e2e.fixture_data import API_RESPONSES, PAGES


class _FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 (stdlib handler API)
        path = self.path.split("?", 1)[0]
        if path in API_RESPONSES:
            status, content_type, body = API_RESPONSES[path]
        elif path in PAGES:
            status, content_type, body = 200, "text/html; charset=utf-8", PAGES[path].encode("utf-8")
        elif path == "/favicon.ico":
            status, content_type, body = 204, "image/x-icon", b""
        else:
            status, content_type, body = (
                404,
                "application/json",
                b'{"error": "not_found", "message": "resource missing"}',
            )

        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:  # noqa: A003
        return


@pytest.fixture(scope="session")
def fixture_server() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
