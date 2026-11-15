# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Local, fast, multi-route fixture with intentionally seeded SaaS defects.

Every defect here is deliberate and inert: no real credential, no destructive
behaviour. The server exists so crawler, accessibility, security, checkout,
API fuzzing, and self-healing tests can run offline in a few seconds.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Iterator
from contextlib import contextmanager

__all__ = ["FixtureHandler", "chaos_app", "start_fixture_server", "vulnerable_saas_server"]

LOGO_BYTES = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\xcf\xc0"
    b"\x00\x00\x03\x01\x01\x00\x18\xdd\x8d\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
)

HOME_HTML = """<!DOCTYPE html>
<html>
<head>
  <title>Vulnerable SaaS Fixture</title>
  <script src="/assets/app.js"></script>
</head>
<body>
  <h1>Acme Billing</h1>
  <h4>Plans and pricing</h4>
  <div style="width: 1400px">
    <p style="color: #999999; background-color: #aaaaaa">Low contrast promotional copy that stretches far to the right.</p>
  </div>
  <nav>
    <a href="/checkout">Checkout</a>
    <a href="/about">About</a>
    <a href="/missing-page">Broken page</a>
  </nav>
  <form action="/api/checkout" method="post">
    <input name="email" type="email">
    <button type="submit">Pay now</button>
  </form>
  <img src="/logo.png">
  <img src="/missing.png" alt="broken preview">
  <div style="position: fixed; top: 0; left: 0; width: 100%; height: 60%; background: rgba(0,0,0,0.5)">Cookie wall</div>
  <script>console.error("fixture console error: cart sync failed");</script>
</body>
</html>
"""

CHECKOUT_HTML = """<!DOCTYPE html>
<html lang="en">
<head><title>Checkout</title></head>
<body>
  <h1>Checkout</h1>
  <form id="checkout" action="/api/checkout" method="post">
    <label for="quantity">Quantity</label>
    <input id="quantity" name="quantity" type="number" value="1">
    <label for="card">Card number</label>
    <input id="card" name="card" type="text">
    <button type="submit" data-testid="place-order">Place order</button>
  </form>
  <button aria-label="Apply coupon">Apply</button>
  <button></button>
  <script>
    document.getElementById("checkout").addEventListener("submit", function (event) {
      window.__submitted = (window.__submitted || 0) + 1;
    });
  </script>
</body>
</html>
"""

ABOUT_HTML = """<!DOCTYPE html>
<html lang="en">
<head><title>About</title></head>
<body><h1>About</h1><p>Fixture company page.</p><a href="/">Home</a></body>
</html>
"""

DYNAMIC_HTML = """<!DOCTYPE html>
<html lang="en">
<head><title>Dynamic</title></head>
<body>
  <h1>Live totals</h1>
  <button data-testid="buy-button">Buy now</button>
  <div id="total">$10.00</div>
  <script>
    setTimeout(function () {
      document.querySelector('[data-testid="buy-button"]').textContent = "Purchase";
      document.getElementById("total").textContent = "$12.50";
    }, 50);
  </script>
</body>
</html>
"""

APP_JS = """
const config = { apiKey: "sk-live-ABCDEFGHIJKLMNOPQRSTUVWX", mode: "production" };
export function boot() { return config; }
"""


class FixtureHandler(BaseHTTPRequestHandler):
    server_version = "VulnerableSaaS/1.0"
    protocol_version = "HTTP/1.1"
    order_counter = 0

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003 - stdlib API
        return

    # -- helpers ----------------------------------------------------------
    def _send(self, status: int, body: bytes, content_type: str = "application/json", extra_headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _json(self, status: int, payload: Any, extra_headers: dict[str, str] | None = None) -> None:
        self._send(status, json.dumps(payload).encode("utf-8"), "application/json", extra_headers)

    def _body(self) -> Any:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return None
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8", "replace"))
        except (ValueError, UnicodeDecodeError):
            return raw.decode("utf-8", "replace")

    # -- routes -----------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 - stdlib API
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._send(200, HOME_HTML.encode("utf-8"), "text/html; charset=utf-8")
        elif path == "/checkout":
            self._send(200, CHECKOUT_HTML.encode("utf-8"), "text/html; charset=utf-8")
        elif path == "/about":
            self._send(200, ABOUT_HTML.encode("utf-8"), "text/html; charset=utf-8")
        elif path == "/dynamic":
            self._send(200, DYNAMIC_HTML.encode("utf-8"), "text/html; charset=utf-8")
        elif path == "/logo.png":
            self._send(200, LOGO_BYTES, "image/png")
        elif path == "/assets/app.js":
            self._send(200, APP_JS.encode("utf-8"), "application/javascript")
        elif path == "/api/health":
            self._json(200, {"status": "ok", "version": "1.0.0"})
        elif path == "/missing-page":
            self._send(404, b"<html><body><h1>Not found</h1></body></html>", "text/html; charset=utf-8")
        elif path == "/api/orders":
            self._json(200, {"orders": []})
        elif path == "/favicon.ico":
            self._send(204, b"", "image/x-icon")
        else:
            self._json(404, {"error": "not_found", "message": "resource missing"})

    def do_POST(self) -> None:  # noqa: N802 - stdlib API
        path = self.path.split("?", 1)[0]
        payload = self._body()
        if path == "/api/checkout":
            FixtureHandler.order_counter += 1
            self._json(
                200,
                {
                    "order_id": f"ord-{FixtureHandler.order_counter}",
                    "quantity": payload.get("quantity") if isinstance(payload, dict) else None,
                    "currency": payload.get("currency") if isinstance(payload, dict) else None,
                    "total": 10.0 * float(payload.get("quantity", 1)) if isinstance(payload, dict) else 10.0,
                },
                # Deliberately weak cookie flags, no CSP/HSTS: seeded security defects.
                {"Set-Cookie": "session=demo-session; Path=/"},
            )
        elif path == "/api/validate":
            value = payload.get("input") if isinstance(payload, dict) else payload
            text = "" if value is None else str(value)
            if any(token in text for token in ("'", "DROP TABLE", "UNION SELECT")):
                self._send(
                    500,
                    b'{"error":"internal","message":"Traceback (most recent call last):\\n  File \\"/app/checkout.py\\", line 42, in validate"}',
                )
            elif "<script" in text or "javascript:" in text:
                self._json(200, {"echo": text})
            elif isinstance(value, (list, dict, bool, int, float)) or text.strip() == "" or "\x00" in text:
                self._json(400, {"error": "validation", "message": "invalid input"})
            else:
                self._json(200, {"accepted": True})
        elif path == "/graphql":
            query = str((payload or {}).get("query", "")) if isinstance(payload, dict) else ""
            if "__schema" in query:
                self._json(200, {"data": {"__schema": {"types": [{"name": "User"}, {"name": "Order"}]}}})
            elif "nonexistentField" in query:
                self._json(
                    200,
                    {
                        "errors": [
                            {
                                "message": "Cannot query field 'nonexistentField'",
                                "stacktrace": "at resolve (/app/src/resolver.js:10:5)",
                            }
                        ]
                    },
                )
            else:
                self._json(200, {"data": {"ok": True}})
        elif path == "/api/slow":
            self._json(200, {"status": "ok"})
        else:
            self._json(404, {"error": "not_found", "message": "resource missing"})


@contextmanager
def start_fixture_server() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def vulnerable_saas_server() -> tuple[ThreadingHTTPServer, str]:
    """Start the fixture server and return ``(server, base_url)`` for tests."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_port}"


def chaos_app() -> dict[str, Any]:
    """Small ASGI app used for transport-level fuzzing tests without sockets."""
    async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            return
        path = scope.get("path", "/")
        status = 200
        body: dict[str, Any] = {"ok": True}
        if path == "/api/echo":
            status = 400
            body = {"error": "validation", "message": "input required"}
        elif path == "/api/boom":
            status = 500
            body = {"error": "internal", "trace": "Traceback (most recent call last)"}
        await send({"type": "http.response.start", "status": status, "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": json.dumps(body).encode("utf-8")})

    return {"app": app}
