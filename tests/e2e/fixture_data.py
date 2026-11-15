# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Shared fixture payloads for the deterministic E2E server and ASGI app."""

from __future__ import annotations

import json
from typing import Any


def _json(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload).encode("utf-8")


API_RESPONSES: dict[str, tuple[int, str, bytes]] = {
    "/api/health": (
        200,
        "application/json",
        _json(
            {
                "status": "ok",
                "version": "1.2.3",
                "checks": [{"name": "database", "ok": True}, {"name": "cache", "ok": True}],
            }
        ),
    ),
    "/api/items/1": (
        200,
        "application/json",
        _json({"id": 1, "name": "widget", "price": 9.99, "tags": ["alpha", "beta"]}),
    ),
    "/api/items/bad": (
        200,
        "application/json",
        _json({"id": "one", "name": 7, "price": "free", "tags": "none"}),
    ),
    "/api/incomplete": (200, "application/json", _json({"id": 2})),
    "/api/extra": (
        200,
        "application/json",
        _json({"id": 2, "name": "widget", "price": 1.0, "tags": [], "debug": True}),
    ),
    "/api/missing": (
        404,
        "application/json",
        _json({"error": "not_found", "message": "resource missing"}),
    ),
    "/api/crash": (
        500,
        "application/json",
        _json({"error": "internal_error", "message": "unexpected failure"}),
    ),
    "/api/leaky-error": (
        500,
        "application/json",
        _json(
            {
                "error": "internal_error",
                "message": "unexpected failure",
                "traceback": "Traceback (most recent call last): ...",
            }
        ),
    ),
    "/api/not-json": (200, "text/html", b"<html><body>not json</body></html>"),
    "/api/malformed": (200, "application/json", b'{"ok": '),
}

PAGES: dict[str, str] = {
    "/": """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Clean QA fixture</title>
  <style>
    html, body { margin: 0; max-width: 100%; overflow-x: hidden; font-family: sans-serif; }
    .wrap { padding: 16px; max-width: 100%; }
    .card { border: 1px solid #ccc; padding: 12px; max-width: 100%; }
  </style>
</head>
<body>
  <main class="wrap">
    <h1>QA Fixture</h1>
    <section class="card"><p>Responsive content with no overflow.</p></section>
  </main>
</body>
</html>""",
    "/clean.html": """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Clean mobile page</title>
  <style>
    * { box-sizing: border-box; }
    html, body { margin: 0; width: 100%; max-width: 100%; overflow-x: hidden; font-family: sans-serif; }
    .wrap { padding: 16px; width: 100%; }
    .card { border: 1px solid #ccc; padding: 12px; width: 100%; }
  </style>
</head>
<body>
  <main class="wrap">
    <h1>Mobile ready</h1>
    <section class="card"><p>This page fits a 390px viewport.</p></section>
  </main>
</body>
</html>""",
    "/noisy.html": """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Noisy fixture</title>
  <style>
    body { margin: 0; font-family: sans-serif; }
    #wide { width: 900px; height: 24px; background: #c00; }
  </style>
</head>
<body>
  <main>
    <h1>Noisy fixture</h1>
    <div id="wide"></div>
  </main>
  <script>console.error("fixture console failure");</script>
</body>
</html>""",
    "/page-error.html": """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Page error fixture</title></head>
<body>
  <h1>Page error fixture</h1>
  <script>setTimeout(function () { throw new Error("fixture page error"); }, 0);</script>
</body>
</html>""",
}

# A minimal ASGI application used to prove HTTPX contract checks also work
# without binding a socket. It shares the exact payloads of the HTTP server.
async def asgi_app(scope: dict[str, Any], receive: Any, send: Any) -> None:
    if scope["type"] != "http":
        return

    path = scope.get("path", "/")
    if path in API_RESPONSES:
        status, content_type, body = API_RESPONSES[path]
    elif path in PAGES:
        status, content_type, body = 200, "text/html", PAGES[path].encode("utf-8")
    else:
        status, content_type, body = (
            404,
            "application/json",
            _json({"error": "not_found", "message": "resource missing"}),
        )

    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", content_type.encode("ascii")),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
