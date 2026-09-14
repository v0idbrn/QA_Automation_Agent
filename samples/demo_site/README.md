# Demo Target — `samples/demo_site`

A small, safe, **local-only** website with deliberate, reproducible problems
for validating the QA agent end-to-end. It is a pure static site plus one
bounded local server script. Nothing here contacts the internet.

## Deliberate findings

| # | Finding | Where |
|---|---------|-------|
| 1 | Broken internal link (`missing-page.html` → 404) | `index.html` |
| 2 | `<img>` without `alt` | `index.html`, `api_page.html` |
| 3 | Heading hierarchy skip (`h1 → h3`, `h1 → h4`) | `index.html`, `products.html` |
| 4 | Duplicate `id="main-content"` | `index.html` + `products.html` |
| 5 | Unlabeled form input (`promo`) | `products.html` |
| 6 | Console error on load | `products.html`, `api_page.html`, `loop.html` |
| 7 | API returning configurable 4xx/5xx | `server.py /api/status?code=NNN` |
| 8 | Slow endpoint (3 s) | `server.py /api/slow` |
| 9 | Malformed JSON endpoint | `server.py /api/malformed` |
| 10 | Fragment / self-loop links | `deep/loop.html` |
| 11 | Admin-style path (scope demo) | `index.html → admin.html` |
| 12 | External absolute link (denied by default scope) | `index.html` |

## Reproducible audit

```bash
# Terminal 1 — serve the demo site (bounded, localhost only)
cd samples/demo_site
../../.venv/Scripts/python server.py --port 8000 --max-requests 200

# Terminal 2 — audit it
cd ../..
.venv/Scripts/python main.py run samples/demo_site --profile safe --url http://127.0.0.1:8000 --output reports/demo_run
```

Or audit the static folder only (no server):

```bash
.venv/Scripts/python main.py run samples/demo_site --profile safe --output reports/demo_static
```

The demo server refuses to serve more than `--max-requests` responses and
never logs query strings, keeping the demo itself aligned with the agent's
safety model.
