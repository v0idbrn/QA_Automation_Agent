# Broken link check

Purpose: crawl in-scope pages and record HTTP/navigation failures.
Inputs: origin URL, Scope, Budget.
Outputs: crawl findings bound into the unified Finding model.
Privacy: local Playwright only; no cloud upload.
Engine: `core.crawler`.
