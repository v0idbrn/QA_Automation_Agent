# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Scope guard and safety budgets for crawling, fuzzing, and auditing.

Scope enforcement is read-only and defensive by default. Ambiguous targets
must fail safely instead of expanding into unconstrained exploration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse


@dataclass(frozen=True)
class Scope:
    allowed_origin: str
    allowed_paths: tuple[str, ...] = ()
    allow_external: bool = False
    max_depth: int = 2
    max_pages: int = 25
    max_requests: int = 100
    max_runtime_seconds: int = 300
    per_request_timeout_seconds: int = 20
    concurrency_limit: int = 3

    def is_allowed(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        if parsed.netloc != urlparse(self.allowed_origin).netloc:
            return False
        if not self.allow_external:
            return False
        if self.allowed_paths:
            path = parsed.path.rstrip("/") or "/"
            if path not in self.allowed_paths:
                return False
        return True

    def check_same_origin(self, url: str) -> bool:
        return urlparse(url).netloc == urlparse(self.allowed_origin).netloc


@dataclass
class Budget:
    scope: Scope
    used_pages: int = 0
    used_requests: int = 0
    started_at: float | None = None
    exhausted_reason: str | None = None

    def start(self) -> None:
        import time

        self.started_at = time.monotonic()

    def consume_page(self) -> bool:
        if not self._within_runtime():
            self.exhausted_reason = "runtime budget exhausted"
            return False
        if self.used_pages >= self.scope.max_pages:
            self.exhausted_reason = "page budget exhausted"
            return False
        self.used_pages += 1
        return True

    def consume_request(self) -> bool:
        if not self._within_runtime():
            self.exhausted_reason = "runtime budget exhausted"
            return False
        if self.used_requests >= self.scope.max_requests:
            self.exhausted_reason = "request budget exhausted"
            return False
        self.used_requests += 1
        return True

    def _within_runtime(self) -> bool:
        if self.started_at is None:
            return True
        import time

        elapsed = time.monotonic() - self.started_at
        return elapsed <= self.scope.max_runtime_seconds

    def is_exhausted(self) -> bool:
        return self.exhausted_reason is not None


class ScopeViolationError(Exception):
    def __init__(self, message: str, url: str | None = None):
        super().__init__(message)
        self.url = url
