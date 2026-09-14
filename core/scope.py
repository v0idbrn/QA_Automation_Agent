# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Scope guard DENY-UNKNOWN, Test Budget STOP-semaphore, and Resource Governor.

Scope: ambiguous targets fail closed (DENY UNKNOWN). Same-origin is only
permitted when `allow_external=False` AND the netloc matches exactly. No
auto-expansion into adjacent domains.

Budget: once ANY `max_*` limit is reached, `is_exhausted()` stays True
forever — no auto-reset. Callers must STOP immediately.

ResourceGovernor: caps browser contexts, temp files, artifact bytes, and
screenshot count to avoid unbounded growth during long runs.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import urlparse

from core.models import ProjectScope, BudgetConfig, ResourceBudget


class ScopeViolationError(Exception):
    """Raised when an action violates the declared scope.

    Callers must NOT auto-recover from this. It indicates either a planner
    bug (produced an out-of-scope action) or a compromised executor.
    """

    def __init__(self, message: str, url: str | None = None, *, detail: str = ""):
        super().__init__(message)
        self.url = url
        self.detail = detail


_DEFAULT_ALLOWED_METHODS = ("GET", "HEAD", "OPTIONS")
_DEFAULT_BLOCKED_PATH_TOKENS = ("/admin", "/delete", "/drop", "/reset", "/logout", "/signout")


@dataclass
class OmitRecord:
    """Why a URL/page/endpoint was skipped. Useful for audit / observability."""

    url: str
    reason: str
    category: str = "scope"


class Scope:
    """DENY-UNKNOWN scope guard.

    SEMANTICS (fail-closed contract):
      * Nothing is authorized implicitly. With no allowlist configured and
        `default_allow_same_origin=False`, `is_allowed()` returns False even
        for the configured origin.
      * Same-origin is only auto-permitted when `default_allow_same_origin=True`
        (the CLI sets this so `run <target>` is usable) or when an explicit
        allowlist (`allowed_paths` / `allowed_endpoints`) exists.
      * Cross-origin requires `allow_external=True`.
    """

    def __init__(
        self,
        allowed_origin: str,
        allowed_paths: Iterable[str] = (),
        allow_external: bool = False,
        max_depth: int = 2,
        max_pages: int = 25,
        max_requests: int = 100,
        max_runtime_seconds: int = 300,
        per_request_timeout_seconds: int = 20,
        concurrency_limit: int = 3,
        *,
        allowed_methods: Iterable[str] | None = None,
        allowed_endpoints: Iterable[str] = (),
        blocked_paths: Iterable[str] = (),
        allow_uploads: bool = False,
        allow_filesystem_write: bool = False,
        project_scope: ProjectScope | None = None,
        default_allow_same_origin: bool = False,
    ) -> None:
        self.allowed_origin = allowed_origin.rstrip("/")
        self.allowed_paths = tuple(allowed_paths)
        self.allow_external = bool(allow_external)
        self.max_depth = int(max_depth)
        self.max_pages = int(max_pages)
        self.max_requests = int(max_requests)
        self.max_runtime_seconds = int(max_runtime_seconds)
        self.per_request_timeout_seconds = int(per_request_timeout_seconds)
        self.concurrency_limit = int(concurrency_limit)
        self.allowed_methods: tuple[str, ...] = tuple(m.upper() for m in (allowed_methods or _DEFAULT_ALLOWED_METHODS))
        self.allowed_endpoints: tuple[str, ...] = tuple(allowed_endpoints)
        self.blocked_paths: tuple[str, ...] = tuple(blocked_paths) or _DEFAULT_BLOCKED_PATH_TOKENS
        self.allow_uploads = bool(allow_uploads)
        self.allow_filesystem_write = bool(allow_filesystem_write)
        self.default_allow_same_origin = bool(default_allow_same_origin)
        self._omits: list[OmitRecord] = []
        if project_scope is not None:
            self._merge_project_scope(project_scope)
        self._origin_parsed = urlparse(self.allowed_origin)

    # ------------------------------------------------------------------
    # Backward compat helpers
    # ------------------------------------------------------------------
    def _merge_project_scope(self, ps: ProjectScope) -> None:
        if ps.allowed_origins and self.allowed_origin not in ps.allowed_origins:
            self.allowed_origin = ps.allowed_origins[0]
        if ps.allowed_methods:
            self.allowed_methods = tuple(ps.allowed_methods)
        if ps.allowed_paths:
            self.allowed_paths = tuple(ps.allowed_paths)
        if ps.blocked_paths:
            self.blocked_paths = tuple(ps.blocked_paths)
        self.allow_external = ps.allow_external or self.allow_external
        self.allow_uploads = ps.allow_uploads or self.allow_uploads
        self.allow_filesystem_write = ps.allow_filesystem_write or self.allow_filesystem_write
        if ps.max_depth is not None:
            self.max_depth = int(ps.max_depth)
        if ps.max_pages is not None:
            self.max_pages = int(ps.max_pages)
        if ps.max_requests is not None:
            self.max_requests = int(ps.max_requests)

    @property
    def project_scope(self) -> ProjectScope:
        return ProjectScope(
            allowed_origins=[self.allowed_origin],
            allowed_paths=list(self.allowed_paths) or None,
            allowed_methods=list(self.allowed_methods) or None,
            allowed_endpoints=list(self.allowed_endpoints) or None,
            blocked_paths=list(self.blocked_paths) or None,
            allow_external=self.allow_external,
            allow_uploads=self.allow_uploads,
            allow_filesystem_write=self.allow_filesystem_write,
            max_depth=self.max_depth,
            max_pages=self.max_pages,
            max_requests=self.max_requests,
        )

    # ------------------------------------------------------------------
    # URL / method enforcement
    # ------------------------------------------------------------------
    def _record_omit(self, url: str, reason: str, *, category: str = "scope") -> None:
        self._omits.append(OmitRecord(url=url, reason=reason, category=category))

    def omits(self) -> list[OmitRecord]:
        return list(self._omits)

    def check_same_origin(self, url: str) -> bool:
        try:
            return urlparse(url).netloc == self._origin_parsed.netloc
        except Exception:
            return False

    def is_allowed(self, url: str, *, method: str | None = None) -> bool:
        """DENY UNKNOWN. Returns True only for explicitly authorized targets.

        Fail-closed rules:
          1. scheme/method/path-token checks always apply;
          2. cross-origin requires allow_external=True (and path allowlist in
             external mode);
          3. same-origin requires an explicit authorization surface:
             default_allow_same_origin=True (CLI runs), an explicit path
             allowlist, or an explicit endpoint allowlist.
        """
        if not url:
            return False
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https", "file") and parsed.scheme != "":
            self._record_omit(url, f"disallowed scheme {parsed.scheme!r}")
            return False
        if method is not None and method.upper() not in self.allowed_methods:
            self._record_omit(url, f"method {method.upper()!r} not in allowlist", category="method")
            return False
        netloc_match = (not parsed.netloc) or parsed.netloc == self._origin_parsed.netloc
        if self.allow_external:
            if self.allowed_paths:
                path = parsed.path.rstrip("/") or "/"
                if path not in self.allowed_paths:
                    self._record_omit(url, "path not in allowlist (external mode)")
                    return False
            return True
        if not netloc_match:
            self._record_omit(url, "cross-origin and allow_external=False")
            return False
        # Same-origin: require an explicit authorization surface (fail closed).
        if not (self.default_allow_same_origin or self.allowed_paths or self.allowed_endpoints):
            self._record_omit(url, "same-origin requested but no authorization surface configured (DENY UNKNOWN)")
            return False
        path = parsed.path or "/"
        norm = path.rstrip("/") or "/"
        if self.allowed_paths and norm not in self.allowed_paths:
            self._record_omit(url, "path not in allowlist (same-origin restricted paths)")
            return False
        lowered = path.lower()
        for token in self.blocked_paths:
            if token.lower() in lowered:
                self._record_omit(url, f"blocked path token {token!r} matched")
                return False
        return True

    def assert_allowed(self, url: str, *, method: str | None = None) -> None:
        if not self.is_allowed(url, method=method):
            raise ScopeViolationError(
                "URL rejected by DENY-UNKNOWN scope guard",
                url=url,
                detail=f"method={method or 'ANY'} origin={self.allowed_origin}",
            )

    def assert_method_allowed(self, method: str) -> None:
        if method.upper() not in self.allowed_methods:
            raise ScopeViolationError(
                f"HTTP method {method.upper()!r} not in scope allowlist",
                detail=f"allowed={sorted(self.allowed_methods)}",
            )

    def assert_upload_allowed(self) -> None:
        if not self.allow_uploads:
            raise ScopeViolationError("uploads are disabled by scope policy")

    def assert_filesystem_write_allowed(self) -> None:
        if not self.allow_filesystem_write:
            raise ScopeViolationError("filesystem writes are disabled by scope policy")


class Budget:
    """STOP-semaphore budget. Once exhausted, stays exhausted forever."""

    def __init__(
        self,
        scope: Scope,
        *,
        config: BudgetConfig | None = None,
    ) -> None:
        self.scope = scope
        self.used_pages: int = 0
        self.used_requests: int = 0
        self.used_tests: int = 0
        self.used_retries: int = 0
        self.used_artifacts: int = 0
        self.started_at: float | None = None
        self.exhausted_reason: str | None = None
        self._config = config or BudgetConfig(
            max_tests=None,
            max_requests=scope.max_requests,
            max_pages=scope.max_pages,
            max_depth=scope.max_depth,
            max_runtime_seconds=scope.max_runtime_seconds,
            max_retries=3,
            max_concurrency=scope.concurrency_limit,
            max_artifacts=None,
            max_response_size_bytes=None,
        )

    # ------------------------------------------------------------------
    def start(self) -> None:
        if self.started_at is None:
            self.started_at = time.monotonic()

    # ------------------------------------------------------------------
    def _runtime_exceeded(self) -> bool:
        if self.started_at is None:
            return False
        if self._config.max_runtime_seconds is None:
            return False
        return (time.monotonic() - self.started_at) > float(self._config.max_runtime_seconds)

    def _exhaust(self, reason: str) -> bool:
        if self.exhausted_reason is None:
            self.exhausted_reason = reason
        return False

    def remaining(self) -> dict[str, int | None]:
        return {
            "pages": (None if self._config.max_pages is None else max(0, self._config.max_pages - self.used_pages)),
            "requests": (None if self._config.max_requests is None else max(0, self._config.max_requests - self.used_requests)),
            "tests": (None if self._config.max_tests is None else max(0, self._config.max_tests - self.used_tests)),
            "retries": (None if self._config.max_retries is None else max(0, self._config.max_retries - self.used_retries)),
            "artifacts": (None if self._config.max_artifacts is None else max(0, self._config.max_artifacts - self.used_artifacts)),
            "runtime_seconds": (None if self._config.max_runtime_seconds is None else max(0.0, float(self._config.max_runtime_seconds) - (time.monotonic() - (self.started_at or time.monotonic())))),
        }

    # ------------------------------------------------------------------
    def is_exhausted(self) -> bool:
        if self.exhausted_reason is not None:
            return True
        if self._runtime_exceeded():
            self._exhaust("runtime budget exhausted")
            return True
        return False

    def consume_page(self) -> bool:
        if self.is_exhausted():
            return False
        if self._config.max_pages is not None and self.used_pages >= self._config.max_pages:
            return self._exhaust("page budget exhausted")
        self.used_pages += 1
        return True

    def consume_request(self) -> bool:
        if self.is_exhausted():
            return False
        if self._config.max_requests is not None and self.used_requests >= self._config.max_requests:
            return self._exhaust("request budget exhausted")
        self.used_requests += 1
        return True

    def consume_test(self) -> bool:
        if self.is_exhausted():
            return False
        if self._config.max_tests is not None and self.used_tests >= self._config.max_tests:
            return self._exhaust("test budget exhausted")
        self.used_tests += 1
        return True

    def consume_retry(self) -> bool:
        if self.is_exhausted():
            return False
        if self._config.max_retries is not None and self.used_retries >= self._config.max_retries:
            return self._exhaust("retry budget exhausted")
        self.used_retries += 1
        return True

    def consume_artifact(self) -> bool:
        if self.is_exhausted():
            return False
        if self._config.max_artifacts is not None and self.used_artifacts >= self._config.max_artifacts:
            return self._exhaust("artifact budget exhausted")
        self.used_artifacts += 1
        return True

    def within_depth(self, depth: int) -> bool:
        if self.is_exhausted():
            return False
        if self._config.max_depth is None:
            return True
        if depth < 0 or depth > self._config.max_depth:
            self._exhaust(f"crawl depth {depth} exceeds max {self._config.max_depth}")
            return False
        return True

    def within_response_size(self, size_bytes: int) -> bool:
        if self.is_exhausted():
            return False
        if self._config.max_response_size_bytes is None:
            return True
        if size_bytes > self._config.max_response_size_bytes:
            self._exhaust(f"response size {size_bytes} exceeds cap {self._config.max_response_size_bytes}")
            return False
        return True


class ResourceGovernor:
    """Caps runtime resource consumption. No unbounded growth permitted."""

    def __init__(
        self,
        *,
        budget: ResourceBudget | None = None,
        max_browser_contexts: int = 4,
        max_temp_files: int = 512,
        max_total_artifact_bytes: int = 512 * 1024 * 1024,
        max_screenshots: int = 128,
    ) -> None:
        self._cfg = budget or ResourceBudget(
            max_memory_mb=None,
            max_browser_contexts=max_browser_contexts,
            max_processes=None,
            max_temp_files=max_temp_files,
            max_response_size_bytes=16 * 1024 * 1024,
            max_screenshots=max_screenshots,
            max_runtime_seconds=None,
        )
        self._browser_contexts = 0
        self._temp_files = 0
        self._screenshots = 0
        self._artifact_bytes = 0
        self._temp_paths: set[str] = set()
        self.rejections: list[str] = []

    # ------------------------------------------------------------------
    def register_browser_context(self) -> bool:
        if self._cfg.max_browser_contexts is not None and self._browser_contexts >= self._cfg.max_browser_contexts:
            self.rejections.append(f"browser contexts limit reached ({self._browser_contexts})")
            return False
        self._browser_contexts += 1
        return True

    def release_browser_context(self) -> None:
        self._browser_contexts = max(0, self._browser_contexts - 1)

    def register_temp_file(self, path: str) -> bool:
        if self._cfg.max_temp_files is not None and self._temp_files >= self._cfg.max_temp_files:
            self.rejections.append(f"temp files limit reached ({self._temp_files})")
            return False
        self._temp_files += 1
        self._temp_paths.add(os.path.abspath(path))
        return True

    def unregister_temp_file(self, path: str) -> None:
        abs_path = os.path.abspath(path)
        if abs_path in self._temp_paths:
            self._temp_paths.discard(abs_path)
            self._temp_files = max(0, self._temp_files - 1)

    def register_screenshot(self, size_bytes: int = 0) -> bool:
        if self._cfg.max_screenshots is not None and self._screenshots >= self._cfg.max_screenshots:
            self.rejections.append(f"screenshots limit reached ({self._screenshots})")
            return False
        return self.register_artifact_bytes(size_bytes) and self._inc_screenshots()

    def _inc_screenshots(self) -> bool:
        self._screenshots += 1
        return True

    def register_artifact_bytes(self, size_bytes: int) -> bool:
        if size_bytes <= 0:
            return True
        if self._cfg.max_response_size_bytes is not None and size_bytes > self._cfg.max_response_size_bytes:
            self.rejections.append(f"single artifact {size_bytes} bytes exceeds cap {self._cfg.max_response_size_bytes}")
            return False
        projected = self._artifact_bytes + size_bytes
        if projected > self._cfg.max_total_artifact_bytes if self._cfg.max_total_artifact_bytes is not None else False:
            self.rejections.append(
                f"total artifact bytes {projected} exceeds cap {self._cfg.max_total_artifact_bytes}"
            )
            return False
        self._artifact_bytes = projected
        return True

    # ------------------------------------------------------------------
    def snapshot(self) -> dict[str, Any]:
        return {
            "browser_contexts": self._browser_contexts,
            "max_browser_contexts": self._cfg.max_browser_contexts,
            "temp_files": self._temp_files,
            "max_temp_files": self._cfg.max_temp_files,
            "screenshots": self._screenshots,
            "max_screenshots": self._cfg.max_screenshots,
            "artifact_bytes": self._artifact_bytes,
            "max_total_artifact_bytes": self._cfg.max_total_artifact_bytes,
            "rejections": list(self.rejections),
        }
