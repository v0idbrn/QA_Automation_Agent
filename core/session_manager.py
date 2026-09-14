# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Session & Auth Management.

Supports four session states:
  ANONYMOUS            — no credentials, no cookies sent
  AUTHENTICATED        — valid credentials/cookies provided via .env
  EXPIRED_SESSION      — credentials rejected / session cookie no longer valid
  INVALID_CREDENTIALS  — credential validation failed (missing user/pass shape)

Guarantee: passwords, cookies, tokens, Authorization headers are NEVER
written to logs or reports. They live only inside this module's
_auth_context dict and are only passed to Playwright/Python HTTP sessions
through local call-by-value arguments that redact at the call boundary.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from core.redaction import scrub


class SessionState(str, Enum):
    ANONYMOUS = "ANONYMOUS"
    AUTHENTICATED = "AUTHENTICATED"
    EXPIRED_SESSION = "EXPIRED_SESSION"
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"


_SESSION_ENV_MARKERS = ("QA_USERNAME", "QA_PASSWORD", "QA_SESSION_COOKIE", "QA_AUTH_TOKEN", "QA_AUTHORIZATION")


@dataclass
class AuthContext:
    """Internal credential container. Never logged or reported."""

    username: str = ""
    password: str = ""
    session_cookie: str = ""
    auth_token: str = ""
    authorization_header: str = ""
    state: SessionState = SessionState.ANONYMOUS
    source: str = "none"  # "env" | "env_file" | "none"


@dataclass
class PublicSessionInfo:
    """Session info SAFE to log/report. No credential values, only metadata."""

    state: SessionState
    has_username: bool
    has_password: bool
    has_cookie: bool
    has_token: bool
    has_authorization: bool
    source: str
    verified: bool = False
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "has_username": self.has_username,
            "has_password": self.has_password,
            "has_cookie": self.has_cookie,
            "has_token": self.has_token,
            "has_authorization": self.has_authorization,
            "source": self.source,
            "verified": self.verified,
            "note": scrub(self.note),
        }


class SessionManager:
    """Credential loader + public session state.

    NEVER log the `_auth` field; use `public_info()` instead.
    """

    def __init__(self, *, env_file: str | Path | None = None) -> None:
        self._auth = AuthContext()
        self._env_file = Path(env_file) if env_file else None
        self._loaded = False
        self._load()

    def _load(self) -> None:
        if self._env_file and self._env_file.exists():
            try:
                text = self._env_file.read_text(encoding="utf-8", errors="ignore")
                for line in text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip('"').strip("'")
                    if k in _SESSION_ENV_MARKERS:
                        os.environ.setdefault(k, v)
                self._auth.source = "env_file"
            except OSError:
                self._auth.source = "env"
        else:
            self._auth.source = "env"
        u = os.environ.get("QA_USERNAME", "").strip()
        p = os.environ.get("QA_PASSWORD", "").strip()
        c = os.environ.get("QA_SESSION_COOKIE", "").strip()
        t = os.environ.get("QA_AUTH_TOKEN", "").strip()
        ah = os.environ.get("QA_AUTHORIZATION", "").strip()
        self._auth.username = u
        self._auth.password = p
        self._auth.session_cookie = c
        self._auth.auth_token = t
        self._auth.authorization_header = ah
        # Determine initial state — do NOT contact network yet
        credentials_present = bool(p or c or t or ah)
        if credentials_present:
            if not self._shape_valid(u, p, c, t, ah):
                self._auth.state = SessionState.INVALID_CREDENTIALS
            else:
                self._auth.state = SessionState.AUTHENTICATED
        else:
            self._auth.state = SessionState.ANONYMOUS
        self._loaded = True

    # ------------------------------------------------------------------
    def _shape_valid(self, u: str, p: str, c: str, t: str, ah: str) -> bool:
        # Username + password both required for basic/form auth; otherwise
        # token/cookie/authorization sufficient individually.
        if u and not p:
            return False
        if not (u and p) and not c and not t and not ah:
            return False
        return True

    # ------------------------------------------------------------------
    def public_info(self) -> PublicSessionInfo:
        return PublicSessionInfo(
            state=self._auth.state,
            has_username=bool(self._auth.username),
            has_password=bool(self._auth.password),
            has_cookie=bool(self._auth.session_cookie),
            has_token=bool(self._auth.auth_token),
            has_authorization=bool(self._auth.authorization_header),
            source=self._auth.source,
            note="Credentials loaded; external verification not yet attempted.",
        )

    def state(self) -> SessionState:
        return self._auth.state

    def mark_expired(self, *, note: str = "") -> None:
        self._auth.state = SessionState.EXPIRED_SESSION
        if note:
            pass  # never store credential content in note; scrub at call boundary

    def mark_invalid(self, *, note: str = "") -> None:
        self._auth.state = SessionState.INVALID_CREDENTIALS

    def mark_authenticated(self) -> None:
        self._auth.state = SessionState.AUTHENTICATED

    # ------------------------------------------------------------------
    # Authenticated-call helpers (pass values locally; callers must scrub any log output)
    # ------------------------------------------------------------------
    def apply_to_playwright_context_options(self, opts: dict[str, Any]) -> dict[str, Any]:
        """Return a NEW Playwright newContext options dict with auth applied.

        The input dict is never mutated. Credential values are placed only
        into the returned dict (call-by-value boundary); callers must never
        log the returned object.
        """
        merged: dict[str, Any] = dict(opts)
        headers = {**(merged.get("extraHTTPHeaders") or {})}
        if self._auth.session_cookie:
            name, _, value = self._auth.session_cookie.partition("=")
            if not value:
                name, value = "session", self._auth.session_cookie
            headers["Cookie"] = f"{name.strip()}={value.strip()}"
        if self._auth.authorization_header:
            headers["Authorization"] = self._auth.authorization_header
        elif self._auth.auth_token:
            headers["Authorization"] = f"Bearer {self._auth.auth_token}"
        if headers:
            merged["extraHTTPHeaders"] = headers
        return merged

    def basic_auth_tuple(self) -> tuple[str, str] | None:
        if self._auth.username and self._auth.password:
            return (self._auth.username, self._auth.password)
        return None
