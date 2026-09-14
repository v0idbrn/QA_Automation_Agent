# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
STRUCTURED FIVE-LEVEL LOGGING WITH AUTO-REDACTION.

Levels: DEBUG < INFO < WARNING < ERROR < CRITICAL.

Every record carries an optional `run_id`. Messages are always passed
through `core.redaction.redact_text` BEFORE hitting stdout/stderr so that
a forgotten `print(password)` in downstream code cannot leak values to
console or CI logs.

This is NOT a full stdlib-logging replacement. It is a tiny opinionated
emitter tailored for the QA agent loop.
"""

from __future__ import annotations

import json as _json
import sys
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from core.redaction import redact_text, scrub

_LOG_LEVELS = {
    "DEBUG": 10,
    "INFO": 20,
    "WARNING": 30,
    "ERROR": 40,
    "CRITICAL": 50,
}

_DEFAULT_MIN_LEVEL = "INFO"


@dataclass
class LogRecord:
    level: str
    message: str
    timestamp: str
    run_id: str | None = None
    extras: dict[str, Any] = field(default_factory=dict)


class StructuredLogger:
    """Thread-safe, always-redacting logger.

    Emits either human-readable lines (default) or JSON-L lines when
    json_lines=True. The destination can be overridden for tests.
    """

    def __init__(
        self,
        min_level: str = _DEFAULT_MIN_LEVEL,
        *,
        run_id: str | None = None,
        json_lines: bool = False,
        stream: Any = None,
    ) -> None:
        self._lock = threading.Lock()
        self.min_level = min_level.upper()
        self.run_id = run_id
        self.json_lines = json_lines
        self._stream = stream or sys.stderr
        self._records: list[LogRecord] = []
        if self.min_level not in _LOG_LEVELS:
            raise ValueError(f"unknown log level {self.min_level!r}")

    # ------------------------------------------------------------------
    @property
    def records(self) -> list[LogRecord]:
        with self._lock:
            return list(self._records)

    def set_run_id(self, run_id: str) -> None:
        with self._lock:
            self.run_id = run_id

    def set_level(self, level: str) -> None:
        lv = level.upper()
        if lv not in _LOG_LEVELS:
            raise ValueError(f"unknown log level {lv!r}")
        with self._lock:
            self.min_level = lv

    # ------------------------------------------------------------------
    def _level_enabled(self, level: str) -> bool:
        return _LOG_LEVELS[level] >= _LOG_LEVELS[self.min_level]

    def _emit(self, level: str, msg: str, **extras: Any) -> None:
        if not self._level_enabled(level):
            return
        clean_msg = redact_text(str(msg))
        clean_extras = scrub(extras) if extras else {}
        record = LogRecord(
            level=level,
            message=clean_msg,
            timestamp=datetime.now(timezone.utc).isoformat(),
            run_id=self.run_id,
            extras=clean_extras,
        )
        line = self._format(record)
        with self._lock:
            self._records.append(record)
            try:
                print(line, file=self._stream, flush=True)
            except Exception:
                pass

    def _format(self, r: LogRecord) -> str:
        if self.json_lines:
            payload = {
                "level": r.level,
                "ts": r.timestamp,
                "run_id": r.run_id,
                "msg": r.message,
            }
            if r.extras:
                payload["extras"] = r.extras
            try:
                return _json.dumps(payload, ensure_ascii=False, default=str)
            except Exception:
                return f"{r.level} {r.timestamp} [run={r.run_id}] {r.message}"
        run = f"[{r.run_id[:10]}]" if r.run_id else "[-]"
        if r.extras:
            try:
                extra_str = " " + _json.dumps(r.extras, ensure_ascii=False, default=str)
            except Exception:
                extra_str = ""
        else:
            extra_str = ""
        return f"{r.level:<8} {r.timestamp} {run} {r.message}{extra_str}"

    # ------------------------------------------------------------------
    def debug(self, msg: str, **extras: Any) -> None:
        self._emit("DEBUG", msg, **extras)

    def info(self, msg: str, **extras: Any) -> None:
        self._emit("INFO", msg, **extras)

    def warning(self, msg: str, **extras: Any) -> None:
        self._emit("WARNING", msg, **extras)

    warn = warning

    def error(self, msg: str, **extras: Any) -> None:
        self._emit("ERROR", msg, **extras)

    def critical(self, msg: str, **extras: Any) -> None:
        self._emit("CRITICAL", msg, **extras)

    def flush(self) -> None:
        try:
            self._stream.flush()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Module-level default logger. Rarely used; orchestrator creates its own.
# ---------------------------------------------------------------------------

_DEFAULT_LOGGER = StructuredLogger(min_level="INFO")


def get_logger(*, run_id: str | None = None, json_lines: bool = False, min_level: str = "INFO") -> StructuredLogger:
    lg = StructuredLogger(min_level=min_level, json_lines=json_lines, run_id=run_id)
    return lg
