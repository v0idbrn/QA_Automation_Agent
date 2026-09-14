# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
ATOMIC ARTIFACT WRITES.

For reports, manifests, and evidence metadata:

    tmp file → flush → fsync → validate → atomic rename

If the process crashes at any point before the final rename, the canonical
destination path is either absent or left untouched (never contains a
half-written payload that could be mistaken for a valid artifact).

Windows note: `os.replace` IS atomic on NTFS for files that are not open
with restrictive sharing modes. This is the same guarantee POSIX rename()
gives us on Unix.
"""

from __future__ import annotations

import hashlib
import json as _json
import os
import tempfile
from pathlib import Path
from typing import Any


class AtomicWriteError(RuntimeError):
    """Raised when validation or rename fails. Destination is untouched."""


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _bytes_of(data: str | bytes) -> tuple[bytes, str]:
    if isinstance(data, (bytes, bytearray)):
        return bytes(data), "b"
    if isinstance(data, str):
        return data.encode("utf-8"), "s"
    raise TypeError(f"atomic_write only accepts str | bytes; got {type(data).__name__}")


def atomic_write(
    path: str | Path,
    data: str | bytes,
    *,
    validate: bool = True,
    suffix: str = ".tmp",
) -> Path:
    """Write `data` to `path` atomically.

    Steps:
      1. Ensure parent directory exists.
      2. Open `path + <uuid>.tmp` next to destination (same FS → rename atomic).
      3. Write bytes.
      4. flush() + os.fsync(fd) so bytes really hit disk.
      5. Optionally reopen & sha256 compare to validate integrity.
      6. os.replace() temp over destination. This is the atomic switch.

    Returns the resolved destination Path.
    """
    dst = Path(path).resolve()
    _ensure_parent(dst)
    payload, _ = _bytes_of(data)

    fd = None
    tmp_name = None
    try:
        fd, tmp_abs = tempfile.mkstemp(prefix=".aw_", suffix=suffix, dir=str(dst.parent))
        tmp_name = tmp_abs
        with os.fdopen(fd, "wb") as fh:
            fd = None  # now owned by fh
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        if validate:
            read_back = Path(tmp_abs).read_bytes()
            if hashlib.sha256(read_back).digest() != hashlib.sha256(payload).digest():
                raise AtomicWriteError(f"integrity check failed for {dst}")
        os.replace(tmp_abs, dst)
        tmp_name = None
        return dst
    finally:
        if tmp_name is not None:
            try:
                if fd is not None:
                    os.close(fd)
            except OSError:
                pass
            try:
                if os.path.exists(tmp_name):
                    os.unlink(tmp_name)
            except OSError:
                pass


def atomic_write_json(
    path: str | Path,
    payload: Any,
    *,
    indent: int = 2,
    validate: bool = True,
) -> Path:
    """JSON-flavoured atomic write. Round-trips through json.loads for validity."""
    text = _json.dumps(payload, indent=indent, default=str, ensure_ascii=False)
    if validate:
        try:
            reparsed = _json.loads(text)
        except _json.JSONDecodeError as exc:
            raise AtomicWriteError(f"JSON payload for {path} is invalid: {exc}") from exc
        del reparsed
    return atomic_write(path, text, validate=validate)


def atomic_write_text(path: str | Path, text: str, *, validate: bool = True) -> Path:
    return atomic_write(path, text, validate=validate)
