# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Reproducible run manifest.

Environment and configuration metadata are persisted only after redaction.
"""

from __future__ import annotations

from core.evidence import RunManifest, EvidenceEntry

__all__ = ["RunManifest", "EvidenceEntry"]
