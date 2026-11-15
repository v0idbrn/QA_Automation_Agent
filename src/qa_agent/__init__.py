# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Reusable AI-SDET quality-engineering primitives.

The modules in this package are intentionally dependency-light: they are
imported by the pytest suites and can be reused from the autonomous agent
without pulling cloud SDKs or API keys into the runtime.
"""

from __future__ import annotations

__all__ = ["llm_evals", "mcp_validator", "web_auditor", "data_gates"]
__version__ = "1.0.0"
