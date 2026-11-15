# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Reusable AI-SDET quality-engineering primitives.

The modules in this package are intentionally dependency-light: they are
imported by the pytest suites and can be reused from the autonomous agent
without pulling cloud SDKs or API keys into the runtime. They are also
exposed as a CLI: ``python -m qa_agent --help``.
"""

from __future__ import annotations

__all__ = [
    "api_fuzzer",
    "cli",
    "crawler",
    "data_gates",
    "db_qa",
    "desktop_cli_qa",
    "functional_qa",
    "llm_evals",
    "mcp_validator",
    "mobile_qa",
    "models",
    "performance_qa",
    "redaction",
    "reporter",
    "security_checkout",
    "self_healing",
    "test_generator",
    "test_management",
    "ux_a11y_perf",
    "visual_regression",
    "web_auditor",
]
__version__ = "2.0.0"
