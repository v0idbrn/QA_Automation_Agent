# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Allow ``python -m qa_agent`` to run the unified CLI."""

from __future__ import annotations

from qa_agent.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
