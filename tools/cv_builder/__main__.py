# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Package entrypoint: ``python -m tools.cv_builder``."""

from __future__ import annotations

import sys

from tools.cv_builder.cli import main

if __name__ == "__main__":
    sys.exit(main())