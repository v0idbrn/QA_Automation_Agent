# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Root fixtures for the vulnerable SaaS target and browser-backed audits."""

from __future__ import annotations

from typing import Iterator

import pytest

from tests.fixtures.vulnerable_saas_fixture import start_fixture_server


@pytest.fixture(scope="session")
def vulnerable_saas() -> Iterator[str]:
    """Base URL of the seeded vulnerable fixture (session-scoped, local only)."""
    with start_fixture_server() as base_url:
        yield base_url
