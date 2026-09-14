# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
DEPRECATED shim module.

The canonical 12-type failure taxonomy now lives in `core.failure_analyzer`
(FailureType.PRODUCT_BUG, TEST_BUG, ENVIRONMENT_FAILURE, NETWORK_FAILURE,
TIMEOUT, DEPENDENCY_FAILURE, AUTH_FAILURE, CONFIGURATION_FAILURE,
DATA_PROBLEM, BROWSER_FAILURE, INFRASTRUCTURE_FAILURE, UNKNOWN).

This module keeps the historical import path `core.analyzer` working for
existing callers. Legacy enum members are exposed as module-level aliases:

    APPLICATION_FAILURE -> PRODUCT_BUG
    SELECTOR_FAILURE    -> TEST_BUG

New code MUST import from `core.failure_analyzer` instead.
"""

from __future__ import annotations

from core.failure_analyzer import (  # noqa: F401
    FailureAnalyzer,
    FailureClassification,
    FailureType,
    FlakyDetector,
    MAX_GLOBAL_RETRIES,
    MAX_SIGNATURE_RETRIES,
    RetryController,
    RetryDecision,
    TRANSIENT_FAILURES,
)

# Legacy enum-name aliases (module-level constants, not new enum members)
APPLICATION_FAILURE = FailureType.PRODUCT_BUG
SELECTOR_FAILURE = FailureType.TEST_BUG

__all__ = [
    "APPLICATION_FAILURE",
    "FailureAnalyzer",
    "FailureClassification",
    "FailureType",
    "FlakyDetector",
    "MAX_GLOBAL_RETRIES",
    "MAX_SIGNATURE_RETRIES",
    "RetryController",
    "RetryDecision",
    "SELECTOR_FAILURE",
    "TRANSIENT_FAILURES",
]
