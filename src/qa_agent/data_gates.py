# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Dataset governance gates for synthetic and production pandas frames.

Gates cover schema types, null ratios, duplicate records, PII leakage, and
label-distribution drift. Every gate returns a structured failure instead of
raising, so a pipeline can render the full report before deciding to block.

PII values are detected but never copied into the report; only counts by
category and column are retained.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Mapping

import pandas as pd
from pydantic import BaseModel, Field

__all__ = [
    "DatasetPolicy",
    "DatasetReport",
    "GateFailure",
    "PII_PATTERNS",
    "detect_pii",
    "label_distribution_drift",
    "validate_dataset",
]

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE = re.compile(r"(?<!\d)(?:\+\d{1,3}[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]\d{3}[\s.-]\d{4}(?!\d)")
_SSN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
_CARD_CANDIDATE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_API_KEY = re.compile(r"\b(?:sk|ghp|AKIA|xox[baprs])[-_A-Za-z0-9]{8,}\b")
_IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")

PII_PATTERNS: Mapping[str, re.Pattern[str]] = {
    "email": _EMAIL,
    "phone": _PHONE,
    "ssn": _SSN,
    "credit_card": _CARD_CANDIDATE,
    "api_key": _API_KEY,
    "ipv4": _IPV4,
}


class DatasetPolicy(BaseModel):
    required_columns: dict[str, str] = Field(default_factory=dict)
    max_null_ratio: float = Field(default=0.0, ge=0.0, le=1.0)
    max_duplicate_ratio: float = Field(default=0.0, ge=0.0, le=1.0)
    label_column: str | None = None
    expected_label_distribution: dict[str, float] | None = None
    max_drift: float = Field(default=0.1, ge=0.0, le=1.0)
    pii_columns: list[str] = Field(default_factory=list)
    max_pii_matches: int = Field(default=0, ge=0)


@dataclass(frozen=True)
class GateFailure:
    gate: str
    detail: str
    column: str | None = None
    metric: float | None = None
    threshold: float | None = None


@dataclass
class DatasetReport:
    row_count: int
    column_count: int
    failures: list[GateFailure] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return not self.failures

    def failures_for(self, gate: str) -> list[GateFailure]:
        return [failure for failure in self.failures if failure.gate == gate]


def _luhn_valid(candidate: str) -> bool:
    digits = [int(char) for char in candidate if char.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _matches_pii(kind: str, text: str) -> bool:
    pattern = PII_PATTERNS[kind]
    if kind == "credit_card":
        return any(_luhn_valid(match.group(0)) for match in pattern.finditer(text))
    return bool(pattern.search(text))


def detect_pii(frame: pd.DataFrame, columns: list[str] | None = None) -> dict[str, dict[str, int]]:
    """Return ``{column: {pii_kind: match_count}}`` without exposing values."""
    results: dict[str, dict[str, int]] = {}
    selected = columns or [str(column) for column in frame.columns]
    for column in selected:
        if column not in frame.columns:
            continue
        series = frame[column]
        if not (pd.api.types.is_object_dtype(series) or pd.api.types.is_string_dtype(series)):
            continue
        counts: dict[str, int] = {}
        for value in series.dropna().astype(str):
            for kind in PII_PATTERNS:
                if _matches_pii(kind, value):
                    counts[kind] = counts.get(kind, 0) + 1
        if counts:
            results[column] = counts
    return results


def _dtype_matches(series: pd.Series, expected: str) -> bool:
    normalized = expected.lower()
    if normalized in {"string", "str", "object"}:
        return pd.api.types.is_object_dtype(series) or pd.api.types.is_string_dtype(series)
    if normalized in {"int", "integer"}:
        return pd.api.types.is_integer_dtype(series)
    if normalized in {"float", "double", "number"}:
        return pd.api.types.is_float_dtype(series)
    if normalized in {"bool", "boolean"}:
        return pd.api.types.is_bool_dtype(series)
    if normalized.startswith("datetime"):
        return pd.api.types.is_datetime64_any_dtype(series)
    return str(series.dtype) == expected


def label_distribution_drift(
    frame: pd.DataFrame,
    label_column: str,
    expected_distribution: Mapping[str, float],
) -> tuple[float, dict[str, float]]:
    """Total variation distance between actual and expected label shares."""
    actual_series = frame[label_column].dropna()
    if actual_series.empty:
        return 1.0, {}
    actual = actual_series.astype(str).value_counts(normalize=True).to_dict()
    labels = sorted(set(actual) | set(expected_distribution))
    baseline_total = sum(expected_distribution.values()) or 1.0
    drift = 0.5 * sum(
        abs(actual.get(label, 0.0) - (expected_distribution.get(label, 0.0) / baseline_total))
        for label in labels
    )
    return drift, {label: float(actual.get(label, 0.0)) for label in labels}


def validate_dataset(frame: pd.DataFrame, policy: DatasetPolicy) -> DatasetReport:
    """Run every governance gate and return a structured report."""
    report = DatasetReport(row_count=len(frame), column_count=len(frame.columns))
    metrics: dict[str, Any] = {}

    # 1. Schema presence and types.
    for column, expected_type in policy.required_columns.items():
        if column not in frame.columns:
            report.failures.append(
                GateFailure("schema", f"required column {column!r} is missing", column=column)
            )
            continue
        if not _dtype_matches(frame[column], expected_type):
            report.failures.append(
                GateFailure(
                    "schema",
                    f"column {column!r} has dtype {frame[column].dtype}, expected {expected_type}",
                    column=column,
                )
            )

    # 2. Null ratios.
    if len(frame):
        null_ratios = {str(column): float(frame[column].isna().mean()) for column in frame.columns}
        metrics["null_ratios"] = null_ratios
        for column, ratio in null_ratios.items():
            if ratio > policy.max_null_ratio:
                report.failures.append(
                    GateFailure(
                        "nulls",
                        f"column {column!r} is {ratio:.0%} null (limit {policy.max_null_ratio:.0%})",
                        column=column,
                        metric=ratio,
                        threshold=policy.max_null_ratio,
                    )
                )
    else:
        metrics["null_ratios"] = {}

    # 3. Duplicate records.
    duplicate_ratio = float(frame.duplicated().mean()) if len(frame) else 0.0
    duplicate_count = int(frame.duplicated().sum()) if len(frame) else 0
    metrics["duplicate_ratio"] = duplicate_ratio
    metrics["duplicate_rows"] = duplicate_count
    if duplicate_ratio > policy.max_duplicate_ratio:
        report.failures.append(
            GateFailure(
                "duplicates",
                f"{duplicate_count} duplicate rows ({duplicate_ratio:.0%}) exceed the limit",
                metric=duplicate_ratio,
                threshold=policy.max_duplicate_ratio,
            )
        )

    # 4. PII leakage.
    pii = detect_pii(frame, policy.pii_columns or None)
    pii_total = sum(sum(counts.values()) for counts in pii.values())
    metrics["pii"] = pii
    metrics["pii_matches"] = pii_total
    if pii_total > policy.max_pii_matches:
        report.failures.append(
            GateFailure(
                "pii",
                f"{pii_total} PII-shaped values detected across {len(pii)} column(s)",
                metric=float(pii_total),
                threshold=float(policy.max_pii_matches),
            )
        )

    # 5. Label distribution drift.
    if policy.label_column and policy.expected_label_distribution is not None:
        if policy.label_column not in frame.columns:
            report.failures.append(
                GateFailure(
                    "label_drift",
                    f"label column {policy.label_column!r} is missing",
                    column=policy.label_column,
                )
            )
        else:
            drift, distribution = label_distribution_drift(
                frame, policy.label_column, policy.expected_label_distribution
            )
            metrics["label_distribution"] = distribution
            metrics["label_drift"] = drift
            if drift > policy.max_drift:
                report.failures.append(
                    GateFailure(
                        "label_drift",
                        f"label drift {drift:.3f} exceeds the {policy.max_drift:.3f} limit",
                        column=policy.label_column,
                        metric=drift,
                        threshold=policy.max_drift,
                    )
                )
            unknown = sorted(set(distribution) - set(policy.expected_label_distribution))
            if unknown:
                report.failures.append(
                    GateFailure(
                        "label_drift",
                        f"unexpected labels present: {unknown}",
                        column=policy.label_column,
                    )
                )

    report.metrics = metrics
    return report
