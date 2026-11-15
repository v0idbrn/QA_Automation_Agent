# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Dataset governance and drift gate suite using synthetic pandas frames."""

from __future__ import annotations

import pandas as pd
import pytest

from qa_agent.data_gates import DatasetPolicy, detect_pii, label_distribution_drift, validate_dataset


def _valid_frame() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "id": pd.Series([1, 2, 3, 4], dtype="int64"),
            "name": pd.Series(["alpha", "beta", "gamma", "delta"], dtype="string"),
            "score": pd.Series([0.1, 0.2, 0.3, 0.4], dtype="float64"),
            "active": pd.Series([True, False, True, False], dtype="boolean"),
            "label": pd.Series(["a", "a", "b", "b"], dtype="string"),
        }
    )


def _policy(**overrides: object) -> DatasetPolicy:
    values: dict[str, object] = {
        "required_columns": {
            "id": "integer",
            "name": "string",
            "score": "float",
            "active": "boolean",
        },
        "max_null_ratio": 0.0,
        "max_duplicate_ratio": 0.0,
    }
    values.update(overrides)
    return DatasetPolicy(**values)


# ---------------------------------------------------------------------------
# Schema and positive controls
# ---------------------------------------------------------------------------


def test_clean_dataset_passes_every_gate() -> None:
    report = validate_dataset(_valid_frame(), _policy())
    assert report.passed is True
    assert report.failures == []
    assert report.row_count == 4
    assert report.column_count == 5


def test_missing_required_column_is_blocked() -> None:
    frame = _valid_frame().drop(columns=["name"])
    report = validate_dataset(frame, _policy())
    assert report.passed is False
    assert any(failure.column == "name" for failure in report.failures_for("schema"))


def test_wrong_column_dtype_is_blocked() -> None:
    frame = _valid_frame()
    frame["id"] = frame["id"].astype("string")
    report = validate_dataset(frame, _policy())
    assert report.passed is False
    assert any("dtype" in failure.detail for failure in report.failures_for("schema"))


# ---------------------------------------------------------------------------
# Null ratios
# ---------------------------------------------------------------------------


def test_null_ratio_above_threshold_is_blocked() -> None:
    frame = _valid_frame()
    frame.loc[1:, "name"] = None
    report = validate_dataset(frame, _policy(max_null_ratio=0.25))
    assert report.passed is False
    assert report.metrics["null_ratios"]["name"] == pytest.approx(0.75)
    assert any(failure.column == "name" for failure in report.failures_for("nulls"))


def test_null_ratio_at_threshold_passes() -> None:
    frame = _valid_frame()
    frame.loc[0, "name"] = None
    report = validate_dataset(frame, _policy(max_null_ratio=0.25))
    assert report.passed is True
    assert report.metrics["null_ratios"]["name"] == pytest.approx(0.25)


# ---------------------------------------------------------------------------
# Duplicate records
# ---------------------------------------------------------------------------


def test_duplicate_rows_are_blocked() -> None:
    frame = pd.concat([_valid_frame(), _valid_frame().iloc[[0]]], ignore_index=True)
    report = validate_dataset(frame, _policy())
    assert report.passed is False
    assert report.metrics["duplicate_rows"] == 1
    assert report.failures_for("duplicates")


def test_duplicate_ratio_budget_can_allow_known_duplicates() -> None:
    frame = pd.concat([_valid_frame(), _valid_frame().iloc[[0]]], ignore_index=True)
    report = validate_dataset(frame, _policy(max_duplicate_ratio=0.5))
    assert report.passed is True


# ---------------------------------------------------------------------------
# PII leakage
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        ("email", "qa.user@example.com"),
        ("phone", "+1 415-555-0142"),
        ("ssn", "123-45-6789"),
        ("credit_card", "4111 1111 1111 1111"),
        ("api_key", "sk-abcdefghijklmnop1234"),
    ],
)
def test_pii_shapes_are_detected(kind: str, value: str) -> None:
    frame = _valid_frame()
    frame["contact"] = pd.Series([value, "none", "none", "none"], dtype="string")
    detected = detect_pii(frame)
    assert detected["contact"][kind] >= 1
    assert validate_dataset(frame, _policy()).failures_for("pii")


def test_clean_dataset_has_no_pii() -> None:
    assert detect_pii(_valid_frame()) == {}
    assert validate_dataset(_valid_frame(), _policy()).metrics["pii_matches"] == 0


def test_pii_columns_can_be_scoped() -> None:
    frame = _valid_frame()
    frame["email"] = pd.Series(["qa@example.com", "none", "none", "none"], dtype="string")
    frame["phone"] = pd.Series(["+1 415-555-0142", "none", "none", "none"], dtype="string")
    scoped = validate_dataset(frame, _policy(pii_columns=["email"]))
    assert set(scoped.metrics["pii"]) == {"email"}
    assert scoped.metrics["pii"]["email"]["email"] == 1


def test_pii_report_never_echoes_the_sensitive_value() -> None:
    frame = _valid_frame()
    frame["email"] = pd.Series(["secret.person@example.com", "none", "none", "none"], dtype="string")
    report = validate_dataset(frame, _policy())
    assert "secret.person@example.com" not in repr(report.metrics)


# ---------------------------------------------------------------------------
# Label distribution drift
# ---------------------------------------------------------------------------


def test_label_distribution_within_threshold_passes() -> None:
    report = validate_dataset(
        _valid_frame(),
        _policy(
            label_column="label",
            expected_label_distribution={"a": 0.5, "b": 0.5},
            max_drift=0.1,
        ),
    )
    assert report.passed is True
    assert report.metrics["label_drift"] == pytest.approx(0.0)


def test_label_distribution_drift_is_blocked() -> None:
    frame = _valid_frame()
    frame["label"] = pd.Series(["a", "a", "a", "b"], dtype="string")
    report = validate_dataset(
        frame,
        _policy(
            label_column="label",
            expected_label_distribution={"a": 0.5, "b": 0.5},
            max_drift=0.1,
        ),
    )
    assert report.passed is False
    assert report.metrics["label_drift"] == pytest.approx(0.25)
    assert report.failures_for("label_drift")


def test_unexpected_label_is_blocked() -> None:
    frame = _valid_frame()
    frame["label"] = pd.Series(["a", "b", "c", "c"], dtype="string")
    report = validate_dataset(
        frame,
        _policy(
            label_column="label",
            expected_label_distribution={"a": 0.5, "b": 0.5},
            max_drift=0.6,
        ),
    )
    assert report.passed is False
    assert any("unexpected labels" in failure.detail for failure in report.failures_for("label_drift"))


def test_missing_label_column_is_blocked() -> None:
    report = validate_dataset(
        _valid_frame().drop(columns=["label"]),
        _policy(label_column="label", expected_label_distribution={"a": 0.5, "b": 0.5}),
    )
    assert report.passed is False
    assert any("missing" in failure.detail for failure in report.failures_for("label_drift"))


def test_drift_helper_returns_total_variation_distance() -> None:
    frame = _valid_frame()
    drift, distribution = label_distribution_drift(frame, "label", {"a": 0.8, "b": 0.2})
    assert drift == pytest.approx(0.3)
    assert distribution == {"a": 0.5, "b": 0.5}


def test_report_exposes_metrics_for_pipeline_export() -> None:
    report = validate_dataset(_valid_frame(), _policy())
    assert {"null_ratios", "duplicate_ratio", "pii_matches"} <= set(report.metrics)
    assert report.metrics["duplicate_ratio"] == 0.0
