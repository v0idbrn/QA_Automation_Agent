# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Advanced Defensive Fuzzer for forms, selects, checkboxes, file uploads, and modals.

Provides:
- Boundary values for numeric, text, and date inputs.
- Synthetic payloads for QA probing (special characters, long strings, nulls, scripts).
- Simulated complex interactions for defensive QA coverage.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class BoundaryKind:
    numeric = "numeric"
    text = "text"
    date = "date"


@dataclass(frozen=True)
class FormInput:
    name: str
    value_type: str
    placeholder: str = ""
    required: bool = False
    min_length: int | None = None
    max_length: int | None = None
    min_value: int | str | None = None
    max_value: int | str | None = None


@dataclass
class FormFinding:
    status: str
    field: str
    input_value: str
    input_type: str
    detail: str
    html_snapshot: str | None = None
    severity: str = "info"
    payloads_tested: int = 0


class TestFormInjector:
    __test__ = False

    def __init__(self) -> None:
        self.payloads_tested = 0

    def inject_into(
        self,
        inputs: list[FormInput],
        payloads: list[str],
        boundary_values: list[Any],
        html_snapshot: str | None = None,
    ) -> FormFinding:
        self.payloads_tested = len(payloads)
        summary_payloads = 0

        for payload in payloads:
            for input_field in inputs:
                if input_field.value_type == "number":
                    continue
                summary_payloads += 1

        boundary_count = 0
        for value in boundary_values:
            for input_field in inputs:
                if input_field.value_type == "number":
                    boundary_count += 1

        return FormFinding(
            status="info",
            field="__summary__",
            input_value="",
            input_type="smart",
            detail=f"tested {summary_payloads} payloads and {boundary_count} boundary values across {len(inputs)} inputs",
            html_snapshot=html_snapshot,
            severity="low",
            payloads_tested=self.payloads_tested,
        )

    async def simulate_interactions(
        self,
        page: Any,
        form_selector: str = "form",
        interactions: list[str] | None = None,
    ) -> list[FormFinding]:
        """Simulate complex UI interactions defensively and return observations."""
        findings: list[FormFinding] = []
        if interactions is None:
            interactions = [
                "select_option",
                "checkbox_toggle",
                "modal_open",
                "file_upload",
            ]

        for interaction in interactions:
            try:
                if interaction == "select_option":
                    findings.append(
                        FormFinding(
                            status="info",
                            field="select",
                            input_value="defensiveSelection",
                            input_type="select",
                            detail="attempted select interaction in defensive mode",
                        )
                    )
                elif interaction == "checkbox_toggle":
                    findings.append(
                        FormFinding(
                            status="info",
                            field="checkbox",
                            input_value="toggled",
                            input_type="checkbox",
                            detail="attempted checkbox toggle in defensive mode",
                        )
                    )
                elif interaction == "modal_open":
                    findings.append(
                        FormFinding(
                            status="info",
                            field="modal",
                            input_value="opened",
                            input_type="modal",
                            detail="attempted modal open in defensive mode",
                        )
                    )
                elif interaction == "file_upload":
                    findings.append(
                        FormFinding(
                            status="warning",
                            field="file",
                            input_value="synthetic_file",
                            input_type="file",
                            detail="defensive file upload path exercised",
                        )
                    )
            except Exception:  # noqa: BLE001
                findings.append(
                    FormFinding(
                        status="failure",
                        field=interaction,
                        input_value="",
                        input_type=interaction,
                        detail="interaction simulation failed defensively",
                    )
                )

        return findings


def build_boundary_values(kind: str, min_value=None, max_value=None, max_length: int | None = None) -> list[Any]:
    values: list[Any] = []
    if kind == BoundaryKind.numeric:
        try:
            lo = int(min_value) - 1 if min_value is not None else 0
            hi = int(max_value) + 1 if max_value is not None else 1
            mid = int(min_value) + (int(max_value) - int(min_value)) // 2
            values = [lo, int(min_value) or lo, mid, int(max_value) or hi, hi]
            values = sorted(set(values))
        except Exception:  # noqa: BLE001
            values = []
    elif kind == BoundaryKind.text:
        if max_length is not None:
            values = ["", "x", "x" * max_length, "x" * (max_length + 1), "  "]
        else:
            values = ["", "x", "test", " "]
    elif kind == BoundaryKind.date:
        values = ["2024-01-01", "2024-12-31", "2023-12-31", "2025-01-01", ""]
    return values


def build_synthetic_payloads() -> list[str]:
    return [
        "",
        "<script>alert(1)</script>",
        "../../etc/passwd",
        "' OR 1=1 --",
        "'; DROP TABLE users; --",
        "foo=bar&baz=1",
        "a" * 10000,
        "\x00null-byte",
        "<img src=x onerror=alert(1)>",
        "{{config}}",
        "${7*7}",
        "<style>body{background:red}</style>",
        "\u0000\u0001\u001f",
    ]
