# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Functional quality: role-based access control and workflow-state integrity.

Both audits are pure functions over declarative input (a role matrix, a
transition graph), so an RBAC specification or a state machine can be
regression-tested offline before any browser touches the product.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from qa_agent.models import Finding, Severity
from qa_agent.redaction import redact_text

__all__ = [
    "DEFAULT_SENSITIVE_PERMISSIONS",
    "RbacReport",
    "WorkflowReport",
    "audit_rbac",
    "audit_workflow",
    "load_rbac_matrix",
]

DEFAULT_SENSITIVE_PERMISSIONS = frozenset(
    {
        "delete",
        "billing",
        "admin",
        "manage_users",
        "impersonate",
        "export_pii",
        "refund",
        "publish",
        "configure",
        "manage_roles",
    }
)
_WILDCARD_ROLES = frozenset({"admin", "superuser", "owner", "root"})


def _finding(
    title: str,
    severity: Severity,
    category: str,
    description: str,
    evidence: str = "",
    recommendation: str = "",
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        category=category,
        description=description,
        evidence=redact_text(evidence),
        recommendation=recommendation,
    )


# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------


def load_rbac_matrix(source: str | Path | Mapping[str, Any]) -> dict[str, Any]:
    """Load a role matrix from a JSON file or a mapping."""
    if isinstance(source, Mapping):
        payload: Any = dict(source)
    else:
        payload = json.loads(Path(source).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("RBAC document must be a JSON object")
    roles = payload.get("roles")
    permissions = payload.get("permissions")
    if not isinstance(permissions, Mapping) or not permissions:
        raise ValueError("RBAC document needs a non-empty 'permissions' object")
    if roles is None:
        roles = list(permissions)
    if not isinstance(roles, Sequence) or isinstance(roles, (str, bytes)):
        raise ValueError("RBAC 'roles' must be a list")
    return {
        "roles": [str(role) for role in roles],
        "permissions": {
            str(role): sorted({str(permission) for permission in values}) for role, values in permissions.items()
        },
        "sensitive_permissions": sorted(
            {str(permission) for permission in payload.get("sensitive_permissions") or DEFAULT_SENSITIVE_PERMISSIONS}
        ),
        "privileged_roles": [str(role) for role in payload.get("privileged_roles") or []],
    }


@dataclass
class RbacReport:
    roles: tuple[str, ...] = ()
    permissions: dict[str, tuple[str, ...]] = field(default_factory=dict)
    sensitive_permissions: tuple[str, ...] = ()
    findings: list[Finding] = field(default_factory=list)
    passed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "roles": list(self.roles),
            "permissions": {role: list(values) for role, values in self.permissions.items()},
            "sensitive_permissions": list(self.sensitive_permissions),
            "coverage": {
                role: round(len(values) / len(self.sensitive_permissions), 3) if self.sensitive_permissions else 0.0
                for role, values in self.permissions.items()
            },
            "passed": self.passed,
            "findings": [finding.to_dict() for finding in self.findings],
        }


def audit_rbac(matrix: str | Path | Mapping[str, Any]) -> RbacReport:
    """Audit a role matrix for over-privilege, gaps, and undefined roles."""
    data = load_rbac_matrix(matrix)
    roles: list[str] = data["roles"]
    permissions: dict[str, list[str]] = data["permissions"]
    sensitive = set(data["sensitive_permissions"])
    privileged = set(data["privileged_roles"]) or {
        role for role in roles if role.lower() in _WILDCARD_ROLES
    }
    report = RbacReport(
        roles=tuple(roles),
        permissions={role: tuple(values) for role, values in permissions.items()},
        sensitive_permissions=tuple(sorted(sensitive)),
    )

    if not roles:
        report.findings.append(
            _finding(
                "Role matrix is empty",
                Severity.HIGH,
                "rbac-empty",
                "No roles are declared, so every authorization decision is undefined.",
                "roles=[]",
                "Declare at least one role and its permissions.",
            )
        )
        return report

    for role in roles:
        if role not in permissions:
            report.findings.append(
                _finding(
                    "Role declared without permissions",
                    Severity.MEDIUM,
                    "rbac-role-gap",
                    f"Role '{role}' has no permission entry, so its access is implicit.",
                    role,
                    "Add an explicit permission list (an empty list is a decision).",
                )
            )
            continue
        values = permissions[role]
        if not values:
            report.findings.append(
                _finding(
                    "Role has no permissions",
                    Severity.LOW,
                    "rbac-role-empty",
                    f"Role '{role}' can do nothing; confirm this is intentional.",
                    role,
                    "Remove the dead role or grant the minimum it needs.",
                )
            )
        held_sensitive = sorted(set(values) & sensitive)
        if held_sensitive and role.lower() not in _WILDCARD_ROLES and role not in privileged:
            report.findings.append(
                _finding(
                    "Sensitive permission on an unprivileged role",
                    Severity.HIGH,
                    "rbac-over-privilege",
                    f"Role '{role}' holds sensitive permissions without being declared privileged.",
                    f"{role} -> {', '.join(held_sensitive)}",
                    "Move the permission to a privileged role or justify it in the matrix.",
                )
            )
        if len(held_sensitive) == len(sensitive) and len(sensitive) > 1 and role.lower() not in _WILDCARD_ROLES:
            report.findings.append(
                _finding(
                    "Role holds every sensitive permission",
                    Severity.HIGH,
                    "rbac-full-privilege",
                    f"Role '{role}' is a de-facto superuser.",
                    f"{role} -> {len(held_sensitive)}/{len(sensitive)}",
                    "Split the matrix so no non-admin role is omnipotent.",
                )
            )
        unknown = sorted(set(values) - sensitive)
        if unknown:
            report.findings.append(
                _finding(
                    "Permission outside the sensitive catalogue",
                    Severity.LOW,
                    "rbac-undefined-permission",
                    f"Role '{role}' holds permissions that are not classified as sensitive.",
                    ", ".join(unknown),
                    "Classify every permission so over-privilege is measurable.",
                )
            )

    for role in permissions:
        if role not in roles:
            report.findings.append(
                _finding(
                    "Permission entry for an undeclared role",
                    Severity.MEDIUM,
                    "rbac-orphan-role",
                    f"'{role}' has permissions but is not part of the role list.",
                    role,
                    "Add the role to 'roles' or delete the entry.",
                )
            )

    read_roles = [role for role in roles if "read" in permissions.get(role, ())]
    if roles and not read_roles:
        report.findings.append(
            _finding(
                "No role can read",
                Severity.HIGH,
                "rbac-gap",
                "The matrix denies every read, so the product is unusable.",
                "read permission absent from every role",
                "Grant read access to at least the base role.",
            )
        )

    for action in ("read", "write", "delete"):
        holders = [role for role in roles if action in permissions.get(role, ())]
        if not holders:
            report.findings.append(
                _finding(
                    f"No role can {action}",
                    Severity.MEDIUM if action != "delete" else Severity.LOW,
                    "rbac-gap",
                    f"The '{action}' action is unreachable for every role.",
                    f"{action} -> holders=0",
                    "Confirm the action is intentionally unavailable.",
                )
            )

    report.passed = not any(
        finding.severity in {Severity.CRITICAL, Severity.HIGH} for finding in report.findings
    )
    return report


# ---------------------------------------------------------------------------
# Workflow / state machine
# ---------------------------------------------------------------------------


@dataclass
class WorkflowReport:
    initial: str = ""
    terminal: tuple[str, ...] = ()
    states: tuple[str, ...] = ()
    transitions: dict[str, tuple[str, ...]] = field(default_factory=dict)
    unreachable: tuple[str, ...] = ()
    dead_ends: tuple[str, ...] = ()
    findings: list[Finding] = field(default_factory=list)
    passed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "initial": self.initial,
            "terminal": list(self.terminal),
            "states": list(self.states),
            "transitions": {state: list(targets) for state, targets in self.transitions.items()},
            "unreachable": list(self.unreachable),
            "dead_ends": list(self.dead_ends),
            "passed": self.passed,
            "findings": [finding.to_dict() for finding in self.findings],
        }


def audit_workflow(
    transitions: Mapping[str, Iterable[str]],
    *,
    initial: str,
    terminal: Sequence[str] = (),
    required: Sequence[str] = (),
) -> WorkflowReport:
    """Audit a transition graph for unreachable states, dead ends, and gaps."""
    graph = {str(state): tuple(str(target) for target in targets) for state, targets in transitions.items()}
    terminal_states = tuple(str(state) for state in terminal)
    report = WorkflowReport(initial=str(initial), terminal=terminal_states, transitions=graph)
    report.states = tuple(sorted(set(graph) | {target for targets in graph.values() for target in targets}))
    report.findings = []

    if not graph:
        report.findings.append(
            _finding(
                "Workflow has no transitions",
                Severity.HIGH,
                "workflow-empty",
                "The state machine is empty, so no user journey can be tested.",
                "transitions={}",
                "Declare the states and their allowed transitions.",
            )
        )
        return report

    if initial not in graph:
        report.findings.append(
            _finding(
                "Initial state is not defined",
                Severity.HIGH,
                "workflow-initial",
                f"'{initial}' has no outgoing transitions.",
                f"initial={initial}",
                "Declare the initial state in the transition map.",
            )
        )

    reachable: set[str] = set()
    frontier = [str(initial)] if initial in graph else []
    while frontier:
        state = frontier.pop()
        if state in reachable:
            continue
        reachable.add(state)
        frontier.extend(graph.get(state, ()))
    report.unreachable = tuple(sorted(set(graph) - reachable))
    for state in report.unreachable:
        report.findings.append(
            _finding(
                "State is unreachable",
                Severity.MEDIUM,
                "workflow-unreachable",
                f"'{state}' cannot be reached from '{initial}'.",
                state,
                "Add a transition into the state or delete it.",
            )
        )

    for state, targets in graph.items():
        for target in targets:
            if target not in graph and target not in terminal_states:
                report.findings.append(
                    _finding(
                        "Transition targets an unknown state",
                        Severity.HIGH,
                        "workflow-unknown-target",
                        f"'{state}' transitions to '{target}', which has no definition.",
                        f"{state} -> {target}",
                        "Declare the target state or correct the typo.",
                    )
                )
        if not targets and state not in terminal_states:
            report.dead_ends += (state,)
            report.findings.append(
                _finding(
                    "Non-terminal state is a dead end",
                    Severity.HIGH,
                    "workflow-dead-end",
                    f"'{state}' has no exit, so a user can get stuck there.",
                    state,
                    "Add the recovery/continue transition, or mark the state terminal.",
                )
            )

    for state in terminal_states:
        if state not in graph:
            report.findings.append(
                _finding(
                    "Terminal state is not defined",
                    Severity.MEDIUM,
                    "workflow-terminal",
                    f"'{state}' is declared terminal but never appears as a source state.",
                    state,
                    "Declare the terminal state with an empty transition list.",
                )
            )
    if not terminal_states:
        report.findings.append(
            _finding(
                "No terminal state declared",
                Severity.MEDIUM,
                "workflow-terminal",
                "The workflow never declares a success state, so its goal is untestable.",
                "terminal=[]",
                "Declare the completed/cancelled states.",
            )
        )
    if terminal_states and not set(terminal_states) & reachable:
        report.findings.append(
            _finding(
                "No terminal state is reachable",
                Severity.HIGH,
                "workflow-goal",
                "Every terminal state is unreachable from the initial state.",
                ", ".join(terminal_states),
                "Connect the happy path to a terminal state.",
            )
        )

    for state in required:
        if str(state) not in reachable:
            report.findings.append(
                _finding(
                    "Required state is not reachable",
                    Severity.HIGH,
                    "workflow-required",
                    f"Required state '{state}' cannot be reached.",
                    str(state),
                    "Add the missing transition on the happy path.",
                )
            )

    for state, targets in graph.items():
        for target in targets:
            if target == state:
                report.findings.append(
                    _finding(
                        "Self-transition",
                        Severity.LOW,
                        "workflow-self-loop",
                        f"'{state}' transitions to itself.",
                        f"{state} -> {state}",
                        "Confirm the self-loop is intentional and bounded.",
                    )
                )

    report.dead_ends = tuple(sorted(set(report.dead_ends)))
    report.passed = not any(
        finding.severity in {Severity.CRITICAL, Severity.HIGH} for finding in report.findings
    )
    return report
