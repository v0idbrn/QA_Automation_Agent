# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""MCP / agent tool-call guardrails mapped to the OWASP LLM Top 10.

Every check is deterministic: raw input is Unicode-normalized, percent-decoded
(bounded), and inspected for path traversal, shell metacharacters, SSRF
targets, prompt injection, and credential leakage. A tool call is allowed only
when it matches a declared :class:`ToolSpec` and produces zero violations.

Mapping used by this module:
  * LLM01 Prompt Injection          -> direct and indirect injection payloads
  * LLM02 Sensitive Information     -> secrets embedded in tool arguments
  * LLM05 Improper Output Handling  -> path traversal / unsafe file arguments
  * LLM06 Excessive Agency          -> command injection and SSRF
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from enum import Enum
from typing import Any
from urllib.parse import unquote, urlsplit

from pydantic import BaseModel, Field

__all__ = [
    "ArgumentKind",
    "OWASP_LLM_TOP10",
    "ToolCall",
    "ToolPolicy",
    "ToolSpec",
    "ValidationResult",
    "Violation",
    "sanitize_text",
    "validate_tool_call",
]

OWASP_LLM_TOP10 = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

OWASP_PROMPT_INJECTION = f"LLM01: {OWASP_LLM_TOP10['LLM01']}"
OWASP_SENSITIVE_INFO = f"LLM02: {OWASP_LLM_TOP10['LLM02']}"
OWASP_IMPROPER_OUTPUT = f"LLM05: {OWASP_LLM_TOP10['LLM05']}"
OWASP_EXCESSIVE_AGENCY = f"LLM06: {OWASP_LLM_TOP10['LLM06']}"


class ArgumentKind(str, Enum):
    PATH = "path"
    URL = "url"
    COMMAND = "command"
    TEXT = "text"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    OBJECT = "object"
    ARRAY = "array"


class ToolSpec(BaseModel):
    name: str
    arguments: dict[str, ArgumentKind] = Field(default_factory=dict)
    required: list[str] = Field(default_factory=list)


class ToolPolicy(BaseModel):
    tools: dict[str, ToolSpec] = Field(default_factory=dict)
    allowed_hosts: list[str] = Field(default_factory=list)
    allow_absolute_paths: bool = False
    max_argument_length: int = 4096


class ToolCall(BaseModel):
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class Violation(BaseModel):
    rule: str
    owasp: str
    detail: str
    argument: str | None = None


class ValidationResult(BaseModel):
    tool: str
    allowed: bool
    violations: list[Violation] = Field(default_factory=list)
    sanitized_arguments: dict[str, Any] = Field(default_factory=dict)

    @property
    def rules(self) -> list[str]:
        return [violation.rule for violation in self.violations]


# ---------------------------------------------------------------------------
# Canonicalisation
# ---------------------------------------------------------------------------


def sanitize_text(value: str) -> str:
    """Normalize and bounded-decode a string before inspection.

    Three decode passes are enough for double/triple encoded payloads and the
    bound prevents a decode bomb from expanding without limit.
    """
    normalized = unicodedata.normalize("NFKC", value)
    for _ in range(3):
        decoded = unquote(normalized)
        if decoded == normalized:
            break
        normalized = decoded
    return "".join(char for char in normalized if char == "\n" or char == "\t" or ord(char) >= 32)


def _iter_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [item for key, val in value.items() for item in _iter_strings(key) + _iter_strings(val)]
    if isinstance(value, (list, tuple, set)):
        return [item for entry in value for item in _iter_strings(entry)]
    return []


# ---------------------------------------------------------------------------
# Individual guards
# ---------------------------------------------------------------------------


def _path_violation(argument: str, value: str, *, allow_absolute: bool) -> Violation | None:
    normalized = sanitize_text(value).replace("\\", "/")
    segments = [segment for segment in normalized.split("/") if segment not in ("", ".")]
    if ".." in segments:
        return Violation(
            rule="PATH_TRAVERSAL",
            owasp=OWASP_IMPROPER_OUTPUT,
            detail="path escapes the workspace through a parent-directory segment",
            argument=argument,
        )
    if not allow_absolute and (normalized.startswith("/") or normalized.startswith("//") or re.match(r"^[A-Za-z]:", normalized)):
        return Violation(
            rule="ABSOLUTE_PATH",
            owasp=OWASP_IMPROPER_OUTPUT,
            detail="absolute filesystem paths are not allowed for this tool",
            argument=argument,
        )
    return None


_SHELL_TOKENS = (";", "&&", "||", "|", "`", "$(", "${", "\n", "\r", ">", "<")


def _command_violation(argument: str, value: str) -> Violation | None:
    normalized = sanitize_text(value)
    for token in _SHELL_TOKENS:
        if token in normalized:
            return Violation(
                rule="COMMAND_INJECTION",
                owasp=OWASP_EXCESSIVE_AGENCY,
                detail=f"shell metacharacter {token!r} is not allowed in command arguments",
                argument=argument,
            )
    if re.search(r"(^|\s)&(\s|$)", normalized):
        return Violation(
            rule="COMMAND_INJECTION",
            owasp=OWASP_EXCESSIVE_AGENCY,
            detail="background shell operator is not allowed in command arguments",
            argument=argument,
        )
    return None


def _parse_ipv4_variants(host: str) -> ipaddress.IPv4Address | None:
    """Catch decimal/octal/hex host encodings such as 2130706433 or 0x7f.0.0.1."""
    if re.fullmatch(r"\d+", host):
        try:
            return ipaddress.IPv4Address(int(host))
        except ValueError:
            return None
    parts = host.split(".")
    if len(parts) == 4 and all(re.fullmatch(r"0[xX][0-9a-fA-F]+|\d+", part) for part in parts):
        try:
            octets = [int(part, 0) for part in parts]
        except ValueError:
            return None
        if all(0 <= octet <= 255 for octet in octets):
            return ipaddress.IPv4Address(".".join(str(octet) for octet in octets))
    return None


def _is_internal_host(host: str) -> bool:
    normalized = host.strip("[]").lower().rstrip(".")
    if normalized in {"localhost", "metadata.google.internal", "metadata.google", "instance-data"}:
        return True
    if normalized.endswith(".localhost") or normalized.endswith(".local") or normalized.endswith(".internal"):
        return True

    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        address = _parse_ipv4_variants(normalized)
        if address is None:
            return False

    return any(
        (
            address.is_loopback,
            address.is_private,
            address.is_link_local,
            address.is_reserved,
            address.is_unspecified,
            address.is_multicast,
        )
    )


def _url_violation(argument: str, value: str, *, allowed_hosts: list[str]) -> Violation | None:
    normalized = sanitize_text(value).strip()
    try:
        parts = urlsplit(normalized)
    except ValueError:
        return Violation(
            rule="MALFORMED_URL",
            owasp=OWASP_EXCESSIVE_AGENCY,
            detail="URL could not be parsed",
            argument=argument,
        )

    if parts.scheme.lower() not in {"http", "https"}:
        return Violation(
            rule="UNSAFE_SCHEME",
            owasp=OWASP_EXCESSIVE_AGENCY,
            detail=f"scheme {parts.scheme or '<none>'!r} is not allowed; use http or https",
            argument=argument,
        )
    if parts.username or parts.password:
        return Violation(
            rule="SSRF",
            owasp=OWASP_EXCESSIVE_AGENCY,
            detail="URL userinfo is not allowed and can mask the real destination",
            argument=argument,
        )

    host = (parts.hostname or "").lower()
    if not host:
        return Violation(
            rule="MALFORMED_URL",
            owasp=OWASP_EXCESSIVE_AGENCY,
            detail="URL has no hostname",
            argument=argument,
        )
    if _is_internal_host(host):
        return Violation(
            rule="SSRF",
            owasp=OWASP_EXCESSIVE_AGENCY,
            detail=f"host {host!r} resolves to a loopback, private, or metadata target",
            argument=argument,
        )

    if allowed_hosts and not any(host == allowed or host.endswith(f".{allowed}") for allowed in allowed_hosts):
        return Violation(
            rule="HOST_NOT_ALLOWED",
            owasp=OWASP_EXCESSIVE_AGENCY,
            detail=f"host {host!r} is outside the configured allowlist",
            argument=argument,
        )
    return None


_DIRECT_INJECTION_PATTERNS = (
    re.compile(r"\bignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)\b", re.IGNORECASE),
    re.compile(r"\bdisregard\s+(the\s+)?(previous|prior|system|all)\s+(system\s+)?(instructions?|prompts?)\b", re.IGNORECASE),
    re.compile(r"\b(reveal|show|print|leak|repeat)\s+(your|the)\s+(system\s+)?(prompt|instructions|rules)\b", re.IGNORECASE),
    re.compile(r"\byou\s+are\s+now\b", re.IGNORECASE),
    re.compile(r"\b(developer|god|dan)\s+mode\b", re.IGNORECASE),
    re.compile(r"\bdo\s+anything\s+now\b", re.IGNORECASE),
    re.compile(r"\bjailbreak\b", re.IGNORECASE),
    re.compile(r"\bnew\s+instructions?\s*:", re.IGNORECASE),
)

_INDIRECT_INJECTION_PATTERNS = (
    re.compile(r"<!--[^>]*(ignore|instruction|system|prompt)", re.IGNORECASE),
    re.compile(r"\[/?system\]", re.IGNORECASE),
    re.compile(r"<\|im_start\|>", re.IGNORECASE),
    re.compile(r"\b(begin|end)\s+(system|instruction)s?\b", re.IGNORECASE),
    re.compile(r"\bassistant\s*:", re.IGNORECASE),
    re.compile(r"\bhidden\s+instruction\b", re.IGNORECASE),
    re.compile(r"\bwhen\s+(the\s+)?(assistant|model|ai|agent)\s+(reads|sees|processes)\s+this", re.IGNORECASE),
)

_SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"(?i)\b(api[_-]?key|password|secret|token)\s*[:=]\s*[^\s,;]{6,}"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{12,}"),
)


def _prompt_violation(argument: str, value: str) -> Violation | None:
    normalized = sanitize_text(value)
    for pattern in _DIRECT_INJECTION_PATTERNS:
        if pattern.search(normalized):
            return Violation(
                rule="PROMPT_INJECTION",
                owasp=OWASP_PROMPT_INJECTION,
                detail="direct prompt injection pattern detected",
                argument=argument,
            )
    for pattern in _INDIRECT_INJECTION_PATTERNS:
        if pattern.search(normalized):
            return Violation(
                rule="PROMPT_INJECTION",
                owasp=OWASP_PROMPT_INJECTION,
                detail="indirect prompt injection pattern detected in untrusted content",
                argument=argument,
            )
    return None


def _secret_violation(argument: str, value: str) -> Violation | None:
    for pattern in _SECRET_PATTERNS:
        if pattern.search(value):
            return Violation(
                rule="SENSITIVE_DATA",
                owasp=OWASP_SENSITIVE_INFO,
                detail="tool argument contains a credential-shaped value",
                argument=argument,
            )
    return None


# ---------------------------------------------------------------------------
# Public validator
# ---------------------------------------------------------------------------


def _type_matches(kind: ArgumentKind, value: Any) -> bool:
    if kind in {ArgumentKind.PATH, ArgumentKind.URL, ArgumentKind.COMMAND, ArgumentKind.TEXT}:
        return isinstance(value, str)
    if kind is ArgumentKind.INTEGER:
        return isinstance(value, int) and not isinstance(value, bool)
    if kind is ArgumentKind.BOOLEAN:
        return isinstance(value, bool)
    if kind is ArgumentKind.OBJECT:
        return isinstance(value, dict)
    if kind is ArgumentKind.ARRAY:
        return isinstance(value, list)
    return False


def validate_tool_call(call: ToolCall, policy: ToolPolicy) -> ValidationResult:
    """Validate one MCP-style tool call against the declared policy."""
    violations: list[Violation] = []
    sanitized: dict[str, Any] = {}
    spec = policy.tools.get(call.tool)

    if spec is None:
        return ValidationResult(
            tool=call.tool,
            allowed=False,
            violations=[
                Violation(
                    rule="UNKNOWN_TOOL",
                    owasp=OWASP_EXCESSIVE_AGENCY,
                    detail=f"tool {call.tool!r} is not declared in the policy",
                )
            ],
        )

    for name in spec.required:
        if name not in call.arguments:
            violations.append(
                Violation(
                    rule="MISSING_ARGUMENT",
                    owasp=OWASP_EXCESSIVE_AGENCY,
                    detail=f"required argument {name!r} is missing",
                    argument=name,
                )
            )

    for name, value in call.arguments.items():
        kind = spec.arguments.get(name)
        if kind is None:
            violations.append(
                Violation(
                    rule="UNDECLARED_ARGUMENT",
                    owasp=OWASP_EXCESSIVE_AGENCY,
                    detail=f"argument {name!r} is not declared for tool {call.tool!r}",
                    argument=name,
                )
            )
            continue

        sanitized[name] = sanitize_text(value) if isinstance(value, str) else value

        if not _type_matches(kind, value):
            violations.append(
                Violation(
                    rule="INVALID_TYPE",
                    owasp=OWASP_EXCESSIVE_AGENCY,
                    detail=f"argument {name!r} must be of kind {kind.value}",
                    argument=name,
                )
            )
            continue

        if isinstance(value, str) and len(value) > policy.max_argument_length:
            violations.append(
                Violation(
                    rule="ARGUMENT_TOO_LONG",
                    owasp=OWASP_EXCESSIVE_AGENCY,
                    detail=f"argument {name!r} exceeds {policy.max_argument_length} characters",
                    argument=name,
                )
            )

        texts = _iter_strings(value)
        if kind is ArgumentKind.PATH and isinstance(value, str):
            violation = _path_violation(name, value, allow_absolute=policy.allow_absolute_paths)
            if violation:
                violations.append(violation)
        if kind is ArgumentKind.URL and isinstance(value, str):
            violation = _url_violation(name, value, allowed_hosts=policy.allowed_hosts)
            if violation:
                violations.append(violation)
        if kind is ArgumentKind.COMMAND and isinstance(value, str):
            violation = _command_violation(name, value)
            if violation:
                violations.append(violation)

        for text in texts:
            if kind is not ArgumentKind.COMMAND:
                command_violation = _command_violation(name, text)
                if command_violation and kind in {ArgumentKind.TEXT, ArgumentKind.OBJECT, ArgumentKind.ARRAY}:
                    violations.append(command_violation)
            prompt_violation = _prompt_violation(name, text)
            if prompt_violation:
                violations.append(prompt_violation)
            secret_violation = _secret_violation(name, text)
            if secret_violation:
                violations.append(secret_violation)

    return ValidationResult(
        tool=call.tool,
        allowed=not violations,
        violations=violations,
        sanitized_arguments=sanitized,
    )
