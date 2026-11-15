# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Deterministic LLM and RAG evaluation primitives.

The suite is offline-first: :class:`MockLLMAdapter` is the default adapter,
so evaluators and regression tests run with no API key and no network. An
OpenAI-compatible adapter is available for optional live checks and reads its
credentials only from the environment (``OPENAI_API_KEY`` / ``GROQ_KEY``).

Design rules:
  * every evaluator is a pure function over text so results are reproducible;
  * no evaluator imports a provider SDK;
  * a live adapter never logs the API key and never retries unsafe requests.
"""

from __future__ import annotations

import json
import math
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence

import httpx
from pydantic import BaseModel, ValidationError

__all__ = [
    "BudgetExceeded",
    "ConversationResult",
    "CredentialError",
    "GroundednessResult",
    "LLMResponse",
    "Message",
    "MockLLMAdapter",
    "OpenAICompatibleAdapter",
    "StructuredOutputError",
    "TurnExpectation",
    "assert_within_budget",
    "estimate_tokens",
    "evaluate_groundedness",
    "run_conversation",
    "validate_structured_output",
]

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_NUMBER_RE = re.compile(r"\b\d+(?:\.\d+)?\b")
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+|\n+")
_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE | re.MULTILINE)

_STOPWORDS = frozenset(
    """
    a an and are as at be been being but by can could did do does for from had has
    have he her his how i if in into is it its may might more most must my no nor
    not of on or our out over should so some such than that the their them then
    there these they this those to too up us was we were what when where which
    while who why will with would you your
    """.split()
)


# ---------------------------------------------------------------------------
# Chat contracts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Message:
    role: str
    content: str


@dataclass(frozen=True)
class LLMResponse:
    text: str
    latency_ms: float = 0.0
    prompt_tokens: int = 0
    completion_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


class LLMAdapter(Protocol):
    def complete(self, messages: Sequence[Message], *, max_tokens: int = 256) -> LLMResponse: ...


def estimate_tokens(text: str) -> int:
    """Provider-agnostic token estimate (4 chars per token, never zero)."""
    return max(1, math.ceil(len(text) / 4))


class MockLLMAdapter:
    """Deterministic, offline adapter.

    ``responses`` maps a prompt substring to a canned answer. The first
    matching key wins; the last user message is matched against every key.
    Unmatched prompts return a conservative refusal so tests never depend on
    an accidental model answer.
    """

    def __init__(self, responses: Mapping[str, str] | None = None, latency_ms: float = 5.0) -> None:
        self._responses = dict(responses or {})
        self.latency_ms = latency_ms
        self.calls: list[list[Message]] = []

    def complete(self, messages: Sequence[Message], *, max_tokens: int = 256) -> LLMResponse:
        history = list(messages)
        self.calls.append(history)
        prompt = history[-1].content if history else ""
        text = self._responses.get(prompt)
        if text is None:
            text = next((answer for key, answer in self._responses.items() if key in prompt), None)
        if text is None:
            text = "I can answer only from the supplied context."

        prompt_text = "\n".join(message.content for message in history)
        return LLMResponse(
            text=text,
            latency_ms=self.latency_ms,
            prompt_tokens=estimate_tokens(prompt_text),
            completion_tokens=estimate_tokens(text),
        )


class CredentialError(RuntimeError):
    """Raised when a live adapter is selected without usable credentials."""


class OpenAICompatibleAdapter:
    """Minimal client for OpenAI-compatible ``/chat/completions`` endpoints.

    Groq is selected automatically when ``GROQ_KEY`` is present; otherwise the
    OpenAI base URL is used. Credentials are read from the environment at
    construction time and are never included in logs or exception messages.
    """

    def __init__(
        self,
        model: str = "gpt-4o-mini",
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        env: Mapping[str, str] | None = None,
        timeout: float = 30.0,
    ) -> None:
        source = os.environ if env is None else env
        key = api_key or source.get("OPENAI_API_KEY") or source.get("GROQ_KEY")
        if not key:
            raise CredentialError("OPENAI_API_KEY or GROQ_KEY is required for the live adapter")

        if base_url is None:
            base_url = source.get("OPENAI_BASE_URL") or (
                "https://api.groq.com/openai/v1"
                if source.get("GROQ_KEY") and not source.get("OPENAI_API_KEY")
                else "https://api.openai.com/v1"
            )

        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._api_key = key

    def complete(self, messages: Sequence[Message], *, max_tokens: int = 256) -> LLMResponse:
        payload = {
            "model": self.model,
            "messages": [{"role": message.role, "content": message.content} for message in messages],
            "max_tokens": max_tokens,
        }
        started = time.perf_counter()
        response = httpx.post(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self._api_key}"},
            json=payload,
            timeout=self.timeout,
        )
        response.raise_for_status()
        latency_ms = (time.perf_counter() - started) * 1000.0
        data = response.json()
        usage = data.get("usage") or {}
        return LLMResponse(
            text=data["choices"][0]["message"]["content"],
            latency_ms=latency_ms,
            prompt_tokens=int(usage.get("prompt_tokens") or 0),
            completion_tokens=int(usage.get("completion_tokens") or 0),
        )


# ---------------------------------------------------------------------------
# RAG groundedness / hallucination detection
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ClaimAssessment:
    claim: str
    supported_terms: int
    total_terms: int
    numbers_supported: bool = True

    @property
    def support_ratio(self) -> float:
        return 1.0 if self.total_terms == 0 else self.supported_terms / self.total_terms

    @property
    def supported(self) -> bool:
        # A missing number is never a paraphrase: treat it as a hard failure.
        return self.total_terms == 0 or (self.numbers_supported and self.support_ratio >= 0.8)


@dataclass(frozen=True)
class GroundednessResult:
    score: float
    hallucination_rate: float
    claims: tuple[ClaimAssessment, ...]
    unsupported_claims: tuple[str, ...]
    min_score: float

    @property
    def passed(self) -> bool:
        return self.score >= self.min_score


def _terms(text: str) -> list[str]:
    return [token for token in _TOKEN_RE.findall(text.lower()) if len(token) > 2 and token not in _STOPWORDS]


def _claim_assessments(answer: str, source_chunks: Sequence[str]) -> tuple[ClaimAssessment, ...]:
    source_terms = set()
    for chunk in source_chunks:
        source_terms.update(_terms(chunk))

    assessments: list[ClaimAssessment] = []
    for raw_claim in _SENTENCE_SPLIT_RE.split(answer):
        claim = raw_claim.strip()
        if not claim:
            continue
        claim_terms = _terms(claim)
        if not claim_terms:
            continue
        supported = sum(1 for term in claim_terms if term in source_terms)
        numbers_supported = all(number in source_terms for number in _NUMBER_RE.findall(claim))
        assessments.append(
            ClaimAssessment(
                claim=claim,
                supported_terms=supported,
                total_terms=len(claim_terms),
                numbers_supported=numbers_supported,
            )
        )
    return tuple(assessments)


def evaluate_groundedness(
    answer: str,
    source_chunks: Sequence[str],
    *,
    min_score: float = 0.75,
) -> GroundednessResult:
    """Score an answer's claims against retrieved source chunks.

    A claim is grounded when at least 60% of its content terms appear in the
    union of the chunks. The score is the share of grounded claims; any claim
    below the support bar is reported as a hallucination candidate.
    """
    assessments = _claim_assessments(answer, source_chunks)
    if not assessments:
        return GroundednessResult(0.0, 1.0, (), (), min_score)

    grounded = [assessment for assessment in assessments if assessment.supported]
    unsupported = tuple(assessment.claim for assessment in assessments if not assessment.supported)
    score = len(grounded) / len(assessments)
    return GroundednessResult(
        score=score,
        hallucination_rate=1.0 - score,
        claims=assessments,
        unsupported_claims=unsupported,
        min_score=min_score,
    )


# ---------------------------------------------------------------------------
# Structured output validation
# ---------------------------------------------------------------------------


class StructuredOutputError(ValueError):
    """Raised when a model response is not valid JSON for the target schema."""

    def __init__(self, message: str, *, errors: Sequence[Any] = ()) -> None:
        super().__init__(message)
        self.errors = tuple(errors)


def _strip_code_fence(raw: str) -> str:
    return _FENCE_RE.sub("", raw.strip()).strip()


def validate_structured_output(raw: str | Mapping[str, Any], schema: type[BaseModel]) -> BaseModel:
    """Parse JSON and validate it against a Pydantic model (strict extras)."""
    if isinstance(raw, str):
        try:
            payload = json.loads(_strip_code_fence(raw))
        except json.JSONDecodeError as exc:
            raise StructuredOutputError(f"response is not valid JSON: {exc.msg}", errors=(str(exc),)) from exc
    else:
        payload = dict(raw)

    if not isinstance(payload, dict):
        raise StructuredOutputError("response must be a JSON object")

    try:
        return schema.model_validate(payload)
    except ValidationError as exc:
        details = [
            f"{'.'.join(str(part) for part in error['loc']) or '<root>'}: {error['msg']}"
            for error in exc.errors()
        ]
        raise StructuredOutputError("structured output failed schema validation", errors=details) from exc


# ---------------------------------------------------------------------------
# Multi-turn prompt regression
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TurnExpectation:
    must_contain: tuple[str, ...] = ()
    must_not_contain: tuple[str, ...] = ()


@dataclass(frozen=True)
class ConversationResult:
    responses: tuple[str, ...]
    failures: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not self.failures


def run_conversation(
    adapter: LLMAdapter,
    turns: Sequence[str],
    expectations: Sequence[TurnExpectation] | None = None,
    *,
    max_tokens: int = 256,
) -> ConversationResult:
    """Run a scripted conversation and assert per-turn substring rules."""
    if expectations is not None and len(expectations) != len(turns):
        raise ValueError("expectations must align one-to-one with turns")

    history: list[Message] = []
    responses: list[str] = []
    failures: list[str] = []

    for index, turn in enumerate(turns):
        history.append(Message(role="user", content=turn))
        response = adapter.complete(history, max_tokens=max_tokens)
        responses.append(response.text)
        history.append(Message(role="assistant", content=response.text))

        if expectations is None:
            continue
        expected = expectations[index]
        for needle in expected.must_contain:
            if needle.lower() not in response.text.lower():
                failures.append(f"turn {index + 1}: missing required text {needle!r}")
        for needle in expected.must_not_contain:
            if needle.lower() in response.text.lower():
                failures.append(f"turn {index + 1}: forbidden text {needle!r}")

    return ConversationResult(tuple(responses), tuple(failures))


# ---------------------------------------------------------------------------
# Latency / token budgets
# ---------------------------------------------------------------------------


class BudgetExceeded(AssertionError):
    """Raised when a response exceeds a latency or token budget."""


def assert_within_budget(
    response: LLMResponse,
    *,
    max_latency_ms: float | None = None,
    max_total_tokens: int | None = None,
) -> LLMResponse:
    violations: list[str] = []
    if max_latency_ms is not None and response.latency_ms > max_latency_ms:
        violations.append(f"latency {response.latency_ms:.1f}ms > {max_latency_ms:.1f}ms")
    if max_total_tokens is not None and response.total_tokens > max_total_tokens:
        violations.append(f"tokens {response.total_tokens} > {max_total_tokens}")
    if violations:
        raise BudgetExceeded("; ".join(violations))
    return response
