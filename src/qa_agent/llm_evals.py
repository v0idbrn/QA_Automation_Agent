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
from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol, Sequence

import httpx
from pydantic import BaseModel, ValidationError

__all__ = [
    "AgentEvaluation",
    "AgentStep",
    "AgentTrace",
    "BudgetExceeded",
    "ContextPrecisionResult",
    "ContextRecallResult",
    "ConversationResult",
    "CostBudget",
    "CostReport",
    "CredentialError",
    "DeterminismResult",
    "GroundednessResult",
    "JudgeVerdict",
    "LLMResponse",
    "Message",
    "MockLLMAdapter",
    "OpenAICompatibleAdapter",
    "SafetyReport",
    "SemanticClaim",
    "SemanticGroundednessResult",
    "StructuredOutputError",
    "TurnExpectation",
    "assert_within_budget",
    "build_idf",
    "char_ngrams",
    "cosine_similarity",
    "evaluate_agent_trace",
    "evaluate_context_precision",
    "evaluate_context_recall",
    "evaluate_cost_budget",
    "evaluate_determinism",
    "evaluate_groundedness",
    "evaluate_safety",
    "evaluate_semantic_groundedness",
    "evaluate_with_judge",
    "estimate_tokens",
    "extract_entities",
    "extract_numbers",
    "run_conversation",
    "semantic_similarity",
    "split_claims",
    "tfidf_vector",
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

# ---------------------------------------------------------------------------
# Semantic similarity: pure-Python TF-IDF over word tokens and char n-grams
# ---------------------------------------------------------------------------

_WORD_RE = re.compile(r"[a-z0-9]+")
_ENTITY_RE = re.compile(r"\b[A-Z][A-Za-z0-9&.-]*(?:\s+[A-Z][A-Za-z0-9&.-]*)*\b")


def _word_terms(text: str) -> list[str]:
    tokens = [token for token in _WORD_RE.findall((text or "").lower()) if token not in _STOPWORDS]
    # Light plural stemming keeps "refunds" and "refund" in the same feature.
    return [token[:-1] if len(token) > 3 and token.endswith("s") and not token.endswith("ss") else token for token in tokens]


def char_ngrams(text: str, n: int = 3) -> list[str]:
    """Character n-grams with boundary padding, robust to paraphrase."""
    cleaned = " ".join((text or "").lower().split())
    if not cleaned:
        return []
    padded = f" {cleaned} "
    if len(padded) < n:
        return [padded]
    return [padded[index : index + n] for index in range(len(padded) - n + 1)]


def tfidf_vector(terms: Sequence[str], idf: Mapping[str, float]) -> dict[str, float]:
    if not terms:
        return {}
    counts: dict[str, int] = {}
    for term in terms:
        counts[term] = counts.get(term, 0) + 1
    total = float(len(terms))
    return {term: (count / total) * idf.get(term, 1.0) for term, count in counts.items()}


def build_idf(documents: Sequence[Sequence[str]]) -> dict[str, float]:
    document_count = len(documents) or 1
    frequency: dict[str, int] = {}
    for document in documents:
        for term in set(document):
            frequency[term] = frequency.get(term, 0) + 1
    return {term: math.log((1 + document_count) / (1 + count)) + 1.0 for term, count in frequency.items()}


def cosine_similarity(first: Mapping[str, float], second: Mapping[str, float]) -> float:
    if not first or not second:
        return 0.0
    shared = set(first) & set(second)
    numerator = sum(first[term] * second[term] for term in shared)
    first_norm = math.sqrt(sum(value * value for value in first.values()))
    second_norm = math.sqrt(sum(value * value for value in second.values()))
    if first_norm == 0 or second_norm == 0:
        return 0.0
    return max(0.0, min(1.0, numerator / (first_norm * second_norm)))


def _feature_terms(text: str) -> list[str]:
    return [*_word_terms(text), *[f"#{gram}" for gram in char_ngrams(text, 3)]]


def semantic_similarity(first: str, second: str) -> float:
    """TF-IDF cosine over word tokens plus character trigrams."""
    documents = [_feature_terms(first), _feature_terms(second)]
    idf = build_idf(documents)
    return cosine_similarity(tfidf_vector(documents[0], idf), tfidf_vector(documents[1], idf))


def split_claims(text: str) -> tuple[str, ...]:
    return tuple(claim.strip() for claim in _SENTENCE_SPLIT_RE.split(text or "") if claim.strip())


def extract_numbers(text: str) -> tuple[str, ...]:
    return tuple(dict.fromkeys(_NUMBER_RE.findall(text or "")))


def extract_entities(text: str) -> tuple[str, ...]:
    """Capitalized multi-word phrases, skipping sentence-initial stopwords."""
    entities: list[str] = []
    for match in _ENTITY_RE.findall(text or ""):
        words = match.split()
        if words and words[0].lower() in _STOPWORDS:
            words = words[1:]
        candidate = " ".join(words).strip(" .,;:")
        if len(candidate) > 1 and candidate.lower() not in _STOPWORDS:
            entities.append(candidate)
    return tuple(dict.fromkeys(entities))


@dataclass(frozen=True)
class SemanticClaim:
    claim: str
    similarity: float
    numbers_missing: tuple[str, ...] = ()
    entities_missing: tuple[str, ...] = ()

    @property
    def supported(self) -> bool:
        return not self.numbers_missing and not self.entities_missing


@dataclass(frozen=True)
class SemanticGroundednessResult:
    score: float
    claims: tuple[SemanticClaim, ...]
    unsupported_claims: tuple[str, ...]
    missing_numbers: tuple[str, ...]
    min_score: float = 0.6
    similarity_threshold: float = 0.3

    @property
    def passed(self) -> bool:
        return self.score >= self.min_score

    @property
    def hallucination_rate(self) -> float:
        return 1.0 - self.score


def evaluate_semantic_groundedness(
    answer: str,
    source_chunks: Sequence[str],
    *,
    min_score: float = 0.6,
    similarity_threshold: float = 0.25,
) -> SemanticGroundednessResult:
    """Catch paraphrased hallucinations and mutated numbers offline."""
    chunks = [chunk for chunk in source_chunks if chunk]
    source_text = " ".join(chunks)
    source_numbers = set(extract_numbers(source_text))
    source_entities = {entity.lower() for entity in extract_entities(source_text)}

    assessments: list[SemanticClaim] = []
    for claim in split_claims(answer):
        best = max((semantic_similarity(claim, chunk) for chunk in chunks), default=0.0)
        numbers_missing = tuple(number for number in extract_numbers(claim) if number not in source_numbers)
        entities_missing = tuple(
            entity for entity in extract_entities(claim) if entity.lower() not in source_entities
        )
        supported = best >= similarity_threshold and not numbers_missing and not entities_missing
        assessments.append(
            SemanticClaim(claim, best if supported else min(best, similarity_threshold * 0.99), numbers_missing, entities_missing)
        )

    if not assessments:
        return SemanticGroundednessResult(0.0, (), (), (), min_score, similarity_threshold)
    supported_count = sum(1 for assessment in assessments if assessment.supported)
    return SemanticGroundednessResult(
        score=supported_count / len(assessments),
        claims=tuple(assessments),
        unsupported_claims=tuple(assessment.claim for assessment in assessments if not assessment.supported),
        missing_numbers=tuple(dict.fromkeys(number for assessment in assessments for number in assessment.numbers_missing)),
        min_score=min_score,
        similarity_threshold=similarity_threshold,
    )


# ---------------------------------------------------------------------------
# RAG context quality
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ContextPrecisionResult:
    precision: float
    relevant_indices: tuple[int, ...]
    min_precision: float = 0.5

    @property
    def passed(self) -> bool:
        return self.precision >= self.min_precision


@dataclass(frozen=True)
class ContextRecallResult:
    recall: float
    missing: tuple[str, ...]
    min_recall: float = 0.8

    @property
    def passed(self) -> bool:
        return self.recall >= self.min_recall


def _matches(chunk: str, expected: str, threshold: float) -> bool:
    if expected.lower() in chunk.lower() or chunk.lower() in expected.lower():
        return True
    return semantic_similarity(chunk, expected) >= threshold


def evaluate_context_precision(
    contexts: Sequence[str],
    relevant_contexts: Sequence[str],
    *,
    threshold: float = 0.5,
    min_precision: float = 0.5,
) -> ContextPrecisionResult:
    """Share of retrieved chunks that are actually relevant."""
    if not contexts:
        return ContextPrecisionResult(0.0, (), min_precision)
    hits = tuple(
        index
        for index, chunk in enumerate(contexts)
        if any(_matches(chunk, expected, threshold) for expected in relevant_contexts)
    )
    return ContextPrecisionResult(len(hits) / len(contexts), hits, min_precision)


def evaluate_context_recall(
    contexts: Sequence[str],
    relevant_contexts: Sequence[str],
    *,
    threshold: float = 0.5,
    min_recall: float = 0.8,
) -> ContextRecallResult:
    """Share of the known-relevant facts that were retrieved."""
    if not relevant_contexts:
        return ContextRecallResult(1.0, (), min_recall)
    missing = tuple(
        expected
        for expected in relevant_contexts
        if not any(_matches(chunk, expected, threshold) for chunk in contexts)
    )
    return ContextRecallResult(1.0 - len(missing) / len(relevant_contexts), missing, min_recall)


# ---------------------------------------------------------------------------
# Multi-agent orchestration evals
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AgentStep:
    agent: str
    action: str
    tool: str = ""
    payload: str = ""

    @property
    def signature(self) -> tuple[str, str, str, str]:
        return (self.agent, self.action, self.tool, self.payload)


@dataclass(frozen=True)
class AgentTrace:
    steps: tuple[AgentStep, ...]

    @classmethod
    def from_mappings(cls, items: Sequence[Mapping[str, Any]]) -> "AgentTrace":
        return cls(
            tuple(
                AgentStep(
                    agent=str(item.get("agent", "")),
                    action=str(item.get("action", "")),
                    tool=str(item.get("tool", "")),
                    payload=str(item.get("payload", "")),
                )
                for item in items
            )
        )

    @property
    def agents(self) -> tuple[str, ...]:
        return tuple(step.agent for step in self.steps)


@dataclass(frozen=True)
class AgentEvaluation:
    loops: tuple[str, ...] = ()
    handoff_failures: tuple[str, ...] = ()
    redundant_tool_calls: tuple[str, ...] = ()
    steps: int = 0

    @property
    def passed(self) -> bool:
        return not self.loops and not self.handoff_failures and not self.redundant_tool_calls


def _ping_pong(agents: Sequence[str]) -> bool:
    if len(agents) < 6:
        return False
    for index in range(len(agents) - 5):
        window = agents[index : index + 6]
        if len(set(window)) == 2 and window[0] == window[2] == window[4] and window[1] == window[3] == window[5]:
            return True
    return False


def evaluate_agent_trace(
    steps: Sequence[AgentStep] | AgentTrace | Sequence[Mapping[str, Any]],
    *,
    required_agents: Sequence[str] = (),
    allowed_agents: Sequence[str] | None = None,
    max_repeats: int = 3,
    max_steps: int = 40,
) -> AgentEvaluation:
    """Detect infinite loops, failed handoffs, and redundant tool calls."""
    if isinstance(steps, AgentTrace):
        trace = steps
    elif steps and isinstance(steps[0], Mapping):
        trace = AgentTrace.from_mappings(steps)  # type: ignore[arg-type]
    else:
        trace = AgentTrace(tuple(steps))  # type: ignore[arg-type]

    counts: dict[tuple[str, str, str, str], int] = {}
    for step in trace.steps:
        counts[step.signature] = counts.get(step.signature, 0) + 1
    loops = tuple(
        f"{agent}:{action} repeated {count}x"
        for (agent, action, _tool, _payload), count in counts.items()
        if count > max_repeats
    )

    handoffs: list[str] = []
    if len(trace.steps) > max_steps:
        handoffs.append(f"trace exceeded {max_steps} steps ({len(trace.steps)})")
    if allowed_agents:
        allowed = set(allowed_agents)
        unknown = sorted({step.agent for step in trace.steps if step.agent not in allowed})
        handoffs.extend(f"handoff to unknown agent {agent}" for agent in unknown)
    missing = [agent for agent in required_agents if agent not in trace.agents]
    handoffs.extend(f"required agent never reached: {agent}" for agent in missing)
    if _ping_pong(trace.agents):
        handoffs.append("handoff ping-pong between two agents")

    tool_counts: dict[tuple[str, str, str], int] = {}
    for step in trace.steps:
        if step.tool:
            key = (step.agent, step.tool, step.payload)
            tool_counts[key] = tool_counts.get(key, 0) + 1
    redundant = tuple(
        f"{agent}:{tool} called {count}x with the same payload"
        for (agent, tool, _payload), count in tool_counts.items()
        if count > 1
    )

    return AgentEvaluation(
        loops=loops,
        handoff_failures=tuple(handoffs),
        redundant_tool_calls=redundant,
        steps=len(trace.steps),
    )


# ---------------------------------------------------------------------------
# Determinism, safety, cost, and judge
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DeterminismResult:
    runs: int
    min_similarity: float
    unique_outputs: int
    threshold: float = 0.95

    @property
    def stable(self) -> bool:
        return self.unique_outputs <= 1 or self.min_similarity >= self.threshold


def evaluate_determinism(outputs: Sequence[str], *, threshold: float = 0.95) -> DeterminismResult:
    """Compare N runs pairwise; identical output is perfectly stable."""
    texts = [str(item) for item in outputs]
    if len(texts) < 2:
        return DeterminismResult(len(texts), 1.0, len(set(texts)), threshold)
    similarities = [
        semantic_similarity(texts[first], texts[second])
        for first in range(len(texts))
        for second in range(first + 1, len(texts))
    ]
    return DeterminismResult(len(texts), min(similarities), len(set(texts)), threshold)


_PII_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b")),
    ("phone", re.compile(r"\b(?:\+?\d{1,3}[\s.-]?)?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}\b")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("card", re.compile(r"\b(?:\d[ -]?){13,16}\b")),
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
)

_TOXIC_TERMS = frozenset({"idiot", "stupid", "moron", "hate", "kill", "worthless"})
_BIAS_PHRASES = (
    "all women",
    "all men",
    "old people can",
    "young people are",
    "those people are",
    "women can't",
    "men can't",
)


def _luhn(number: str) -> bool:
    digits = [int(char) for char in re.sub(r"\D", "", number)]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


@dataclass
class SafetyReport:
    pii: list[str] = field(default_factory=list)
    toxicity: list[str] = field(default_factory=list)
    bias: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.pii and not self.toxicity and not self.bias

    def to_dict(self) -> dict[str, Any]:
        return {"pii": self.pii, "toxicity": self.toxicity, "bias": self.bias, "passed": self.passed}


def evaluate_safety(text: str) -> SafetyReport:
    """PII, toxicity and bias gate over model output. PII values are never echoed."""
    report = SafetyReport()
    content = text or ""
    for label, pattern in _PII_PATTERNS:
        match = pattern.search(content)
        if not match:
            continue
        if label == "card" and not _luhn(match.group(0)):
            continue
        report.pii.append(label)
    tokens = set(_word_terms(content))
    report.toxicity.extend(sorted(tokens & _TOXIC_TERMS))
    lowered = content.lower()
    report.bias.extend(phrase for phrase in _BIAS_PHRASES if phrase in lowered)
    report.pii = sorted(set(report.pii))
    return report


@dataclass(frozen=True)
class CostBudget:
    max_total_tokens: int = 2000
    max_cost_usd: float = 0.05
    max_latency_ms: float = 2000.0
    input_cost_per_1k: float = 0.0005
    output_cost_per_1k: float = 0.0015


@dataclass(frozen=True)
class CostReport:
    input_tokens: int
    output_tokens: int
    cost_usd: float
    latency_ms: float
    violations: tuple[str, ...] = ()

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    @property
    def passed(self) -> bool:
        return not self.violations


def evaluate_cost_budget(
    *,
    input_tokens: int,
    output_tokens: int,
    latency_ms: float = 0.0,
    budget: CostBudget | None = None,
) -> CostReport:
    limits = budget or CostBudget()
    cost = (input_tokens / 1000) * limits.input_cost_per_1k + (output_tokens / 1000) * limits.output_cost_per_1k
    total = input_tokens + output_tokens
    violations: list[str] = []
    if total > limits.max_total_tokens:
        violations.append(f"tokens {total} > {limits.max_total_tokens}")
    if cost > limits.max_cost_usd:
        violations.append(f"cost ${cost:.4f} > ${limits.max_cost_usd:.4f}")
    if latency_ms > limits.max_latency_ms:
        violations.append(f"latency {latency_ms:.0f}ms > {limits.max_latency_ms:.0f}ms")
    return CostReport(input_tokens, output_tokens, cost, latency_ms, tuple(violations))


@dataclass(frozen=True)
class JudgeVerdict:
    score: float
    passed: bool
    rationale: str = ""
    provider: str = "mock"


def evaluate_with_judge(
    adapter: LLMAdapter,
    *,
    question: str,
    answer: str,
    context: str = "",
    min_score: float = 0.7,
    max_tokens: int = 128,
) -> JudgeVerdict:
    """Optional LLM-as-a-Judge. Defaults to the offline mock adapter."""
    prompt = (
        "You are a strict QA judge. Score the answer from 0 to 1 for correctness, "
        "grounding and completeness.\n"
        f"QUESTION: {question}\nCONTEXT: {context}\nANSWER: {answer}\n"
        "Reply with 'SCORE: <number>' and one sentence of rationale."
    )
    response = adapter.complete([Message("user", prompt)], max_tokens=max_tokens)
    text = response.text or ""
    match = re.search(r"SCORE\s*:\s*([0-9]*\.?[0-9]+)", text, re.IGNORECASE)
    if match:
        score = max(0.0, min(1.0, float(match.group(1))))
    elif "fail" in text.lower():
        score = 0.0
    elif "pass" in text.lower():
        score = 1.0
    else:
        score = 0.0
    provider = type(adapter).__name__
    return JudgeVerdict(score=score, passed=score >= min_score, rationale=text.strip()[:240], provider=provider)
