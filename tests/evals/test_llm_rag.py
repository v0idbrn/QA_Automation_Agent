# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Deterministic LLM and RAG evaluation suite (offline by default)."""

from __future__ import annotations

import pytest
from pydantic import BaseModel, ConfigDict, Field

from qa_agent.llm_evals import (
    BudgetExceeded,
    CredentialError,
    LLMResponse,
    Message,
    MockLLMAdapter,
    OpenAICompatibleAdapter,
    StructuredOutputError,
    TurnExpectation,
    assert_within_budget,
    estimate_tokens,
    evaluate_groundedness,
    run_conversation,
    validate_structured_output,
)


class RAGAnswer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    answer: str
    citations: list[str] = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)


SOURCE_CHUNKS = (
    "The Eiffel Tower is located in Paris, France. It was completed in 1889.",
    "The tower is 330 metres tall and receives millions of visitors each year.",
)


# ---------------------------------------------------------------------------
# RAG groundedness / hallucination detection
# ---------------------------------------------------------------------------


def test_grounded_answer_scores_full_groundedness() -> None:
    result = evaluate_groundedness(
        "The Eiffel Tower is located in Paris, France. It was completed in 1889.",
        SOURCE_CHUNKS,
    )
    assert result.score == 1.0
    assert result.hallucination_rate == 0.0
    assert result.passed is True
    assert result.unsupported_claims == ()


def test_unsupported_entity_is_flagged_as_hallucination() -> None:
    result = evaluate_groundedness(
        "The Eiffel Tower is located in Berlin. It was completed in 1889.",
        SOURCE_CHUNKS,
    )
    assert result.score < 1.0
    assert any("Berlin" in claim for claim in result.unsupported_claims)


def test_numeric_hallucination_is_flagged() -> None:
    result = evaluate_groundedness("The Eiffel Tower was completed in 1912.", SOURCE_CHUNKS)
    assert result.score == 0.0
    assert result.unsupported_claims == ("The Eiffel Tower was completed in 1912.",)


def test_empty_answer_scores_zero() -> None:
    result = evaluate_groundedness("", SOURCE_CHUNKS)
    assert result.score == 0.0
    assert result.hallucination_rate == 1.0
    assert result.passed is False


def test_partial_grounding_reports_hallucination_rate() -> None:
    result = evaluate_groundedness(
        "The tower is 330 metres tall. The tower is made of titanium.",
        SOURCE_CHUNKS,
        min_score=0.75,
    )
    assert result.score == 0.5
    assert result.hallucination_rate == 0.5
    assert result.passed is False


def test_unsupported_claims_are_reported_with_source_evidence() -> None:
    result = evaluate_groundedness("The tower is in Paris. It has a glass elevator.", SOURCE_CHUNKS)
    assert len(result.claims) == 2
    assert result.unsupported_claims == ("It has a glass elevator.",)


# ---------------------------------------------------------------------------
# Structured JSON output validation
# ---------------------------------------------------------------------------


def test_valid_structured_output_passes() -> None:
    raw = '{"answer": "Paris", "citations": ["chunk-1"], "confidence": 0.91}'
    parsed = validate_structured_output(raw, RAGAnswer)
    assert parsed.answer == "Paris"
    assert parsed.confidence == pytest.approx(0.91)


def test_fenced_json_output_is_accepted() -> None:
    raw = '```json\n{"answer": "Paris", "citations": ["chunk-1"], "confidence": 0.8}\n```'
    assert validate_structured_output(raw, RAGAnswer).citations == ["chunk-1"]


def test_invalid_json_is_rejected() -> None:
    with pytest.raises(StructuredOutputError, match="not valid JSON"):
        validate_structured_output('{"answer": "Paris",', RAGAnswer)


def test_missing_required_field_is_rejected() -> None:
    with pytest.raises(StructuredOutputError) as excinfo:
        validate_structured_output('{"answer": "Paris"}', RAGAnswer)
    assert any("citations" in detail for detail in excinfo.value.errors)


def test_extra_field_is_rejected_by_strict_schema() -> None:
    with pytest.raises(StructuredOutputError) as excinfo:
        validate_structured_output(
            '{"answer": "Paris", "citations": ["c1"], "confidence": 0.5, "debug": true}',
            RAGAnswer,
        )
    assert any("debug" in detail for detail in excinfo.value.errors)


def test_out_of_range_confidence_is_rejected() -> None:
    with pytest.raises(StructuredOutputError, match="schema validation"):
        validate_structured_output(
            '{"answer": "Paris", "citations": ["c1"], "confidence": 1.7}',
            RAGAnswer,
        )


def test_non_object_json_is_rejected() -> None:
    with pytest.raises(StructuredOutputError, match="JSON object"):
        validate_structured_output("[]", RAGAnswer)


# ---------------------------------------------------------------------------
# Multi-turn prompt regression
# ---------------------------------------------------------------------------


def test_multi_turn_conversation_passes_assertions() -> None:
    adapter = MockLLMAdapter(
        {
            "What is the capital of France?": "Paris is the capital of France.",
            "Which river runs through it?": "The Seine runs through Paris.",
        }
    )
    result = run_conversation(
        adapter,
        ["What is the capital of France?", "Which river runs through it?"],
        [
            TurnExpectation(must_contain=("Paris",)),
            TurnExpectation(must_contain=("Seine",), must_not_contain=("Rhine",)),
        ],
    )
    assert result.passed is True
    assert len(result.responses) == 2


def test_multi_turn_regression_detects_forbidden_phrase() -> None:
    adapter = MockLLMAdapter(
        {
            "Change the order.": "Sure, I cancelled the order and issued a refund.",
        }
    )
    result = run_conversation(
        adapter,
        ["Change the order."],
        [TurnExpectation(must_not_contain=("cancelled",))],
    )
    assert result.passed is False
    assert "forbidden text 'cancelled'" in result.failures[0]


def test_multi_turn_regression_detects_missing_required_phrase() -> None:
    adapter = MockLLMAdapter({"Summarize.": "The report contains data."})
    result = run_conversation(adapter, ["Summarize."], [TurnExpectation(must_contain=("risk",))])
    assert result.passed is False
    assert "missing required text 'risk'" in result.failures[0]


def test_multi_turn_history_is_preserved() -> None:
    adapter = MockLLMAdapter({"first": "one", "second": "two"})
    run_conversation(adapter, ["first", "second"])
    second_call = adapter.calls[1]
    assert [message.role for message in second_call] == ["user", "assistant", "user"]
    assert second_call[1].content == "one"


def test_multi_turn_expectation_length_must_match() -> None:
    with pytest.raises(ValueError, match="align"):
        run_conversation(MockLLMAdapter(), ["one", "two"], [TurnExpectation()])


# ---------------------------------------------------------------------------
# Latency and token budgets
# ---------------------------------------------------------------------------


def test_latency_budget_passes_under_threshold() -> None:
    response = LLMResponse(text="ok", latency_ms=120.0, prompt_tokens=10, completion_tokens=5)
    assert assert_within_budget(response, max_latency_ms=200.0) is response


def test_latency_budget_fails_over_threshold() -> None:
    response = LLMResponse(text="slow", latency_ms=450.0, prompt_tokens=10, completion_tokens=5)
    with pytest.raises(BudgetExceeded, match="latency"):
        assert_within_budget(response, max_latency_ms=300.0)


def test_token_budget_fails_over_threshold() -> None:
    response = LLMResponse(text="long", latency_ms=10.0, prompt_tokens=80, completion_tokens=40)
    with pytest.raises(BudgetExceeded, match="tokens"):
        assert_within_budget(response, max_total_tokens=100)


def test_token_estimate_never_returns_zero() -> None:
    assert estimate_tokens("") == 1
    assert estimate_tokens("four") == 1
    assert estimate_tokens("x" * 400) == 100


# ---------------------------------------------------------------------------
# Adapter contracts
# ---------------------------------------------------------------------------


def test_mock_adapter_is_deterministic_and_offline() -> None:
    adapter = MockLLMAdapter({"ping": "pong"})
    first = adapter.complete([Message("user", "ping")])
    second = adapter.complete([Message("user", "ping")])
    assert first.text == second.text == "pong"
    assert first.total_tokens == second.total_tokens
    assert len(adapter.calls) == 2


def test_mock_adapter_defaults_to_grounded_refusal() -> None:
    response = MockLLMAdapter().complete([Message("user", "unknown prompt")])
    assert "supplied context" in response.text


def test_live_adapter_requires_credentials() -> None:
    with pytest.raises(CredentialError):
        OpenAICompatibleAdapter(env={})


def test_live_adapter_uses_groq_base_url_from_env() -> None:
    adapter = OpenAICompatibleAdapter(env={"GROQ_KEY": "gsk_test_key"})
    assert adapter.base_url == "https://api.groq.com/openai/v1"


def test_live_adapter_prefers_explicit_openai_base_url() -> None:
    adapter = OpenAICompatibleAdapter(
        env={"OPENAI_API_KEY": "sk-test", "OPENAI_BASE_URL": "https://llm.internal/v1"}
    )
    assert adapter.base_url == "https://llm.internal/v1"


def test_live_adapter_never_exposes_credential_in_repr() -> None:
    adapter = OpenAICompatibleAdapter(env={"GROQ_KEY": "gsk_super_secret"})
    assert "gsk_super_secret" not in repr(adapter)
