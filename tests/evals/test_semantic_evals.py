# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Offline semantic RAG, context, agent, determinism, safety, and cost evals."""

from __future__ import annotations

import pytest

from qa_agent.llm_evals import (
    AgentStep,
    AgentTrace,
    CostBudget,
    MockLLMAdapter,
    build_idf,
    char_ngrams,
    cosine_similarity,
    evaluate_agent_trace,
    evaluate_context_precision,
    evaluate_context_recall,
    evaluate_cost_budget,
    evaluate_determinism,
    evaluate_safety,
    evaluate_semantic_groundedness,
    evaluate_with_judge,
    extract_entities,
    extract_numbers,
    semantic_similarity,
    split_claims,
    tfidf_vector,
)

SOURCE = [
    "The refund window is 30 days from delivery.",
    "Acme Corp charges a 5% restocking fee on opened items.",
]


@pytest.mark.parametrize(
    ("text", "n", "expected_count"),
    [
        ("ab", 3, 2),
        ("abcd", 3, 4),
        ("", 3, 0),
        ("a b", 4, 2),
    ],
)
def test_char_ngrams_counts(text: str, n: int, expected_count: int) -> None:
    grams = char_ngrams(text, n)
    assert len(grams) == expected_count
    assert all(len(gram) == n for gram in grams)


def test_char_ngrams_are_normalized() -> None:
    assert char_ngrams("Pay  Now") == char_ngrams("pay now")


def test_build_idf_rewards_rare_terms() -> None:
    idf = build_idf([["refund", "days"], ["refund", "shipping"]])
    assert idf["days"] > idf["refund"]


def test_tfidf_vector_normalizes_counts() -> None:
    vector = tfidf_vector(["a", "a", "b"], {"a": 1.0, "b": 2.0})
    assert vector["a"] == pytest.approx(2 / 3)
    assert vector["b"] == pytest.approx(2 / 3)


def test_tfidf_vector_empty() -> None:
    assert tfidf_vector([], {}) == {}


def test_cosine_similarity_identity() -> None:
    vector = {"a": 1.0, "b": 2.0}
    assert cosine_similarity(vector, vector) == pytest.approx(1.0)


def test_cosine_similarity_disjoint() -> None:
    assert cosine_similarity({"a": 1.0}, {"b": 1.0}) == 0.0


def test_cosine_similarity_empty() -> None:
    assert cosine_similarity({}, {"a": 1.0}) == 0.0


def test_semantic_similarity_identical() -> None:
    assert semantic_similarity("The refund window is 30 days.", "The refund window is 30 days.") == pytest.approx(1.0)


def test_semantic_similarity_paraphrase_beats_unrelated() -> None:
    paraphrase = semantic_similarity("The refund window is 30 days.", "Refunds are available for 30 days.")
    unrelated = semantic_similarity("The refund window is 30 days.", "Bananas are yellow fruit.")
    assert paraphrase > unrelated
    assert paraphrase >= 0.25


def test_semantic_similarity_empty_text() -> None:
    assert semantic_similarity("", "anything") == 0.0


def test_split_claims() -> None:
    assert split_claims("One. Two! Three?\nFour") == ("One.", "Two!", "Three?", "Four")


def test_extract_numbers_unique() -> None:
    assert extract_numbers("30 days, 30 nights, 4.5 stars") == ("30", "4.5")


def test_extract_entities() -> None:
    entities = extract_entities("Acme Corp refund policy applies in New York.")
    assert "Acme Corp" in entities
    assert "New York" in entities


def test_extract_entities_skips_sentence_start_stopword() -> None:
    entities = extract_entities("The refund window")
    assert "The refund window" not in entities


def test_semantic_groundedness_accepts_grounded_answer() -> None:
    result = evaluate_semantic_groundedness("The refund window is 30 days from delivery.", SOURCE)
    assert result.score == 1.0
    assert result.passed is True
    assert result.missing_numbers == ()


def test_semantic_groundedness_catches_mutated_number() -> None:
    result = evaluate_semantic_groundedness("The refund window is 60 days from delivery.", SOURCE)
    assert result.passed is False
    assert "60" in result.missing_numbers


def test_semantic_groundedness_catches_fabricated_entity() -> None:
    result = evaluate_semantic_groundedness("Beta Inc charges a 5% restocking fee.", SOURCE)
    assert result.passed is False
    assert result.unsupported_claims


def test_semantic_groundedness_catches_paraphrased_hallucination() -> None:
    result = evaluate_semantic_groundedness("Shipping is always free worldwide.", SOURCE)
    assert result.passed is False


def test_semantic_groundedness_partial_score() -> None:
    answer = "The refund window is 30 days from delivery. Shipping is always free worldwide."
    result = evaluate_semantic_groundedness(answer, SOURCE)
    assert result.score == pytest.approx(0.5)
    assert result.hallucination_rate == pytest.approx(0.5)


def test_semantic_groundedness_empty_answer() -> None:
    result = evaluate_semantic_groundedness("", SOURCE)
    assert result.score == 0.0
    assert result.passed is False


def test_semantic_groundedness_custom_threshold() -> None:
    result = evaluate_semantic_groundedness("The refund window is 60 days.", SOURCE, min_score=0.0)
    assert result.passed is True


def test_context_precision_all_relevant() -> None:
    result = evaluate_context_precision(["refund policy", "return window"], ["refund policy", "return window"])
    assert result.precision == 1.0
    assert result.passed is True


def test_context_precision_half() -> None:
    result = evaluate_context_precision(["refund policy", "shipping times"], ["refund policy"])
    assert result.precision == 0.5
    assert result.relevant_indices == (0,)


def test_context_precision_empty_contexts() -> None:
    assert evaluate_context_precision([], ["refund"]).precision == 0.0


def test_context_precision_gate() -> None:
    assert evaluate_context_precision(["a"], ["b"], min_precision=0.6).passed is False


def test_context_recall_full() -> None:
    result = evaluate_context_recall(["refund policy", "return window"], ["refund policy", "return window"])
    assert result.recall == 1.0
    assert result.passed is True


def test_context_recall_missing_fact() -> None:
    result = evaluate_context_recall(["refund policy"], ["refund policy", "return window"])
    assert result.recall == 0.5
    assert result.missing == ("return window",)
    assert result.passed is False


def test_context_recall_no_relevant_contexts() -> None:
    assert evaluate_context_recall([], []).recall == 1.0


def test_agent_trace_clean() -> None:
    trace = AgentTrace((AgentStep("intake", "classify"), AgentStep("checkout", "act"), AgentStep("review", "finish")))
    evaluation = evaluate_agent_trace(trace, required_agents=["intake", "checkout", "review"])
    assert evaluation.passed is True
    assert evaluation.steps == 3


def test_agent_trace_detects_loop() -> None:
    trace = AgentTrace(tuple(AgentStep("worker", "retry", tool="search", payload="x") for _ in range(5)))
    evaluation = evaluate_agent_trace(trace, max_repeats=3)
    assert evaluation.loops
    assert evaluation.passed is False


def test_agent_trace_detects_redundant_tool_calls() -> None:
    trace = AgentTrace(
        (
            AgentStep("worker", "lookup", tool="search", payload="refund"),
            AgentStep("worker", "lookup", tool="search", payload="refund"),
            AgentStep("worker", "answer"),
        )
    )
    evaluation = evaluate_agent_trace(trace)
    assert evaluation.redundant_tool_calls
    assert evaluation.passed is False


def test_agent_trace_missing_required_agent() -> None:
    trace = AgentTrace((AgentStep("intake", "classify"),))
    evaluation = evaluate_agent_trace(trace, required_agents=["intake", "billing"])
    assert any("billing" in failure for failure in evaluation.handoff_failures)


def test_agent_trace_unknown_handoff() -> None:
    trace = AgentTrace((AgentStep("intake", "classify"), AgentStep("intruder", "act")))
    evaluation = evaluate_agent_trace(trace, allowed_agents=["intake", "billing"])
    assert any("intruder" in failure for failure in evaluation.handoff_failures)


def test_agent_trace_ping_pong() -> None:
    agents = ["a", "b", "a", "b", "a", "b"]
    trace = AgentTrace(tuple(AgentStep(agent, "handoff") for agent in agents))
    evaluation = evaluate_agent_trace(trace)
    assert "handoff ping-pong between two agents" in evaluation.handoff_failures


def test_agent_trace_too_many_steps() -> None:
    trace = AgentTrace(tuple(AgentStep(f"agent-{index}", "act") for index in range(5)))
    evaluation = evaluate_agent_trace(trace, max_steps=4)
    assert any("exceeded" in failure for failure in evaluation.handoff_failures)


def test_agent_trace_accepts_mappings() -> None:
    evaluation = evaluate_agent_trace([{"agent": "a", "action": "go", "tool": "t", "payload": "p"}])
    assert evaluation.steps == 1


def test_determinism_stable() -> None:
    result = evaluate_determinism(["same output"] * 4)
    assert result.stable is True
    assert result.unique_outputs == 1


def test_determinism_unstable() -> None:
    result = evaluate_determinism(["The total is 10 USD.", "The total is 99 USD.", "Unrelated sentence entirely."])
    assert result.stable is False
    assert result.unique_outputs == 3


def test_determinism_single_run() -> None:
    result = evaluate_determinism(["only"])
    assert result.min_similarity == 1.0
    assert result.stable is True


@pytest.mark.parametrize(
    ("text", "label"),
    [
        ("Contact qa@example.com", "email"),
        ("SSN 123-45-6789", "ssn"),
        ("Card 4111 1111 1111 1111", "card"),
        ("Host 10.0.0.12", "ipv4"),
    ],
)
def test_safety_flags_pii(text: str, label: str) -> None:
    report = evaluate_safety(text)
    assert label in report.pii
    assert report.passed is False


def test_safety_ignores_invalid_card() -> None:
    report = evaluate_safety("Card 4111 1111 1111 1112")
    assert "card" not in report.pii


def test_safety_flags_toxicity() -> None:
    report = evaluate_safety("You are an idiot for asking.")
    assert "idiot" in report.toxicity
    assert report.passed is False


def test_safety_flags_bias() -> None:
    report = evaluate_safety("Obviously all women are bad at maths.")
    assert report.bias
    assert report.passed is False


def test_safety_clean_text() -> None:
    report = evaluate_safety("The refund window is 30 days from delivery.")
    assert report.passed is True
    assert report.to_dict() == {"pii": [], "toxicity": [], "bias": [], "passed": True}


def test_cost_budget_within_limits() -> None:
    report = evaluate_cost_budget(input_tokens=1000, output_tokens=500, latency_ms=900)
    assert report.total_tokens == 1500
    assert report.passed is True


def test_cost_budget_token_violation() -> None:
    report = evaluate_cost_budget(input_tokens=2000, output_tokens=1500)
    assert any("tokens" in violation for violation in report.violations)


def test_cost_budget_cost_violation() -> None:
    report = evaluate_cost_budget(input_tokens=100_000, output_tokens=100_000)
    assert any("cost" in violation for violation in report.violations)


def test_cost_budget_latency_violation() -> None:
    report = evaluate_cost_budget(input_tokens=1, output_tokens=1, latency_ms=9000)
    assert report.violations == ("latency 9000ms > 2000ms",)


def test_cost_budget_custom_limits() -> None:
    budget = CostBudget(max_total_tokens=10, max_cost_usd=1.0, max_latency_ms=10)
    report = evaluate_cost_budget(input_tokens=5, output_tokens=6, latency_ms=5, budget=budget)
    assert report.passed is False


def test_judge_parses_score() -> None:
    adapter = MockLLMAdapter({"The answer is grounded": "SCORE: 0.9 The answer matches the context."})
    verdict = evaluate_with_judge(adapter, question="q", answer="The answer is grounded", context="ctx")
    assert verdict.score == 0.9
    assert verdict.passed is True
    assert verdict.provider == "MockLLMAdapter"


def test_judge_failure_text() -> None:
    adapter = MockLLMAdapter({"bad answer": "FAIL: unsupported claim."})
    verdict = evaluate_with_judge(adapter, question="q", answer="bad answer")
    assert verdict.score == 0.0
    assert verdict.passed is False


def test_judge_unparseable_is_zero() -> None:
    adapter = MockLLMAdapter({"whatever": "No verdict here."})
    verdict = evaluate_with_judge(adapter, question="q", answer="whatever")
    assert verdict.score == 0.0


def test_judge_respects_min_score() -> None:
    adapter = MockLLMAdapter({"x": "SCORE: 0.5 Mostly right."})
    verdict = evaluate_with_judge(adapter, question="q", answer="x", min_score=0.8)
    assert verdict.passed is False
