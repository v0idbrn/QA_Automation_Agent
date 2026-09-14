# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Adversarial regression suite (Phase 2 validation, frozen as executable tests).

Locks in the adversarial scenarios that were manually verified during final
validation, so they cannot silently regress:

  * Crash recovery    — interrupted runs can NEVER look successful;
                        classify KeyboardInterrupt / timeout / browser crash /
                        cancellation / worker crash; corrupted manifests are
                        detected, never trusted.
  * Retry caps        — max 3 global retries, max 3 per signature, product
                        bugs / auth / config failures and destructive or
                        non-idempotent actions are never auto-retried;
                        PASS+FAIL => FLAKY, never a confirmed bug.
  * Scope bypass      — DENY UNKNOWN: cross-origin, javascript:/ftp: schemes,
                        userinfo smuggling, path traversal into blocked paths,
                        blocked path tokens, disallowed methods, and the
                        fail-closed default (same-origin denied without an
                        explicit authorization surface). Redirect chains are
                        re-checked hop by hop.
  * Idempotency       — duplicate findings collapse onto one canonical
                        finding with an occurrence counter; fingerprints are
                        stable across runs; concurrent async adds stay
                        deduplicated; the retry budget is a STOP-semaphore.

Crash/async paths use @pytest.mark.asyncio (pytest-asyncio strict mode).
"""

from __future__ import annotations

import asyncio
import json
from contextlib import suppress
from pathlib import Path

import pytest

from core.actions import Action
from core.crash_recovery import CrashRecoveryManager, InterruptKind
from core.failure_analyzer import (
    FailureAnalyzer,
    FailureClassification,
    FailureType,
    FlakyDetector,
    RetryController,
)
from core.finding_manager import FindingManager, compute_fingerprint
from core.models import Confidence, Finding, FindingCategory, Severity
from core.scope import Budget, Scope


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_finding(
    *,
    finding_id: str = "",
    title: str = "button does nothing",
    location: str = "https://example.test/cart",
    description: str = "click produced no effect",
    category: FindingCategory = FindingCategory.FUNCTIONAL,
    severity: Severity = Severity.HIGH,
    confidence: Confidence = Confidence.HIGH,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        title=title,
        location=location,
        description=description,
        category=category,
        severity=severity,
        confidence=confidence,
    )


async def follow_redirect_chain(scope: Scope, chain: list[str]) -> tuple[list[str], list[str]]:
    """Simulate an agent navigating a redirect chain, re-checking scope on
    every hop. Returns (visited_urls, denied_urls)."""
    visited: list[str] = []
    denied: list[str] = []
    for i, url in enumerate(chain):
        await asyncio.sleep(0)  # yield: model concurrent navigation
        if i == 0 or scope.is_allowed(url):
            visited.append(url)
        else:
            denied.append(url)
            break
    return visited, denied


# ---------------------------------------------------------------------------
# Crash recovery
# ---------------------------------------------------------------------------


class TestCrashRecovery:
    def test_keyboard_interrupt_is_classified(self):
        mgr = CrashRecoveryManager()
        assert mgr.classify_exception(KeyboardInterrupt()) is InterruptKind.KEYBOARD_INTERRUPT

    def test_timeout_error_is_classified(self):
        mgr = CrashRecoveryManager()
        assert mgr.classify_exception(TimeoutError("operation timed out")) is InterruptKind.TIMEOUT

    def test_browser_crash_is_classified(self):
        mgr = CrashRecoveryManager()
        assert mgr.classify_exception(RuntimeError("Target closed")) is InterruptKind.BROWSER_CRASH
        assert mgr.classify_exception(RuntimeError("browser has been closed")) is InterruptKind.BROWSER_CRASH

    @pytest.mark.asyncio
    async def test_cancelled_task_is_classified_as_cancellation(self):
        mgr = CrashRecoveryManager()
        task = asyncio.create_task(asyncio.sleep(30))
        await asyncio.sleep(0)
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
        assert mgr.classify_exception(asyncio.CancelledError()) is InterruptKind.CANCELLATION

    @pytest.mark.asyncio
    async def test_async_worker_crash_is_classified(self):
        mgr = CrashRecoveryManager()

        async def worker() -> None:
            raise RuntimeError("worker died unexpectedly")

        with pytest.raises(RuntimeError):
            await worker()
        assert mgr.classify_exception(RuntimeError("worker died unexpectedly")) is InterruptKind.WORKER_CRASH

    def test_interrupted_run_never_looks_successful(self, tmp_path: Path):
        """THE invariant: a suspected-successful payload is downgraded to
        BLOCKED/interrupted when the run is finalized via a crash path."""
        mgr = CrashRecoveryManager()
        payload = {
            "run_id": "run-ki",
            "quality_gate": {"status": "PASS", "passed": True, "reasons": []},
            "tests_executed": 5,
        }
        with pytest.raises(KeyboardInterrupt):
            mgr.run_protected(
                lambda: (_ for _ in ()).throw(KeyboardInterrupt()),
                run_id="run-ki",
                output_dir=tmp_path,
                manifest_payload=payload,
            )
        data = json.loads((tmp_path / "run_manifest.json").read_text(encoding="utf-8"))
        assert data["interrupted"] is True
        assert data["status"] == "INTERRUPTED"
        assert data["quality_gate"]["status"] == "BLOCKED"
        assert data["quality_gate"]["passed"] is False
        assert any("interrupted" in r for r in data["quality_gate"]["reasons"])

    def test_successful_run_writes_no_interrupted_manifest(self, tmp_path: Path):
        mgr = CrashRecoveryManager()
        result = mgr.run_protected(lambda: None, run_id="run-ok", output_dir=tmp_path)
        assert result.manifest_finalized is False
        assert not (tmp_path / "run_manifest.json").exists()

    def test_corrupted_manifest_is_detected_not_trusted(self, tmp_path: Path):
        mgr = CrashRecoveryManager()
        (tmp_path / "run_manifest.json").write_bytes(b"{corrupt json payload...")
        ok, detail = mgr.validate_manifest(tmp_path / "run_manifest.json")
        assert ok is False
        assert "unreadable" in detail

    def test_interrupted_manifest_validates(self, tmp_path: Path):
        mgr = CrashRecoveryManager()
        mgr.finalize_interrupted(
            run_id="run-x",
            output_dir=tmp_path,
            kind=InterruptKind.TIMEOUT,
            detail="step exceeded deadline",
        )
        ok, detail = mgr.validate_manifest(tmp_path / "run_manifest.json")
        assert ok is True
        assert "interrupted" in detail


# ---------------------------------------------------------------------------
# Retry caps
# ---------------------------------------------------------------------------


class TestRetryCaps:
    def _action(self, **kw) -> Action:
        return Action(name="probe", skill="crawler", test_id="t1", **kw)

    def test_transient_failure_retried_then_capped_per_signature(self):
        ctrl = RetryController(max_global=10, max_per_signature=2)
        cls = FailureClassification(FailureType.TIMEOUT, 0.9, "request timed out", "", True)
        sig = "sigA"
        assert ctrl.evaluate(cls, self._action(), sig).should_retry is True
        ctrl.consume(sig)
        assert ctrl.evaluate(cls, self._action(), sig).should_retry is True
        ctrl.consume(sig)
        decision = ctrl.evaluate(cls, self._action(), sig)
        assert decision.should_retry is False
        assert "max retries exhausted for signature" in decision.reason

    def test_global_retry_cap_is_three(self):
        ctrl = RetryController(max_global=3, max_per_signature=3)
        cls = FailureClassification(FailureType.TIMEOUT, 0.9, "request timed out", "", True)
        for i, sig in enumerate(("s1", "s2", "s3")):
            assert ctrl.evaluate(cls, self._action(), sig).should_retry is True
            ctrl.consume(sig)
        decision = ctrl.evaluate(cls, self._action(), "s4")
        assert decision.should_retry is False
        assert decision.reason == "max global retries exhausted"

    def test_product_bug_never_retried_even_if_flagged_retryable(self):
        ctrl = RetryController()
        cls = FailureClassification(FailureType.PRODUCT_BUG, 0.9, "assertion mismatch", "", True)
        decision = ctrl.evaluate(cls, self._action(), "sig")
        assert decision.should_retry is False
        assert "never auto-retryable" in decision.reason

    def test_auth_failure_never_retried(self):
        ctrl = RetryController()
        cls = FailureClassification(FailureType.AUTH_FAILURE, 0.9, "401 unauthorized", "not retryable")
        assert ctrl.evaluate(cls, self._action(), "sig").should_retry is False

    def test_destructive_and_non_idempotent_actions_never_retried(self):
        ctrl = RetryController()
        cls = FailureClassification(FailureType.TIMEOUT, 0.9, "request timed out", "", True)
        assert ctrl.evaluate(cls, self._action(destructive=True), "sig").should_retry is False
        assert ctrl.evaluate(cls, self._action(idempotent=False), "sig").should_retry is False

    def test_analyzer_routes_timeout_to_retryable_classification(self):
        analyzer = FailureAnalyzer()
        finding = make_finding(
            title="slow endpoint",
            description="request timed out after 30s",
            category=FindingCategory.TIMEOUT,
        )
        classification = analyzer.classify(finding)
        assert classification.failure_type is FailureType.TIMEOUT
        assert classification.retryable is True

    def test_analyzer_routes_401_to_non_retryable_auth(self):
        analyzer = FailureAnalyzer()
        finding = make_finding(
            title="login rejected",
            description="server returned http 401 unauthorized",
            category=FindingCategory.HTTP,
        )
        classification = analyzer.classify(finding)
        assert classification.failure_type is FailureType.AUTH_FAILURE
        assert classification.retryable is False

    def test_low_confidence_failure_is_unknown_and_not_retryable(self):
        analyzer = FailureAnalyzer()
        finding = make_finding(
            title="mystery",
            description="could not verify anything",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
        )
        classification = analyzer.classify(finding)
        assert classification.failure_type is FailureType.UNKNOWN
        assert classification.retryable is False
        assert "insufficient evidence" in classification.note

    def test_pass_fail_pair_is_flaky_never_confirmed_bug(self):
        detector = FlakyDetector()
        detector.register_run("t1", "PASS")
        detector.register_run("t1", "FAIL")
        assert detector.status_for("t1") == "FLAKY"
        assert detector.counts()["FLAKY"] == 1

    def test_consistent_failures_stay_fail(self):
        detector = FlakyDetector()
        for _ in range(3):
            detector.register_run("t1", "FAIL")
        assert detector.status_for("t1") == "FAIL"

    def test_blocked_takes_precedence(self):
        detector = FlakyDetector()
        detector.register_run("t1", "PASS")
        detector.register_run("t1", "BLOCKED")
        assert detector.status_for("t1") == "BLOCKED"

    def test_retry_budget_is_a_stop_semaphore(self):
        scope = Scope(allowed_origin="https://example.test")
        budget = Budget(scope=scope)
        budget.start()
        assert [budget.consume_retry() for _ in range(4)] == [True, True, True, False]
        assert budget.exhausted_reason == "retry budget exhausted"
        # STOP semantics: exhaustion is permanent, never silently reset.
        assert budget.is_exhausted() is True
        assert budget.consume_test() is False


# ---------------------------------------------------------------------------
# Scope bypass
# ---------------------------------------------------------------------------


class TestScopeBypass:
    def test_fail_closed_default_denies_even_same_origin(self):
        scope = Scope(allowed_origin="https://example.test")
        assert scope.is_allowed("https://example.test/page") is False
        omits = scope.omits()
        assert omits and "DENY UNKNOWN" in omits[-1].reason

    def test_cross_origin_denied_without_allow_external(self):
        scope = Scope(allowed_origin="https://example.test", default_allow_same_origin=True)
        assert scope.is_allowed("https://evil.test/steal") is False

    def test_javascript_and_ftp_schemes_denied(self):
        scope = Scope(allowed_origin="https://example.test", default_allow_same_origin=True)
        assert scope.is_allowed("javascript:alert(1)") is False
        assert scope.is_allowed("ftp://example.test/file") is False
        assert scope.is_allowed("data:text/html,<script>1</script>") is False

    def test_userinfo_smuggling_denied(self):
        scope = Scope(allowed_origin="https://example.test", default_allow_same_origin=True)
        assert scope.is_allowed("https://example.test:9999@evil.test/") is False

    def test_path_traversal_into_blocked_path_denied(self):
        scope = Scope(allowed_origin="https://example.test", default_allow_same_origin=True)
        assert scope.is_allowed("https://example.test/public/../../admin/users") is False

    def test_blocked_path_token_denied_even_same_origin(self):
        scope = Scope(allowed_origin="https://example.test", default_allow_same_origin=True)
        assert scope.is_allowed("https://example.test/admin/panel") is False
        assert scope.is_allowed("https://example.test/reset-all") is False

    def test_disallowed_method_denied_and_recorded(self):
        scope = Scope(allowed_origin="https://example.test", default_allow_same_origin=True)
        assert scope.is_allowed("https://example.test/api/items", method="POST") is False
        assert any(o.category == "method" for o in scope.omits())

    def test_external_mode_still_enforces_path_allowlist(self):
        scope = Scope(
            allowed_origin="https://example.test",
            allowed_paths=("/login",),
            allow_external=True,
        )
        assert scope.is_allowed("https://partner.test/login") is True
        assert scope.is_allowed("https://partner.test/anything-else") is False

    def test_empty_url_denied(self):
        scope = Scope(allowed_origin="https://example.test", default_allow_same_origin=True)
        assert scope.is_allowed("") is False

    @pytest.mark.asyncio
    async def test_redirect_chain_rechecked_every_hop(self):
        """A redirect that leaves scope must be denied mid-chain, not followed."""
        scope = Scope(allowed_origin="https://example.test", default_allow_same_origin=True)
        chain = [
            "https://example.test/a",
            "https://example.test/b",
            "https://evil.test/steal",
        ]
        visited, denied = await follow_redirect_chain(scope, chain)
        assert visited == ["https://example.test/a", "https://example.test/b"]
        assert denied == ["https://evil.test/steal"]
        assert any("cross-origin" in o.reason for o in scope.omits())


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


class TestIdempotency:
    def test_duplicate_finding_collapses_with_occurrence_counter(self):
        fm = FindingManager()
        primary = make_finding(finding_id="f-1")
        duplicate = make_finding(finding_id="f-1-dup")
        canonical, is_dup = fm.add(primary)
        assert is_dup is False
        canonical2, is_dup2 = fm.add(duplicate)
        assert is_dup2 is True
        assert canonical2.finding_id == "f-1"
        assert duplicate.duplicate_of == "f-1"
        assert fm.occurrences("f-1") == 2
        assert len(fm.findings()) == 1

    def test_fingerprint_is_stable_across_instances_and_runs(self):
        a = compute_fingerprint(make_finding())
        b = compute_fingerprint(make_finding())
        assert a == b and a

    def test_distinct_problems_get_distinct_fingerprints(self):
        fp_a = compute_fingerprint(make_finding(title="broken link", location="https://x.test/a"))
        fp_b = compute_fingerprint(make_finding(title="missing alt", location="https://x.test/b"))
        assert fp_a != fp_b

    def test_extend_dedups_mixed_batch(self):
        fm = FindingManager()
        findings = [
            make_finding(finding_id="a", title="broken link", location="https://x.test/a"),
            make_finding(finding_id="a-dup", title="broken link", location="https://x.test/a"),
            make_finding(finding_id="b", title="missing alt", location="https://x.test/b"),
            make_finding(finding_id="c", title="api 500", location="https://x.test/api"),
            make_finding(finding_id="c-dup", title="api 500", location="https://x.test/api"),
            make_finding(finding_id="c-dup2", title="api 500", location="https://x.test/api"),
        ]
        summary = fm.extend(findings)
        assert summary.total_input == 6
        assert summary.unique_output == 3
        assert summary.duplicates_removed == 3
        counts = fm.by_severity()
        assert counts["HIGH"] == 3

    @pytest.mark.asyncio
    async def test_concurrent_async_adds_stay_deduplicated(self):
        fm = FindingManager()

        async def add_one(finding: Finding) -> tuple[Finding, bool]:
            await asyncio.sleep(0)
            return fm.add(finding)

        originals = [
            make_finding(finding_id=f"id-{i}", title=f"problem {i}", location=f"https://x.test/{i}")
            for i in range(3)
        ]
        batch = originals + [make_finding(finding_id=f"id-{i}-dup", title=f"problem {i}", location=f"https://x.test/{i}") for i in range(3)]
        results = await asyncio.gather(*(add_one(f) for f in batch))
        fresh = sum(1 for _, is_dup in results if not is_dup)
        assert fresh == 3
        assert len(fm.findings()) == 3

    def test_two_runs_over_same_input_are_comparable(self):
        findings = [
            make_finding(finding_id="a", title="broken link", location="https://x.test/a"),
            make_finding(finding_id="b", title="missing alt", location="https://x.test/b"),
            make_finding(finding_id="b-dup", title="missing alt", location="https://x.test/b"),
        ]
        fm1, fm2 = FindingManager(), FindingManager()
        s1, s2 = fm1.extend(findings), fm2.extend(list(findings))
        assert s1.unique_output == s2.unique_output
        assert s1.duplicates_removed == s2.duplicates_removed
        assert [f.finding_id for f in fm1.findings()] == [f.finding_id for f in fm2.findings()]
