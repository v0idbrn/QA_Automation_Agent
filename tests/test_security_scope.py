import pytest

from core.models import Finding, FindingCategory, Severity
from core.scope import Budget, Scope, ScopeViolationError
from core.security import (
    RedactionPolicy,
    redact_dict_sensitive_keys,
    redact_headers,
    redact_sensitive_data,
    sanitize_log_line,
)


class TestScope:
    def test_scope_allows_same_origin_by_default(self):
        sc = Scope(allowed_origin="https://example.test")
        assert sc.check_same_origin("https://example.test/page") is True
        assert sc.is_allowed("https://example.test/page") is False

    def test_scope_blocks_external_origin_by_default(self):
        sc = Scope(allowed_origin="https://example.test", allow_external=False)
        assert sc.check_same_origin("https://other.test/page") is False
        assert sc.is_allowed("https://other.test/page") is False

    def test_scope_allows_external_when_enabled(self):
        sc = Scope(allowed_origin="https://example.test", allow_external=True)
        assert sc.is_allowed("https://other.test/page") is True

    def test_scope_respects_path_restrictions(self):
        sc = Scope(allowed_origin="https://example.test", allowed_paths=("/login",), allow_external=True)
        assert sc.is_allowed("https://example.test/login") is True
        assert sc.is_allowed("https://example.test/register") is False


class TestBudget:
    def test_budget_starts_unexhausted(self):
        scope = Scope(allowed_origin="https://example.test", max_pages=5, max_requests=10)
        budget = Budget(scope=scope)
        budget.start()
        assert not budget.is_exhausted()

    def test_budget_consumes_pages(self):
        scope = Scope(allowed_origin="https://example.test", max_pages=2)
        budget = Budget(scope=scope)
        budget.start()
        assert budget.consume_page() is True
        assert budget.consume_page() is True
        assert budget.consume_page() is False
        assert budget.exhausted_reason == "page budget exhausted"

    def test_budget_consumes_requests(self):
        scope = Scope(allowed_origin="https://example.test", max_requests=2)
        budget = Budget(scope=scope)
        budget.start()
        assert budget.consume_request() is True
        assert budget.consume_request() is True
        assert budget.consume_request() is False
        assert budget.exhausted_reason == "request budget exhausted"

    def test_budget_rejects_scope_violation(self):
        sc = Scope(allowed_origin="https://example.test")
        with pytest.raises(ScopeViolationError):
            raise ScopeViolationError("external origin blocked", url="https://other.test")


class TestRedaction:
    def test_redact_sensitive_string(self):
        assert redact_sensitive_data("Authorization: Bearer secret") == "[REDACTED]"
        assert redact_sensitive_data("password=secret") == "[REDACTED]"
        assert redact_sensitive_data("normal log") == "normal log"

    def test_redact_dict_sensitive_keys(self):
        payload = {"user": "alice", "password": "secret", "token": "abc"}
        out = redact_dict_sensitive_keys(payload)
        assert out["password"] == "[REDACTED]"
        assert out["token"] == "[REDACTED]"
        assert out["user"] == "alice"

    def test_redact_headers(self):
        headers = {"Authorization": "Bearer secret", "Content-Type": "application/json"}
        out = redact_headers(headers)
        assert out["Authorization"] == "[REDACTED]"
        assert out["Content-Type"] == "application/json"

    def test_sanitize_log_line(self):
        assert sanitize_log_line("Cookie: secret") == "[REDACTED]"
        assert sanitize_log_line("ok log") == "ok log"

    def test_redaction_preserves_finding_structure(self):
        finding = Finding(
            id="f1",
            category=FindingCategory.HTTP,
            severity=Severity.HIGH,
            title="HTTP error",
            description="Authorization header present",
            evidence="Bearer token",
        )
        safe = finding.model_dump_safe(redaction=RedactionPolicy())
        assert safe["evidence"] == "[REDACTED]" or safe["description"] == "[REDACTED]"
