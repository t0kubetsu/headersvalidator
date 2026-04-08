"""Tests for headersvalidator.constants — rules table integrity."""

from __future__ import annotations

import pytest

from headersvalidator.constants import HEADER_RULES, HTTP_TIMEOUT, RULES_BY_NAME

REQUIRED_KEYS = {
    "name",
    "iana_status",
    "source",
    "required",
    "check",
    "recommended",
    "description",
}
VALID_IANA = {"permanent", "provisional", "deprecated", "obsoleted"}


class TestHeaderRules:
    def test_rules_not_empty(self):
        assert len(HEADER_RULES) > 0

    @pytest.mark.parametrize("rule", HEADER_RULES, ids=lambda r: r.get("name", "?"))
    def test_rule_has_required_keys(self, rule):
        missing = REQUIRED_KEYS - rule.keys()
        assert not missing, f"Rule {rule.get('name')!r} missing keys: {missing}"

    @pytest.mark.parametrize("rule", HEADER_RULES, ids=lambda r: r.get("name", "?"))
    def test_rule_name_is_str(self, rule):
        assert isinstance(rule["name"], str) and rule["name"]

    @pytest.mark.parametrize("rule", HEADER_RULES, ids=lambda r: r.get("name", "?"))
    def test_iana_status_valid(self, rule):
        assert rule["iana_status"] in VALID_IANA

    @pytest.mark.parametrize("rule", HEADER_RULES, ids=lambda r: r.get("name", "?"))
    def test_check_callable(self, rule):
        assert callable(rule["check"])

    @pytest.mark.parametrize("rule", HEADER_RULES, ids=lambda r: r.get("name", "?"))
    def test_required_is_bool(self, rule):
        assert isinstance(rule["required"], bool)

    def test_rules_by_name_lowercase_keys(self):
        for key in RULES_BY_NAME:
            assert key == key.lower(), f"Key {key!r} is not lowercase"

    def test_rules_by_name_complete(self):
        assert len(RULES_BY_NAME) == len(HEADER_RULES)

    def test_no_duplicate_names(self):
        names = [r["name"].lower() for r in HEADER_RULES]
        assert len(names) == len(set(names)), "Duplicate header names in HEADER_RULES"

    def test_http_timeout_positive(self):
        assert HTTP_TIMEOUT > 0


class TestCheckFunctions:
    """Smoke-test every check function returns (Status, str)."""

    @pytest.mark.parametrize("rule", HEADER_RULES, ids=lambda r: r.get("name", "?"))
    def test_check_returns_tuple(self, rule):
        from headersvalidator.models import Status

        # Use the recommended value as a valid input (it may trigger PASS or WARN)
        result = rule["check"](rule["recommended"])
        assert isinstance(result, tuple) and len(result) == 2
        status, reason = result
        assert isinstance(status, Status)
        assert isinstance(reason, str) and reason
