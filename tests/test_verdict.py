"""Tests for headersvalidator.verdict — extract_verdict_actions and calculate_grade."""

from __future__ import annotations

import pytest

from headersvalidator.models import HeaderResult, HeadersReport, Status
from headersvalidator.verdict import (
    Grade,
    VerdictAction,
    VerdictSeverity,
    calculate_grade,
    extract_verdict_actions,
    _PENALTY,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_REQUIRED_HEADER = "Strict-Transport-Security"
_OPTIONAL_HEADER = "Cache-Control"


def _make_result(
    name: str,
    status: Status,
    *,
    present: bool = True,
    reason: str = "test reason",
) -> HeaderResult:
    return HeaderResult(
        name=name,
        status=status,
        present=present,
        value="value" if present else None,
        recommended="rec",
        source="test",
        reason=reason,
        iana_status="permanent",
    )


def _make_report(*results: HeaderResult) -> HeadersReport:
    return HeadersReport(
        url="https://example.com",
        status_code=200,
        final_url="https://example.com",
        results=list(results),
    )


# ---------------------------------------------------------------------------
# extract_verdict_actions — status filtering
# ---------------------------------------------------------------------------


class TestExtractVerdictActionsFiltering:
    def test_pass_results_are_skipped(self):
        report = _make_report(_make_result(_REQUIRED_HEADER, Status.PASS))
        assert extract_verdict_actions(report) == []

    def test_info_results_are_skipped(self):
        report = _make_report(_make_result(_OPTIONAL_HEADER, Status.INFO, present=False))
        assert extract_verdict_actions(report) == []

    def test_empty_report_returns_empty_list(self):
        report = _make_report()
        assert extract_verdict_actions(report) == []


# ---------------------------------------------------------------------------
# extract_verdict_actions — DEPRECATED
# ---------------------------------------------------------------------------


class TestExtractVerdictActionsDeprecated:
    def test_deprecated_produces_medium_action(self):
        report = _make_report(_make_result("Expect-CT", Status.DEPRECATED))
        actions = extract_verdict_actions(report)
        assert len(actions) == 1
        assert actions[0].severity is VerdictSeverity.MEDIUM

    def test_deprecated_action_text_contains_remove(self):
        report = _make_report(_make_result("Expect-CT", Status.DEPRECATED))
        actions = extract_verdict_actions(report)
        assert "Remove" in actions[0].text

    def test_deprecated_action_header_name(self):
        report = _make_report(_make_result("Expect-CT", Status.DEPRECATED))
        actions = extract_verdict_actions(report)
        assert actions[0].header_name == "Expect-CT"


# ---------------------------------------------------------------------------
# extract_verdict_actions — FAIL (absent)
# ---------------------------------------------------------------------------


class TestExtractVerdictActionsFailAbsent:
    def test_required_absent_is_critical(self):
        result = _make_result(_REQUIRED_HEADER, Status.FAIL, present=False)
        actions = extract_verdict_actions(_make_report(result))
        assert actions[0].severity is VerdictSeverity.CRITICAL

    def test_optional_absent_is_high(self):
        result = _make_result(_OPTIONAL_HEADER, Status.FAIL, present=False)
        actions = extract_verdict_actions(_make_report(result))
        assert actions[0].severity is VerdictSeverity.HIGH

    def test_tier2_required_absent_is_high(self):
        # Tier-2 headers (Referrer-Policy, Permissions-Policy) are required but
        # their absence is HIGH rather than CRITICAL — they are privacy/hygiene
        # headers, not direct-exploit-enabler headers.
        result = _make_result("Referrer-Policy", Status.FAIL, present=False)
        actions = extract_verdict_actions(_make_report(result))
        assert actions[0].severity is VerdictSeverity.HIGH

    def test_tier1_required_absent_is_critical(self):
        # Tier-1 headers (STS, CSP, XFO, XCTO) absent → CRITICAL.
        for header in ("Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"):
            result = _make_result(header, Status.FAIL, present=False)
            actions = extract_verdict_actions(_make_report(result))
            assert actions[0].severity is VerdictSeverity.CRITICAL, f"{header} should be CRITICAL"

    def test_absent_action_text_starts_with_add(self):
        result = _make_result(_REQUIRED_HEADER, Status.FAIL, present=False)
        actions = extract_verdict_actions(_make_report(result))
        assert actions[0].text.startswith("Add")


# ---------------------------------------------------------------------------
# extract_verdict_actions — FAIL (present, bad value)
# ---------------------------------------------------------------------------


class TestExtractVerdictActionsFailPresent:
    def test_required_present_fail_is_high(self):
        result = _make_result(_REQUIRED_HEADER, Status.FAIL, present=True)
        actions = extract_verdict_actions(_make_report(result))
        assert actions[0].severity is VerdictSeverity.HIGH

    def test_optional_present_fail_is_medium(self):
        result = _make_result(_OPTIONAL_HEADER, Status.FAIL, present=True)
        actions = extract_verdict_actions(_make_report(result))
        assert actions[0].severity is VerdictSeverity.MEDIUM

    def test_present_fail_action_text_starts_with_fix(self):
        result = _make_result(_REQUIRED_HEADER, Status.FAIL, present=True)
        actions = extract_verdict_actions(_make_report(result))
        assert actions[0].text.startswith("Fix")


# ---------------------------------------------------------------------------
# extract_verdict_actions — WARN
# ---------------------------------------------------------------------------


class TestExtractVerdictActionsWarn:
    def test_required_warn_is_medium(self):
        result = _make_result(_REQUIRED_HEADER, Status.WARN)
        actions = extract_verdict_actions(_make_report(result))
        assert actions[0].severity is VerdictSeverity.MEDIUM

    def test_optional_warn_is_info(self):
        # Optional headers with sub-optimal values surface at INFO severity
        # (zero penalty) so operators can see them without affecting the grade.
        _TRULY_OPTIONAL = "Cross-Origin-Opener-Policy"
        result = _make_result(_TRULY_OPTIONAL, Status.WARN)
        actions = extract_verdict_actions(_make_report(result))
        assert len(actions) == 1
        assert actions[0].severity is VerdictSeverity.INFO

    def test_optional_warn_info_has_zero_penalty(self):
        assert _PENALTY[VerdictSeverity.INFO] == 0

    def test_optional_warn_action_text_starts_with_note(self):
        _TRULY_OPTIONAL = "Cross-Origin-Opener-Policy"
        result = _make_result(_TRULY_OPTIONAL, Status.WARN)
        actions = extract_verdict_actions(_make_report(result))
        assert actions[0].text.startswith("Note")

    def test_warn_action_text_starts_with_review(self):
        result = _make_result(_REQUIRED_HEADER, Status.WARN)
        actions = extract_verdict_actions(_make_report(result))
        assert actions[0].text.startswith("Review")


# ---------------------------------------------------------------------------
# extract_verdict_actions — sorting
# ---------------------------------------------------------------------------


class TestExtractVerdictActionsSorting:
    def test_results_sorted_critical_first(self):
        results = [
            _make_result("Permissions-Policy", Status.WARN),              # MEDIUM (required+WARN)
            _make_result(_REQUIRED_HEADER, Status.FAIL, present=False),   # CRITICAL
        ]
        actions = extract_verdict_actions(_make_report(*results))
        assert actions[0].severity is VerdictSeverity.CRITICAL
        assert actions[1].severity is VerdictSeverity.MEDIUM

    def test_action_contains_reason(self):
        result = _make_result(_REQUIRED_HEADER, Status.WARN, reason="sub-optimal max-age")
        actions = extract_verdict_actions(_make_report(result))
        assert "sub-optimal max-age" in actions[0].text

    def test_action_header_name_matches(self):
        result = _make_result(_REQUIRED_HEADER, Status.WARN)
        actions = extract_verdict_actions(_make_report(result))
        assert actions[0].header_name == _REQUIRED_HEADER


# ---------------------------------------------------------------------------
# calculate_grade
# ---------------------------------------------------------------------------


class TestCalculateGrade:
    def test_no_actions_gives_a_plus(self):
        grade = calculate_grade([])
        assert grade.letter == "A+"
        assert grade.penalty == 0

    def test_a_plus_rationale(self):
        grade = calculate_grade([])
        assert "No issues" in grade.rationale

    def test_info_only_gives_a_plus_no_penalty(self):
        # INFO actions carry zero penalty and should not affect the grade.
        actions = [VerdictAction("t", VerdictSeverity.INFO, "H")]
        grade = calculate_grade(actions)
        assert grade.letter == "A+"
        assert grade.penalty == 0
        assert "No issues" in grade.rationale

    def test_one_critical_gives_a(self):
        # 10 pts → ≤ 10 threshold → A
        actions = [VerdictAction("t", VerdictSeverity.CRITICAL, "H")]
        grade = calculate_grade(actions)
        assert grade.letter == "A"
        assert grade.penalty == 10

    def test_one_high_gives_a(self):
        # 5 pts → ≤ 10 threshold → A
        actions = [VerdictAction("t", VerdictSeverity.HIGH, "H")]
        grade = calculate_grade(actions)
        assert grade.letter == "A"
        assert grade.penalty == 5

    def test_one_medium_gives_a_plus(self):
        # 2 pts → ≤ 10 threshold → A
        actions = [VerdictAction("t", VerdictSeverity.MEDIUM, "H")]
        grade = calculate_grade(actions)
        assert grade.letter == "A"
        assert grade.penalty == 2

    @pytest.mark.parametrize(
        "actions_spec, expected_letter",
        [
            ([], "A+"),
            ([("MEDIUM",)], "A"),                                         # 2 pts  → ≤ 10 → A
            ([("HIGH",)], "A"),                                           # 5 pts  → ≤ 10 → A
            ([("CRITICAL",)], "A"),                                       # 10 pts → ≤ 10 → A
            ([("CRITICAL",), ("CRITICAL",)], "B"),                        # 20 pts → ≤ 20 → B
            ([("CRITICAL",), ("CRITICAL",), ("CRITICAL",)], "C"),         # 30 pts → ≤ 30 → C
            ([("CRITICAL",), ("CRITICAL",), ("CRITICAL",), ("CRITICAL",)], "D"),  # 40 pts → ≤ 40 → D
        ],
    )
    def test_grade_thresholds(self, actions_spec, expected_letter):
        severity_map = {
            "CRITICAL": VerdictSeverity.CRITICAL,
            "HIGH": VerdictSeverity.HIGH,
            "MEDIUM": VerdictSeverity.MEDIUM,
        }
        actions = [VerdictAction("t", severity_map[s[0]], "H") for s in actions_spec]
        grade = calculate_grade(actions)
        assert grade.letter == expected_letter

    def test_rationale_mentions_critical_count(self):
        actions = [VerdictAction("t", VerdictSeverity.CRITICAL, "H")]
        grade = calculate_grade(actions)
        assert "1 critical" in grade.rationale

    def test_rationale_mentions_high_count(self):
        actions = [VerdictAction("t", VerdictSeverity.HIGH, "H")]
        grade = calculate_grade(actions)
        assert "1 high" in grade.rationale

    def test_rationale_mentions_medium_count(self):
        actions = [VerdictAction("t", VerdictSeverity.MEDIUM, "H")]
        grade = calculate_grade(actions)
        assert "1 medium" in grade.rationale

    def test_penalty_accumulates(self):
        actions = [
            VerdictAction("t", VerdictSeverity.CRITICAL, "H"),  # 10
            VerdictAction("t", VerdictSeverity.HIGH, "H"),       # 5
            VerdictAction("t", VerdictSeverity.MEDIUM, "H"),     # 2
        ]
        grade = calculate_grade(actions)
        assert grade.penalty == 17

    def test_d_grade_boundary(self):
        # 4 CRITICAL = 40 pts → D (≤ 40)
        actions = [VerdictAction("t", VerdictSeverity.CRITICAL, "H") for _ in range(4)]
        grade = calculate_grade(actions)
        assert grade.letter == "D"
        assert grade.penalty == 40

    def test_f_grade_just_above_d_boundary(self):
        # 5 CRITICAL = 50 pts → F (> 40)
        actions = [VerdictAction("t", VerdictSeverity.CRITICAL, "H") for _ in range(5)]
        grade = calculate_grade(actions)
        assert grade.letter == "F"
        assert grade.penalty == 50
