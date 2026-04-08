"""Tests for headersvalidator.reporter — output captured via Rich Console."""

from __future__ import annotations

from io import StringIO

from rich.console import Console

from headersvalidator.models import HeaderResult, HeadersReport, Status
from headersvalidator.reporter import (
    _grade_text,
    _print_verdict,
    _status_text,
    print_full_report,
    print_results_table,
)
from headersvalidator.verdict import Grade, VerdictAction, VerdictSeverity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_result(name, status, present=True, value="value") -> HeaderResult:
    return HeaderResult(
        name=name,
        status=status,
        present=present,
        value=value if present else None,
        recommended="rec",
        source="test",
        reason="test reason",
        iana_status="permanent",
    )


def _make_report(*pairs, url="https://example.com", status_code=200) -> HeadersReport:
    return HeadersReport(
        url=url,
        status_code=status_code,
        final_url=url,
        results=[_make_result(n, s) for n, s in pairs],
    )


def _capture(fn, *args, **kwargs) -> str:
    """Run *fn* with a fresh Console writing to a StringIO, return captured text."""
    buf = StringIO()
    console = Console(file=buf, highlight=False, no_color=True, width=200)
    fn(*args, console=console, **kwargs)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# print_full_report
# ---------------------------------------------------------------------------


class TestPrintFullReport:
    def test_runs_without_error(self):
        report = _make_report(("X-Frame-Options", Status.PASS))
        output = _capture(print_full_report, report)
        assert output  # something was written

    def test_contains_url(self):
        report = _make_report(("X-Frame-Options", Status.PASS))
        output = _capture(print_full_report, report)
        assert "example.com" in output

    def test_contains_header_name(self):
        report = _make_report(("X-Frame-Options", Status.PASS))
        output = _capture(print_full_report, report)
        assert "X-Frame-Options" in output

    def test_contains_grade_letter(self):
        report = _make_report(("X-Frame-Options", Status.PASS))
        output = _capture(print_full_report, report)
        # Grade letters A+, A, B, C, D, F must appear somewhere
        assert any(g in output for g in ("A+", "A", "B", "C", "D", "F"))

    def test_shows_pass_verdict(self):
        report = _make_report(("X-Frame-Options", Status.PASS))
        output = _capture(print_full_report, report)
        assert "PASS" in output

    def test_shows_fail_verdict(self):
        report = _make_report(("X-Frame-Options", Status.FAIL), ("CSP", Status.FAIL))
        output = _capture(print_full_report, report)
        assert "FAIL" in output

    def test_shows_warn_verdict(self):
        report = _make_report(("X-Frame-Options", Status.WARN))
        output = _capture(print_full_report, report)
        assert "WARN" in output

    def test_shows_end_of_report_rule(self):
        report = _make_report(("X-Frame-Options", Status.PASS))
        output = _capture(print_full_report, report)
        assert "End of Report" in output


# ---------------------------------------------------------------------------
# print_results_table
# ---------------------------------------------------------------------------


class TestPrintResultsTable:
    def test_shows_iana_status(self):
        report = _make_report(("X-Frame-Options", Status.PASS))
        output = _capture(print_results_table, report)
        assert "permanent" in output

    def test_shows_reason(self):
        result = _make_result("X-Frame-Options", Status.PASS)
        result.reason = "uniquereasonstring"
        report = HeadersReport(
            url="https://example.com",
            status_code=200,
            final_url="https://example.com",
            results=[result],
        )
        output = _capture(print_results_table, report)
        assert "uniquereasonstring" in output

    def test_shows_present_yes_for_present_header(self):
        report = _make_report(("X-Frame-Options", Status.PASS))
        output = _capture(print_results_table, report)
        assert "yes" in output.lower()

    def test_shows_present_no_for_absent_header(self):
        result = _make_result("X-Frame-Options", Status.FAIL, present=False)
        report = HeadersReport(
            url="https://example.com",
            status_code=200,
            final_url="https://example.com",
            results=[result],
        )
        output = _capture(print_results_table, report)
        assert "no" in output.lower()

    def test_shows_deprecated_status(self):
        report = _make_report(("Expect-CT", Status.DEPRECATED))
        output = _capture(print_results_table, report)
        assert "DEPRECATED" in output

    def test_truncates_long_value(self):
        result = _make_result("Content-Security-Policy", Status.WARN, value="x" * 200)
        report = HeadersReport(
            url="https://example.com",
            status_code=200,
            final_url="https://example.com",
            results=[result],
        )
        output = _capture(print_results_table, report)
        # Should not contain the full 200-character value verbatim
        assert "x" * 200 not in output
        assert "…" in output  # truncation indicator

    def test_multiple_results_all_shown(self):
        report = _make_report(
            ("Strict-Transport-Security", Status.PASS),
            ("X-Frame-Options", Status.FAIL),
            ("Referrer-Policy", Status.WARN),
        )
        output = _capture(print_results_table, report)
        assert "Strict-Transport-Security" in output
        assert "X-Frame-Options" in output
        assert "Referrer-Policy" in output


# ---------------------------------------------------------------------------
# _status_text helper
# ---------------------------------------------------------------------------


class TestStatusText:
    def test_returns_rich_text_for_pass(self):
        text = _status_text(Status.PASS)
        assert "PASS" in text.plain

    def test_returns_rich_text_for_fail(self):
        text = _status_text(Status.FAIL)
        assert "FAIL" in text.plain


# ---------------------------------------------------------------------------
# _grade_text helper
# ---------------------------------------------------------------------------


class TestGradeText:
    def test_includes_letter(self):
        grade = Grade(letter="A+", penalty=0, rationale="No issues found — all evaluated headers pass.")
        text = _grade_text(grade)
        assert "A+" in text.plain

    def test_includes_rationale(self):
        grade = Grade(letter="F", penalty=50, rationale="2 critical issue(s) found (50 penalty point(s)).")
        text = _grade_text(grade)
        assert "critical" in text.plain

    def test_unknown_grade_letter_uses_default_style(self):
        grade = Grade(letter="Z", penalty=0, rationale="test")
        text = _grade_text(grade)
        assert "Z" in text.plain


# ---------------------------------------------------------------------------
# _print_verdict
# ---------------------------------------------------------------------------


class TestPrintVerdict:
    def _verdict_output(self, actions, grade) -> str:
        buf = StringIO()
        con = Console(file=buf, highlight=False, no_color=True, width=200)
        _print_verdict(actions, grade, con)
        return buf.getvalue()

    def test_shows_critical_action(self):
        actions = [
            VerdictAction(
                text="Add Strict-Transport-Security: missing required header",
                severity=VerdictSeverity.CRITICAL,
                header_name="Strict-Transport-Security",
            )
        ]
        grade = Grade(letter="F", penalty=25, rationale="1 critical issue(s) found (25 penalty point(s)).")
        output = self._verdict_output(actions, grade)
        assert "CRITICAL" in output
        assert "Strict-Transport-Security" in output

    def test_shows_high_action(self):
        actions = [
            VerdictAction(
                text="Fix X-Frame-Options: bad value",
                severity=VerdictSeverity.HIGH,
                header_name="X-Frame-Options",
            )
        ]
        grade = Grade(letter="B", penalty=10, rationale="1 high issue(s) found (10 penalty point(s)).")
        output = self._verdict_output(actions, grade)
        assert "HIGH" in output

    def test_shows_medium_action(self):
        actions = [
            VerdictAction(
                text="Remove Expect-CT: deprecated header should not be sent",
                severity=VerdictSeverity.MEDIUM,
                header_name="Expect-CT",
            )
        ]
        grade = Grade(letter="A", penalty=3, rationale="1 medium issue(s) found (3 penalty point(s)).")
        output = self._verdict_output(actions, grade)
        assert "MEDIUM" in output

    def test_shows_pass_when_no_actions(self):
        grade = Grade(letter="A+", penalty=0, rationale="No issues found — all evaluated headers pass.")
        output = self._verdict_output([], grade)
        assert "PASS" in output

    def test_shows_grade_letter(self):
        grade = Grade(letter="C", penalty=30, rationale="1 critical, 1 high issue(s) found (35 penalty point(s)).")
        output = self._verdict_output([], grade)
        assert "C" in output
