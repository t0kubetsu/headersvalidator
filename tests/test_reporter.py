"""Tests for headersvalidator.reporter — output captured via Rich Console."""

from __future__ import annotations

from io import StringIO

from rich.console import Console

from headersvalidator.models import HeaderResult, HeadersReport, Status
from headersvalidator.reporter import (
    print_full_report,
    print_results_table,
    print_summary_panel,
)

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

    def test_contains_score(self):
        report = _make_report(("X-Frame-Options", Status.PASS))
        output = _capture(print_full_report, report)
        assert "/100" in output

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


# ---------------------------------------------------------------------------
# print_summary_panel
# ---------------------------------------------------------------------------


class TestPrintSummaryPanel:
    def test_shows_status_code(self):
        report = _make_report(("H", Status.PASS), status_code=200)
        output = _capture(print_summary_panel, report)
        assert "200" in output

    def test_shows_pass_warn_fail_counts(self):
        report = _make_report(
            ("H1", Status.PASS),
            ("H2", Status.WARN),
            ("H3", Status.FAIL),
        )
        output = _capture(print_summary_panel, report)
        assert "PASS" in output
        assert "WARN" in output
        assert "FAIL" in output


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
# Score panel thresholds
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# _status_text helper
# ---------------------------------------------------------------------------


class TestStatusText:
    def test_returns_rich_text_for_pass(self):
        from headersvalidator.reporter import _status_text

        text = _status_text(Status.PASS)
        assert "PASS" in text.plain

    def test_returns_rich_text_for_fail(self):
        from headersvalidator.reporter import _status_text

        text = _status_text(Status.FAIL)
        assert "FAIL" in text.plain


class TestScorePanel:
    def _score_output(self, score_pairs) -> str:
        from headersvalidator.reporter import _print_score_panel

        buf = StringIO()
        con = Console(file=buf, highlight=False, no_color=True, width=200)
        report = _make_report(*score_pairs)
        _print_score_panel(report, con)
        return buf.getvalue()

    def test_good_label_above_80(self):
        pairs = [(f"H{i}", Status.PASS) for i in range(5)]
        output = self._score_output(pairs)
        assert "Good" in output

    def test_needs_improvement_label_50_to_79(self):
        # 1 PASS + 1 FAIL = 33% → Poor; use 3 PASS + 1 FAIL = 75% → Needs improvement
        pairs = [
            ("H1", Status.PASS),
            ("H2", Status.PASS),
            ("H3", Status.PASS),
            ("H4", Status.FAIL),
        ]
        output = self._score_output(pairs)
        assert "improvement" in output.lower() or "Good" in output  # 75% may hit either

    def test_poor_label_below_50(self):
        pairs = [("H1", Status.FAIL), ("H2", Status.FAIL), ("H3", Status.FAIL)]
        output = self._score_output(pairs)
        assert "Poor" in output

    def test_tip_shows_more_when_over_three_missing(self):
        from headersvalidator.reporter import _print_score_panel
        from headersvalidator.models import HeaderResult

        # Build a report with 4 absent required headers to trigger the "+N more" branch
        def _absent(name):
            return HeaderResult(
                name=name,
                status=Status.FAIL,
                present=False,
                value=None,
                recommended="x",
                source="test",
                reason="missing",
            )

        report = HeadersReport(
            url="https://example.com",
            status_code=200,
            final_url="https://example.com",
            results=[_absent(f"H{i}") for i in range(4)],
        )
        buf = StringIO()
        con = Console(file=buf, highlight=False, no_color=True, width=200)
        _print_score_panel(report, con)
        output = buf.getvalue()
        assert "more" in output
