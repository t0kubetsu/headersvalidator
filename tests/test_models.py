"""Tests for headersvalidator.models."""

from __future__ import annotations

from headersvalidator.models import HeaderResult, HeadersReport, Status


class TestStatus:
    def test_values(self):
        assert Status.PASS.value == "PASS"
        assert Status.FAIL.value == "FAIL"
        assert Status.WARN.value == "WARN"
        assert Status.INFO.value == "INFO"
        assert Status.DEPRECATED.value == "DEPRECATED"

    def test_str_enum(self):
        # Status inherits from str so it can be serialised as a plain string
        assert Status.PASS == "PASS"


class TestHeaderResult:
    def _make(self, status=Status.PASS, present=True, value="nosniff") -> HeaderResult:
        return HeaderResult(
            name="X-Content-Type-Options",
            status=status,
            present=present,
            value=value,
            recommended="nosniff",
            source="RFC 9110 + OWASP",
            reason="MIME sniffing disabled",
        )

    def test_is_pass(self):
        assert self._make(Status.PASS).is_pass is True
        assert self._make(Status.FAIL).is_pass is False

    def test_is_fail(self):
        assert self._make(Status.FAIL).is_fail is True
        assert self._make(Status.PASS).is_fail is False

    def test_is_warn(self):
        assert self._make(Status.WARN).is_warn is True
        assert self._make(Status.PASS).is_warn is False

    def test_default_iana_status(self):
        r = self._make()
        assert r.iana_status == "permanent"


class TestHeadersReport:
    def _result(self, name, status) -> HeaderResult:
        return HeaderResult(
            name=name,
            status=status,
            present=status != Status.FAIL,
            value=None if status == Status.FAIL else "value",
            recommended="rec",
            source="test",
            reason="test reason",
        )

    def _report(self, *status_pairs) -> HeadersReport:
        results = [self._result(n, s) for n, s in status_pairs]
        return HeadersReport(
            url="https://ex.com",
            status_code=200,
            final_url="https://ex.com",
            results=results,
        )

    def test_status_all_pass(self):
        report = self._report(("H1", Status.PASS), ("H2", Status.PASS))
        assert report.status == Status.PASS

    def test_status_fail_dominates(self):
        report = self._report(("H1", Status.PASS), ("H2", Status.FAIL))
        assert report.status == Status.FAIL

    def test_status_warn_between_pass_and_fail(self):
        report = self._report(("H1", Status.PASS), ("H2", Status.WARN))
        assert report.status == Status.WARN

    def test_is_pass_property(self):
        report = self._report(("H1", Status.PASS))
        assert report.is_pass is True

    def test_passed_list(self):
        report = self._report(("H1", Status.PASS), ("H2", Status.FAIL))
        assert len(report.passed) == 1
        assert report.passed[0].name == "H1"

    def test_failed_list(self):
        report = self._report(("H1", Status.PASS), ("H2", Status.FAIL))
        assert len(report.failed) == 1

    def test_warned_list(self):
        report = self._report(("H1", Status.WARN), ("H2", Status.PASS))
        assert len(report.warned) == 1

    def test_deprecated_list(self):
        report = self._report(("H1", Status.DEPRECATED))
        assert len(report.deprecated) == 1

    def test_score_all_pass(self):
        report = self._report(("H1", Status.PASS), ("H2", Status.PASS))
        assert report.score == 100

    def test_score_all_fail(self):
        report = self._report(("H1", Status.FAIL), ("H2", Status.FAIL))
        assert report.score == 0

    def test_score_mixed(self):
        # 1 PASS (2 pts) + 1 WARN (1 pt) + 1 FAIL (0 pts) out of 6 max → 50%
        report = self._report(
            ("H1", Status.PASS), ("H2", Status.WARN), ("H3", Status.FAIL)
        )
        assert report.score == 50

    def test_score_ignores_info(self):
        # INFO is not graded
        report = self._report(("H1", Status.INFO), ("H2", Status.PASS))
        assert report.score == 100

    def test_score_empty_results(self):
        report = HeadersReport(url="x", status_code=200, final_url="x", results=[])
        assert report.score == 0

    def test_by_name_case_insensitive(self):
        report = self._report(("X-Frame-Options", Status.PASS))
        assert report.by_name("x-frame-options") is not None
        assert report.by_name("X-FRAME-OPTIONS") is not None

    def test_by_name_missing(self):
        report = self._report(("X-Frame-Options", Status.PASS))
        assert report.by_name("Not-A-Header") is None
