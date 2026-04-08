"""Tests for headersvalidator.cli — Typer CLI commands."""

from __future__ import annotations

import json
from unittest.mock import patch

import requests
from typer.testing import CliRunner

from headersvalidator.cli import app
from headersvalidator.models import HeaderResult, HeadersReport, Status


runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_report(
    status: Status, score: int = 80, url="https://example.com"
) -> HeadersReport:
    result = HeaderResult(
        name="X-Frame-Options",
        status=status,
        present=status == Status.PASS,
        value="DENY" if status == Status.PASS else None,
        recommended="DENY",
        source="test",
        reason="test",
    )
    report = HeadersReport(url=url, status_code=200, final_url=url, results=[result])
    return report


def _patch_assess(report: HeadersReport):
    """Return a context manager that patches headersvalidator.assessor.assess."""
    return patch("headersvalidator.assessor.assess", return_value=report)


def _patch_assess_error(exc):
    return patch("headersvalidator.assessor.assess", side_effect=exc)


# ---------------------------------------------------------------------------
# check command — basic
# ---------------------------------------------------------------------------


class TestCheckCommand:
    def test_exits_0_on_pass(self):
        report = _make_report(Status.PASS)
        with _patch_assess(report):
            result = runner.invoke(app, ["check", "https://example.com"])
        assert result.exit_code == 0

    def test_exits_1_on_fail(self):
        report = _make_report(Status.FAIL)
        with _patch_assess(report):
            result = runner.invoke(app, ["check", "https://example.com"])
        assert result.exit_code == 1

    def test_exits_0_on_warn_without_strict(self):
        report = _make_report(Status.WARN)
        with _patch_assess(report):
            result = runner.invoke(app, ["check", "https://example.com"])
        assert result.exit_code == 0

    def test_exits_1_on_warn_with_strict(self):
        report = _make_report(Status.WARN)
        with _patch_assess(report):
            result = runner.invoke(app, ["check", "--strict", "https://example.com"])
        assert result.exit_code == 1

    def test_exits_2_on_network_error(self):
        with _patch_assess_error(requests.ConnectionError("refused")):
            result = runner.invoke(app, ["check", "https://unreachable.example.com"])
        assert result.exit_code == 2

    def test_output_contains_url(self):
        report = _make_report(Status.PASS, url="https://example.com")
        with _patch_assess(report):
            result = runner.invoke(app, ["check", "https://example.com"])
        assert "example.com" in result.output

    def test_output_contains_score(self):
        report = _make_report(Status.PASS)
        with _patch_assess(report):
            result = runner.invoke(app, ["check", "https://example.com"])
        assert "/100" in result.output

    def test_custom_timeout_passed(self):
        report = _make_report(Status.PASS)
        captured = {}

        def fake_assess(url, timeout=10.0, **kw):
            captured["timeout"] = timeout
            return report

        with patch("headersvalidator.assessor.assess", side_effect=fake_assess):
            runner.invoke(app, ["check", "https://example.com", "--timeout", "30"])

        assert captured.get("timeout") == 30.0

    def test_no_tls_verify_flag(self):
        report = _make_report(Status.PASS)
        captured = {}

        def fake_assess(url, verify_tls=True, **kw):
            captured["verify_tls"] = verify_tls
            return report

        with patch("headersvalidator.assessor.assess", side_effect=fake_assess):
            runner.invoke(app, ["check", "https://example.com", "--no-tls-verify"])

        assert captured.get("verify_tls") is False


# ---------------------------------------------------------------------------
# check --json
# ---------------------------------------------------------------------------


class TestCheckJsonOutput:
    def test_json_flag_produces_valid_json(self):
        report = _make_report(Status.PASS)
        with _patch_assess(report):
            result = runner.invoke(app, ["check", "--json", "https://example.com"])
        data = json.loads(result.output)
        assert "url" in data
        assert "status" in data
        assert "score" in data
        assert "results" in data

    def test_json_result_fields(self):
        report = _make_report(Status.PASS)
        with _patch_assess(report):
            result = runner.invoke(app, ["check", "--json", "https://example.com"])
        data = json.loads(result.output)
        first_result = data["results"][0]
        for key in (
            "name",
            "status",
            "present",
            "value",
            "recommended",
            "source",
            "reason",
        ):
            assert key in first_result, f"Missing key {key!r} in result"

    def test_json_status_values_are_strings(self):
        report = _make_report(Status.PASS)
        with _patch_assess(report):
            result = runner.invoke(app, ["check", "--json", "https://example.com"])
        data = json.loads(result.output)
        assert isinstance(data["status"], str)
        assert data["status"] == "PASS"


# ---------------------------------------------------------------------------
# info subcommands
# ---------------------------------------------------------------------------


class TestInfoRules:
    def test_exits_0(self):
        result = runner.invoke(app, ["info", "rules"])
        assert result.exit_code == 0

    def test_shows_header_names(self):
        result = runner.invoke(app, ["info", "rules"])
        assert "Strict-Transport-Security" in result.output
        assert "Content-Security-Policy" in result.output

    def test_shows_recommended_column(self):
        result = runner.invoke(app, ["info", "rules"])
        assert "nosniff" in result.output  # X-Content-Type-Options recommended value

    def test_shows_iana_status(self):
        result = runner.invoke(app, ["info", "rules"])
        assert "permanent" in result.output


class TestInfoSources:
    def test_exits_0(self):
        result = runner.invoke(app, ["info", "sources"])
        assert result.exit_code == 0

    def test_shows_rfc_9110(self):
        result = runner.invoke(app, ["info", "sources"])
        assert "RFC 9110" in result.output

    def test_shows_rfc_9111(self):
        result = runner.invoke(app, ["info", "sources"])
        assert "RFC 9111" in result.output

    def test_shows_owasp(self):
        result = runner.invoke(app, ["info", "sources"])
        assert "OWASP" in result.output

    def test_shows_iana(self):
        result = runner.invoke(app, ["info", "sources"])
        assert "IANA" in result.output


class TestInfoIana:
    def test_exits_0(self):
        result = runner.invoke(app, ["info", "iana"])
        assert result.exit_code == 0

    def test_shows_all_iana_statuses(self):
        result = runner.invoke(app, ["info", "iana"])
        assert "permanent" in result.output

    def test_shows_obsoleted_for_expect_ct(self):
        result = runner.invoke(app, ["info", "iana"])
        assert "Expect-CT" in result.output
        assert "obsoleted" in result.output


# ---------------------------------------------------------------------------
# --version flag
# ---------------------------------------------------------------------------


class TestVersionFlag:
    def test_version_flag(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "headersvalidator" in result.output

    def test_version_contains_number(self):
        result = runner.invoke(app, ["--version"])
        import re

        assert re.search(r"\d+\.\d+", result.output)
