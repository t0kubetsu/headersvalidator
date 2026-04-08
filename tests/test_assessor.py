"""Tests for headersvalidator.assessor — all network I/O mocked at fetch_headers."""

from __future__ import annotations

import pytest
import requests

from headersvalidator.assessor import assess
from headersvalidator.models import Status
from tests.conftest import (
    EMPTY_HEADERS,
    MINIMAL_REQUIRED_HEADERS,
    SECURE_HEADERS,
    make_response,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_assess(monkeypatch, headers, status_code=200, url="https://example.com"):
    """Patch fetch_headers and call assess()."""
    response = make_response(headers=headers, status_code=status_code, url=url)
    monkeypatch.setattr(
        "headersvalidator.assessor.fetch_headers", lambda *a, **kw: response
    )
    return assess(url)


# ---------------------------------------------------------------------------
# Basic integration
# ---------------------------------------------------------------------------


class TestAssess:
    def test_returns_headers_report(self, monkeypatch):
        from headersvalidator.models import HeadersReport

        report = _mock_assess(monkeypatch, SECURE_HEADERS)
        assert isinstance(report, HeadersReport)

    def test_report_url(self, monkeypatch):
        report = _mock_assess(monkeypatch, SECURE_HEADERS)
        assert report.url == "https://example.com"

    def test_report_status_code(self, monkeypatch):
        report = _mock_assess(monkeypatch, SECURE_HEADERS, status_code=200)
        assert report.status_code == 200

    def test_report_final_url_follows_redirect(self, monkeypatch):
        response = make_response(SECURE_HEADERS, url="https://www.example.com")
        monkeypatch.setattr(
            "headersvalidator.assessor.fetch_headers", lambda *a, **kw: response
        )
        report = assess("https://example.com")
        assert report.final_url == "https://www.example.com"

    def test_results_non_empty(self, monkeypatch):
        report = _mock_assess(monkeypatch, SECURE_HEADERS)
        assert len(report.results) > 0

    def test_secure_headers_produce_pass_status(self, monkeypatch):
        report = _mock_assess(monkeypatch, SECURE_HEADERS)
        # PASS or WARN are acceptable for secure headers;
        # no FAIL should appear.
        assert report.status != Status.FAIL

    def test_empty_headers_produce_fail_status(self, monkeypatch):
        report = _mock_assess(monkeypatch, EMPTY_HEADERS)
        assert report.status == Status.FAIL

    def test_score_secure_above_80(self, monkeypatch):
        report = _mock_assess(monkeypatch, SECURE_HEADERS)
        assert report.score >= 80

    def test_score_empty_below_40(self, monkeypatch):
        report = _mock_assess(monkeypatch, EMPTY_HEADERS)
        assert report.score < 40

    def test_minimal_required_no_fail(self, monkeypatch):
        report = _mock_assess(monkeypatch, MINIMAL_REQUIRED_HEADERS)
        failed = [r for r in report.results if r.status == Status.FAIL]
        assert failed == [], f"Unexpected FAILs: {[r.name for r in failed]}"

    def test_by_name_lookup_works(self, monkeypatch):
        report = _mock_assess(monkeypatch, SECURE_HEADERS)
        xcto = report.by_name("X-Content-Type-Options")
        assert xcto is not None
        assert xcto.status == Status.PASS


# ---------------------------------------------------------------------------
# URL normalisation in assess()
# ---------------------------------------------------------------------------


class TestAssessUrlNormalisation:
    def test_bare_hostname_gets_https(self, monkeypatch):
        response = make_response(SECURE_HEADERS)
        captured = {}

        def mock_fetch(url, **kwargs):
            captured["url"] = url
            return response

        monkeypatch.setattr("headersvalidator.assessor.fetch_headers", mock_fetch)
        assess("example.com")
        assert captured["url"].startswith("https://")

    def test_http_url_preserved(self, monkeypatch):
        response = make_response(SECURE_HEADERS)
        captured = {}

        def mock_fetch(url, **kwargs):
            captured["url"] = url
            return response

        monkeypatch.setattr("headersvalidator.assessor.fetch_headers", mock_fetch)
        assess("http://example.com")
        assert captured["url"] == "http://example.com"


# ---------------------------------------------------------------------------
# assess() propagates RequestException
# ---------------------------------------------------------------------------


class TestAssessNetworkError:
    def test_raises_on_connection_error_when_both_fail(self, monkeypatch):
        # Both HTTPS and HTTP fallback fail — the original HTTPS error is raised.
        monkeypatch.setattr(
            "headersvalidator.assessor.fetch_headers",
            lambda *a, **kw: (_ for _ in ()).throw(requests.ConnectionError("refused")),
        )
        with pytest.raises(requests.ConnectionError):
            assess("https://unreachable.example.com")

    def test_passes_timeout_to_fetch(self, monkeypatch):
        response = make_response(SECURE_HEADERS)
        captured = {}

        def mock_fetch(url, timeout=None, **kwargs):
            captured["timeout"] = timeout
            return response

        monkeypatch.setattr("headersvalidator.assessor.fetch_headers", mock_fetch)
        assess("https://example.com", timeout=42.0)
        assert captured["timeout"] == 42.0

    def test_passes_verify_tls_to_fetch(self, monkeypatch):
        response = make_response(SECURE_HEADERS)
        captured = {}

        def mock_fetch(url, verify_tls=True, **kwargs):
            captured["verify_tls"] = verify_tls
            return response

        monkeypatch.setattr("headersvalidator.assessor.fetch_headers", mock_fetch)
        assess("https://example.com", verify_tls=False)
        assert captured["verify_tls"] is False


# ---------------------------------------------------------------------------
# HTTP fallback when HTTPS port is closed
# ---------------------------------------------------------------------------


class TestAssessHttpFallback:
    def test_https_connection_error_retries_http(self, monkeypatch):
        """HTTPS ConnectionError (not SSLError) → automatic http:// retry succeeds."""
        response = make_response(SECURE_HEADERS, url="https://example.com")
        calls = []

        def mock_fetch(url, **kwargs):
            calls.append(url)
            if url.startswith("https://"):
                raise requests.ConnectionError("refused")
            return response

        monkeypatch.setattr("headersvalidator.assessor.fetch_headers", mock_fetch)
        report = assess("https://example.com")
        assert calls == ["https://example.com", "http://example.com"]
        assert report is not None

    def test_ssl_error_is_not_retried(self, monkeypatch):
        """SSLError must not trigger an http:// fallback — surface the TLS error."""
        calls = []

        def mock_fetch(url, **kwargs):
            calls.append(url)
            raise requests.exceptions.SSLError("cert verify failed")

        monkeypatch.setattr("headersvalidator.assessor.fetch_headers", mock_fetch)
        with pytest.raises(requests.exceptions.SSLError):
            assess("https://example.com")
        # Only the HTTPS attempt — no http:// retry.
        assert calls == ["https://example.com"]

    def test_https_connection_error_http_also_fails_raises_original(self, monkeypatch):
        """When both HTTPS and HTTP fail, the original HTTPS error is re-raised."""
        https_error = requests.ConnectionError("https refused")
        http_error = requests.ConnectionError("http refused")
        calls = []

        def mock_fetch(url, **kwargs):
            calls.append(url)
            if url.startswith("https://"):
                raise https_error
            raise http_error

        monkeypatch.setattr("headersvalidator.assessor.fetch_headers", mock_fetch)
        with pytest.raises(requests.ConnectionError) as exc_info:
            assess("https://example.com")
        assert exc_info.value is https_error
        assert calls == ["https://example.com", "http://example.com"]

    def test_plain_http_url_connection_error_not_retried(self, monkeypatch):
        """A plain http:// URL that fails must NOT be retried (no fallback loop)."""
        calls = []

        def mock_fetch(url, **kwargs):
            calls.append(url)
            raise requests.ConnectionError("refused")

        monkeypatch.setattr("headersvalidator.assessor.fetch_headers", mock_fetch)
        with pytest.raises(requests.ConnectionError):
            assess("http://example.com")
        assert calls == ["http://example.com"]


# ---------------------------------------------------------------------------
# Specific header scenarios end-to-end
# ---------------------------------------------------------------------------


class TestAssessSpecificHeaders:
    def test_deprecated_expect_ct_flagged(self, monkeypatch):
        headers = {**SECURE_HEADERS, "Expect-CT": "max-age=86400"}
        report = _mock_assess(monkeypatch, headers)
        expect_ct = report.by_name("Expect-CT")
        assert expect_ct.status == Status.DEPRECATED

    def test_server_version_disclosure_warned(self, monkeypatch):
        headers = {**SECURE_HEADERS, "Server": "Apache/2.4.54"}
        report = _mock_assess(monkeypatch, headers)
        server = report.by_name("Server")
        assert server.status == Status.WARN

    def test_weak_hsts_max_age_warns(self, monkeypatch):
        headers = {**SECURE_HEADERS, "Strict-Transport-Security": "max-age=3600"}
        report = _mock_assess(monkeypatch, headers)
        hsts = report.by_name("Strict-Transport-Security")
        assert hsts.status == Status.WARN

    def test_unsafe_referrer_policy_fails(self, monkeypatch):
        headers = {**SECURE_HEADERS, "Referrer-Policy": "unsafe-url"}
        report = _mock_assess(monkeypatch, headers)
        rp = report.by_name("Referrer-Policy")
        assert rp.status == Status.FAIL

    def test_unrecognised_referrer_policy_warns(self, monkeypatch):
        headers = {**SECURE_HEADERS, "Referrer-Policy": "foobar-unrecognised"}
        report = _mock_assess(monkeypatch, headers)
        rp = report.by_name("Referrer-Policy")
        assert rp.status == Status.WARN

    def test_unrecognised_coop_value_warns(self, monkeypatch):
        headers = {**SECURE_HEADERS, "Cross-Origin-Opener-Policy": "foobar-unrecognised"}
        report = _mock_assess(monkeypatch, headers)
        coop = report.by_name("Cross-Origin-Opener-Policy")
        assert coop.status == Status.WARN

    def test_unrecognised_coep_value_warns(self, monkeypatch):
        headers = {**SECURE_HEADERS, "Cross-Origin-Embedder-Policy": "foobar-unrecognised"}
        report = _mock_assess(monkeypatch, headers)
        coep = report.by_name("Cross-Origin-Embedder-Policy")
        assert coep.status == Status.WARN

    def test_unrecognised_corp_value_warns(self, monkeypatch):
        headers = {**SECURE_HEADERS, "Cross-Origin-Resource-Policy": "foobar-unrecognised"}
        report = _mock_assess(monkeypatch, headers)
        corp = report.by_name("Cross-Origin-Resource-Policy")
        assert corp.status == Status.WARN
