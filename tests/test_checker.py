"""Tests for headersvalidator.checker — core validation logic."""

from __future__ import annotations

import pytest

from headersvalidator.checker import HeadersChecker
from headersvalidator.models import Status
from tests.conftest import EMPTY_HEADERS, SECURE_HEADERS

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_checker(headers: dict[str, str]) -> HeadersChecker:
    """Build a HeadersChecker from a plain {name: value} dict (mimics extract_headers)."""
    return HeadersChecker({k.lower(): v for k, v in headers.items()})


# ---------------------------------------------------------------------------
# check_all
# ---------------------------------------------------------------------------


class TestCheckAll:
    def test_returns_list_of_results(self):
        checker = make_checker(SECURE_HEADERS)
        results = checker.check_all()
        assert isinstance(results, list)
        assert len(results) > 0

    def test_secure_headers_produce_no_fails(self):
        checker = make_checker(SECURE_HEADERS)
        results = checker.check_all()
        failed = [r for r in results if r.status == Status.FAIL]
        assert failed == [], f"Unexpected FAILs: {[r.name for r in failed]}"

    def test_empty_headers_fail_required(self):
        checker = make_checker(EMPTY_HEADERS)
        results = checker.check_all()
        failed = [r for r in results if r.status == Status.FAIL]
        assert len(failed) > 0

    def test_result_names_match_rules(self):
        from headersvalidator.constants import HEADER_RULES

        checker = make_checker(SECURE_HEADERS)
        results = checker.check_all()
        result_names = {r.name for r in results}
        rule_names = {rule["name"] for rule in HEADER_RULES}
        assert result_names == rule_names

    def test_results_have_present_flag(self):
        checker = make_checker({"x-frame-options": "DENY"})
        results = checker.check_all()
        xfo = next(r for r in results if r.name == "X-Frame-Options")
        assert xfo.present is True
        hsts = next(r for r in results if r.name == "Strict-Transport-Security")
        assert hsts.present is False


# ---------------------------------------------------------------------------
# check_header — individual header checks
# ---------------------------------------------------------------------------


class TestCheckHeader:
    def test_returns_none_for_unknown_header(self):
        checker = make_checker({})
        assert checker.check_header("X-Unknown-Header") is None

    def test_case_insensitive_lookup(self):
        checker = make_checker({"x-frame-options": "DENY"})
        result = checker.check_header("X-Frame-Options")
        assert result is not None
        assert result.status == Status.PASS

    def test_absent_required_header_is_fail(self):
        checker = make_checker({})
        result = checker.check_header("Strict-Transport-Security")
        assert result.status == Status.FAIL
        assert result.present is False

    def test_absent_optional_header_is_info(self):
        checker = make_checker({})
        result = checker.check_header("Cross-Origin-Opener-Policy")
        assert result.status == Status.INFO
        assert result.present is False


# ---------------------------------------------------------------------------
# Strict-Transport-Security
# ---------------------------------------------------------------------------


class TestHSTS:
    def test_pass_full(self):
        c = make_checker(
            {
                "strict-transport-security": "max-age=63072000; includeSubDomains; preload"
            }
        )
        r = c.check_header("Strict-Transport-Security")
        assert r.status == Status.PASS

    def test_pass_min_max_age(self):
        c = make_checker(
            {"strict-transport-security": "max-age=31536000; includeSubDomains"}
        )
        r = c.check_header("Strict-Transport-Security")
        assert r.status == Status.PASS

    def test_warn_no_include_subdomains(self):
        c = make_checker({"strict-transport-security": "max-age=63072000"})
        r = c.check_header("Strict-Transport-Security")
        assert r.status == Status.WARN

    def test_warn_low_max_age(self):
        c = make_checker(
            {"strict-transport-security": "max-age=3600; includeSubDomains"}
        )
        r = c.check_header("Strict-Transport-Security")
        assert r.status == Status.WARN

    def test_fail_missing_max_age(self):
        c = make_checker({"strict-transport-security": "includeSubDomains"})
        r = c.check_header("Strict-Transport-Security")
        assert r.status == Status.FAIL

    def test_fail_absent(self):
        c = make_checker({})
        r = c.check_header("Strict-Transport-Security")
        assert r.status == Status.FAIL


# ---------------------------------------------------------------------------
# Content-Security-Policy
# ---------------------------------------------------------------------------


class TestCSP:
    def test_pass_safe_policy(self):
        c = make_checker(
            {"content-security-policy": "default-src 'self'; object-src 'none'"}
        )
        r = c.check_header("Content-Security-Policy")
        assert r.status == Status.PASS

    def test_warn_unsafe_inline(self):
        c = make_checker(
            {
                "content-security-policy": "default-src 'self'; script-src 'unsafe-inline'"
            }
        )
        r = c.check_header("Content-Security-Policy")
        assert r.status == Status.WARN
        assert "unsafe-inline" in r.reason

    def test_warn_unsafe_eval(self):
        c = make_checker(
            {"content-security-policy": "default-src 'self'; script-src 'unsafe-eval'"}
        )
        r = c.check_header("Content-Security-Policy")
        assert r.status == Status.WARN

    def test_warn_no_default_or_script_src(self):
        c = make_checker({"content-security-policy": "img-src 'self'"})
        r = c.check_header("Content-Security-Policy")
        assert r.status == Status.WARN

    def test_fail_absent(self):
        c = make_checker({})
        r = c.check_header("Content-Security-Policy")
        assert r.status == Status.FAIL


# ---------------------------------------------------------------------------
# X-Frame-Options
# ---------------------------------------------------------------------------


class TestXFrameOptions:
    def test_pass_deny(self):
        c = make_checker({"x-frame-options": "DENY"})
        assert c.check_header("X-Frame-Options").status == Status.PASS

    def test_pass_sameorigin(self):
        c = make_checker({"x-frame-options": "SAMEORIGIN"})
        assert c.check_header("X-Frame-Options").status == Status.PASS

    def test_warn_allow_from(self):
        c = make_checker({"x-frame-options": "ALLOW-FROM https://trusted.com"})
        r = c.check_header("X-Frame-Options")
        assert r.status == Status.WARN

    def test_fail_invalid_value(self):
        c = make_checker({"x-frame-options": "ALLOWALL"})
        assert c.check_header("X-Frame-Options").status == Status.FAIL

    def test_fail_absent(self):
        c = make_checker({})
        assert c.check_header("X-Frame-Options").status == Status.FAIL


# ---------------------------------------------------------------------------
# X-Content-Type-Options
# ---------------------------------------------------------------------------


class TestXContentTypeOptions:
    def test_pass_nosniff(self):
        c = make_checker({"x-content-type-options": "nosniff"})
        assert c.check_header("X-Content-Type-Options").status == Status.PASS

    def test_pass_nosniff_case_insensitive_value(self):
        c = make_checker({"x-content-type-options": "  nosniff  "})
        assert c.check_header("X-Content-Type-Options").status == Status.PASS

    def test_fail_wrong_value(self):
        c = make_checker({"x-content-type-options": "sniff"})
        assert c.check_header("X-Content-Type-Options").status == Status.FAIL

    def test_fail_absent(self):
        c = make_checker({})
        assert c.check_header("X-Content-Type-Options").status == Status.FAIL


# ---------------------------------------------------------------------------
# Referrer-Policy
# ---------------------------------------------------------------------------


class TestReferrerPolicy:
    @pytest.mark.parametrize(
        "value",
        [
            "no-referrer",
            "strict-origin",
            "strict-origin-when-cross-origin",
            "same-origin",
        ],
    )
    def test_pass_safe_values(self, value):
        c = make_checker({"referrer-policy": value})
        assert c.check_header("Referrer-Policy").status == Status.PASS

    def test_fail_unsafe_url(self):
        c = make_checker({"referrer-policy": "unsafe-url"})
        assert c.check_header("Referrer-Policy").status == Status.FAIL

    def test_warn_no_referrer_when_downgrade(self):
        c = make_checker({"referrer-policy": "no-referrer-when-downgrade"})
        assert c.check_header("Referrer-Policy").status == Status.WARN

    def test_fail_absent(self):
        c = make_checker({})
        assert c.check_header("Referrer-Policy").status == Status.FAIL


# ---------------------------------------------------------------------------
# Cache-Control
# ---------------------------------------------------------------------------


class TestCacheControl:
    def test_pass_no_store(self):
        c = make_checker({"cache-control": "no-store, max-age=0"})
        assert c.check_header("Cache-Control").status == Status.PASS

    def test_pass_no_cache(self):
        c = make_checker({"cache-control": "no-cache, no-store"})
        assert c.check_header("Cache-Control").status == Status.PASS

    def test_warn_public_without_no_store(self):
        c = make_checker({"cache-control": "public, max-age=3600"})
        r = c.check_header("Cache-Control")
        assert r.status == Status.WARN

    def test_warn_no_explicit_directives(self):
        c = make_checker({"cache-control": ""})
        r = c.check_header("Cache-Control")
        # Empty value has no protective directive
        assert r.status in (Status.WARN, Status.FAIL)

    def test_info_absent_optional(self):
        c = make_checker({})
        assert c.check_header("Cache-Control").status == Status.INFO


# ---------------------------------------------------------------------------
# Permissions-Policy (required header)
# ---------------------------------------------------------------------------


class TestPermissionsPolicy:
    def test_pass_restricts_sensitive(self):
        c = make_checker(
            {"permissions-policy": "geolocation=(), camera=(), microphone=()"}
        )
        assert c.check_header("Permissions-Policy").status == Status.PASS

    def test_warn_missing_geolocation(self):
        c = make_checker({"permissions-policy": "camera=(), microphone=()"})
        r = c.check_header("Permissions-Policy")
        assert r.status == Status.WARN
        assert "geolocation" in r.reason

    def test_fail_absent_required(self):
        c = make_checker({})
        r = c.check_header("Permissions-Policy")
        assert r.status == Status.FAIL


# ---------------------------------------------------------------------------
# Cross-origin headers (COOP / COEP / CORP)
# ---------------------------------------------------------------------------


class TestCOOP:
    def test_pass_same_origin(self):
        c = make_checker({"cross-origin-opener-policy": "same-origin"})
        assert c.check_header("Cross-Origin-Opener-Policy").status == Status.PASS

    def test_warn_allow_popups(self):
        c = make_checker({"cross-origin-opener-policy": "same-origin-allow-popups"})
        assert c.check_header("Cross-Origin-Opener-Policy").status == Status.WARN

    def test_fail_unsafe_none(self):
        c = make_checker({"cross-origin-opener-policy": "unsafe-none"})
        assert c.check_header("Cross-Origin-Opener-Policy").status == Status.FAIL


class TestCOEP:
    def test_pass_require_corp(self):
        c = make_checker({"cross-origin-embedder-policy": "require-corp"})
        assert c.check_header("Cross-Origin-Embedder-Policy").status == Status.PASS

    def test_pass_credentialless(self):
        c = make_checker({"cross-origin-embedder-policy": "credentialless"})
        assert c.check_header("Cross-Origin-Embedder-Policy").status == Status.PASS

    def test_fail_unsafe_none(self):
        c = make_checker({"cross-origin-embedder-policy": "unsafe-none"})
        assert c.check_header("Cross-Origin-Embedder-Policy").status == Status.FAIL


class TestCORP:
    def test_pass_same_origin(self):
        c = make_checker({"cross-origin-resource-policy": "same-origin"})
        assert c.check_header("Cross-Origin-Resource-Policy").status == Status.PASS

    def test_pass_same_site(self):
        c = make_checker({"cross-origin-resource-policy": "same-site"})
        assert c.check_header("Cross-Origin-Resource-Policy").status == Status.PASS

    def test_warn_cross_origin(self):
        c = make_checker({"cross-origin-resource-policy": "cross-origin"})
        assert c.check_header("Cross-Origin-Resource-Policy").status == Status.WARN


# ---------------------------------------------------------------------------
# Server header (information disclosure)
# ---------------------------------------------------------------------------


class TestServerHeader:
    def test_info_non_informative(self):
        c = make_checker({"server": "webserver"})
        assert c.check_header("Server").status == Status.INFO

    def test_warn_reveals_software_name(self):
        c = make_checker({"server": "nginx"})
        assert c.check_header("Server").status == Status.WARN

    def test_warn_reveals_version(self):
        c = make_checker({"server": "Apache/2.4.51"})
        assert c.check_header("Server").status == Status.WARN

    def test_info_absent_optional(self):
        c = make_checker({})
        r = c.check_header("Server")
        assert r.status == Status.INFO


# ---------------------------------------------------------------------------
# Deprecated headers
# ---------------------------------------------------------------------------


class TestXXSSProtection:
    def test_pass_zero(self):
        c = make_checker({"x-xss-protection": "0"})
        assert c.check_header("X-XSS-Protection").status == Status.PASS

    def test_warn_enabled(self):
        c = make_checker({"x-xss-protection": "1; mode=block"})
        assert c.check_header("X-XSS-Protection").status == Status.WARN


class TestExpectCT:
    def test_deprecated_when_present(self):
        c = make_checker({"expect-ct": "max-age=604800"})
        r = c.check_header("Expect-CT")
        assert r.status == Status.DEPRECATED

    def test_info_absent_optional(self):
        c = make_checker({})
        r = c.check_header("Expect-CT")
        assert r.status == Status.INFO


# ---------------------------------------------------------------------------
# X-Permitted-Cross-Domain-Policies
# ---------------------------------------------------------------------------


class TestXPermittedCrossDomainPolicies:
    def test_pass_none(self):
        c = make_checker({"x-permitted-cross-domain-policies": "none"})
        assert c.check_header("X-Permitted-Cross-Domain-Policies").status == Status.PASS

    def test_pass_master_only(self):
        c = make_checker({"x-permitted-cross-domain-policies": "master-only"})
        assert c.check_header("X-Permitted-Cross-Domain-Policies").status == Status.PASS

    def test_warn_all(self):
        c = make_checker({"x-permitted-cross-domain-policies": "all"})
        assert c.check_header("X-Permitted-Cross-Domain-Policies").status == Status.WARN
