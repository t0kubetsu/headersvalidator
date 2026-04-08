"""
Shared pytest fixtures and helper factories for headersvalidator tests.

All network I/O (requests.head / requests.get) is mocked here so no test
ever touches a real server.  The mocking boundary is
headersvalidator.http_utils.fetch_headers, matching chainvalidator's
approach of mocking at the outermost I/O function.
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock

# Ensure Rich Console uses a wide terminal in all tests so table columns
# (e.g. "Recommended Value") are not truncated in non-TTY environments.
os.environ.setdefault("COLUMNS", "200")

import pytest
from requests.models import Response

# ---------------------------------------------------------------------------
# Response factory
# ---------------------------------------------------------------------------


def make_response(
    headers: dict[str, str] | None = None,
    status_code: int = 200,
    url: str = "https://example.com",
) -> Response:
    """
    Build a :class:`requests.Response` with the given headers.

    Parameters
    ----------
    headers:
        Dict of header name → value.  Names are stored as-given (requests
        is case-insensitive, but tests should use canonical casing).
    status_code:
        HTTP status code.
    url:
        Final (post-redirect) URL.
    """
    response = MagicMock(spec=Response)
    response.status_code = status_code
    response.url = url
    # Use a real case-insensitive dict to mimic requests.structures.CaseInsensitiveDict
    from requests.structures import CaseInsensitiveDict

    response.headers = CaseInsensitiveDict(headers or {})
    return response


# ---------------------------------------------------------------------------
# Secure header set — a response that should score 100
# ---------------------------------------------------------------------------

SECURE_HEADERS: dict[str, str] = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Cache-Control": "no-store, max-age=0",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Resource-Policy": "same-origin",
    "X-Permitted-Cross-Domain-Policies": "none",
    "X-XSS-Protection": "0",
}

# Minimal headers — only the OWASP-required subset
MINIMAL_REQUIRED_HEADERS: dict[str, str] = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Cache-Control": "no-store",
}

# Empty headers — everything missing
EMPTY_HEADERS: dict[str, str] = {}


# ---------------------------------------------------------------------------
# Pytest fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def secure_response() -> Response:
    """A Response with all security headers set to their recommended values."""
    return make_response(SECURE_HEADERS)


@pytest.fixture
def minimal_response() -> Response:
    """A Response with only the OWASP-required headers present."""
    return make_response(MINIMAL_REQUIRED_HEADERS)


@pytest.fixture
def empty_response() -> Response:
    """A Response with no security headers at all."""
    return make_response(EMPTY_HEADERS)


@pytest.fixture
def mock_fetch(monkeypatch):
    """
    Return a factory that patches fetch_headers to return the given response.

    Usage::

        def test_foo(mock_fetch):
            mock_fetch(make_response({"X-Frame-Options": "DENY"}))
            report = assess("https://example.com")
            assert report.by_name("X-Frame-Options").status == Status.PASS
    """

    def _patch(response: Response):
        monkeypatch.setattr(
            "headersvalidator.assessor.fetch_headers",
            lambda *args, **kwargs: response,
        )

    return _patch
