"""Tests for headersvalidator.http_utils — all network I/O is mocked."""

from __future__ import annotations

from unittest.mock import patch

import pytest
import requests

from headersvalidator.http_utils import extract_headers, fetch_headers, normalise_url
from tests.conftest import make_response

# ---------------------------------------------------------------------------
# normalise_url
# ---------------------------------------------------------------------------


class TestNormaliseUrl:
    def test_adds_https_when_no_scheme(self):
        assert normalise_url("example.com") == "https://example.com"

    def test_preserves_https(self):
        assert normalise_url("https://example.com") == "https://example.com"

    def test_preserves_http(self):
        assert normalise_url("http://example.com") == "http://example.com"

    def test_strips_whitespace(self):
        assert normalise_url("  example.com  ") == "https://example.com"

    def test_preserves_path_and_query(self):
        result = normalise_url("example.com/path?q=1")
        assert result == "https://example.com/path?q=1"


# ---------------------------------------------------------------------------
# extract_headers
# ---------------------------------------------------------------------------


class TestExtractHeaders:
    def test_lowercases_all_keys(self):
        response = make_response(
            {"X-Frame-Options": "DENY", "Content-Type": "text/html"}
        )
        headers = extract_headers(response)
        assert "x-frame-options" in headers
        assert "content-type" in headers
        assert "X-Frame-Options" not in headers

    def test_preserves_values(self):
        response = make_response({"X-Content-Type-Options": "nosniff"})
        headers = extract_headers(response)
        assert headers["x-content-type-options"] == "nosniff"

    def test_empty_headers(self):
        response = make_response({})
        assert extract_headers(response) == {}

    def test_returns_dict(self):
        response = make_response({"Server": "nginx"})
        assert isinstance(extract_headers(response), dict)


# ---------------------------------------------------------------------------
# fetch_headers — HEAD success path
# ---------------------------------------------------------------------------


class TestFetchHeaders:
    def test_issues_head_request(self):
        response = make_response(status_code=200)
        with patch("requests.head", return_value=response) as mock_head:
            fetch_headers("https://example.com", timeout=5.0)
        mock_head.assert_called_once()
        call_kwargs = mock_head.call_args
        assert call_kwargs[0][0] == "https://example.com"
        assert call_kwargs[1]["timeout"] == 5.0

    def test_returns_response_on_success(self):
        response = make_response(status_code=200)
        with patch("requests.head", return_value=response):
            result = fetch_headers("https://example.com")
        assert result is response

    def test_follows_redirects(self):
        response = make_response(status_code=200, url="https://www.example.com")
        with patch("requests.head", return_value=response):
            result = fetch_headers("https://example.com")
        assert result.url == "https://www.example.com"

    def test_passes_user_agent(self):
        response = make_response()
        with patch("requests.head", return_value=response) as mock_head:
            fetch_headers("https://example.com", user_agent="custom-agent/1.0")
        headers_sent = mock_head.call_args[1]["headers"]
        assert headers_sent["User-Agent"] == "custom-agent/1.0"

    def test_uses_default_user_agent_when_none(self):
        from headersvalidator.constants import USER_AGENT

        response = make_response()
        with patch("requests.head", return_value=response) as mock_head:
            fetch_headers("https://example.com")
        headers_sent = mock_head.call_args[1]["headers"]
        assert headers_sent["User-Agent"] == USER_AGENT

    # ------ 405 fallback to GET -------------------------------------------

    def test_falls_back_to_get_on_405(self):
        head_response = make_response(status_code=405)
        get_response = make_response(status_code=200)
        with (
            patch("requests.head", return_value=head_response),
            patch("requests.get", return_value=get_response) as mock_get,
        ):
            result = fetch_headers("https://example.com")
        mock_get.assert_called_once()
        assert result is get_response

    def test_get_fallback_uses_stream(self):
        head_response = make_response(status_code=405)
        get_response = make_response(status_code=200)
        with (
            patch("requests.head", return_value=head_response),
            patch("requests.get", return_value=get_response) as mock_get,
        ):
            fetch_headers("https://example.com")
        assert mock_get.call_args[1]["stream"] is True

    # ------ TLS verification ----------------------------------------------

    def test_verify_tls_true_by_default(self):
        response = make_response()
        with patch("requests.head", return_value=response) as mock_head:
            fetch_headers("https://example.com")
        assert mock_head.call_args[1]["verify"] is True

    def test_verify_tls_false_when_disabled(self):
        response = make_response()
        with patch("requests.head", return_value=response) as mock_head:
            fetch_headers("https://example.com", verify_tls=False)
        assert mock_head.call_args[1]["verify"] is False

    # ------ Exception propagation -----------------------------------------

    def test_raises_request_exception_on_failure(self):
        with patch("requests.head", side_effect=requests.ConnectionError("refused")):
            with pytest.raises(requests.RequestException):
                fetch_headers("https://unreachable.example.com")
