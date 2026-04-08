"""
Low-level HTTP utilities for headersvalidator.

Mirrors the dns_utils.py pattern in chainvalidator: pure I/O helpers that
can be easily mocked at test boundaries.
"""

from __future__ import annotations

import logging
from typing import Optional

import requests
from requests import Response
from requests.exceptions import RequestException

logger = logging.getLogger("headersvalidator")

# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def fetch_headers(
    url: str,
    timeout: float = 10.0,
    user_agent: Optional[str] = None,
    verify_tls: bool = True,
) -> Response:
    """
    Issue an HTTP HEAD request to *url* and return the response.

    Falls back to GET if the server returns 405 (Method Not Allowed) for
    HEAD.  RFC 9110 §9.3.2 requires HEAD support, but many servers violate
    this in practice.

    :param url: Target URL including scheme (``http://`` or ``https://``).
    :param timeout: Per-request socket timeout in seconds (default ``10``).
    :param user_agent: Custom ``User-Agent`` header value.  Defaults to the
        headersvalidator UA string from
        :data:`headersvalidator.constants.USER_AGENT`.
    :param verify_tls: Whether to verify TLS certificates.  Set ``False``
        only for internal or self-signed hosts.
    :returns: The full HTTP response (headers accessible via
        ``response.headers``).
    :rtype: requests.Response
    :raises requests.RequestException: On any network or protocol error;
        callers are responsible for handling this.
    """
    from headersvalidator.constants import USER_AGENT

    ua = user_agent or USER_AGENT
    headers = {"User-Agent": ua}

    logger.debug("HEAD %s (timeout=%.1fs)", url, timeout)
    try:
        response = requests.head(
            url,
            headers=headers,
            timeout=timeout,
            allow_redirects=True,
            verify=verify_tls,
        )
        if response.status_code == 405:
            logger.debug("HEAD returned 405; retrying with GET %s", url)
            response = requests.get(
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=True,
                verify=verify_tls,
                stream=True,  # Don't download the body
            )
        logger.info(
            "Fetched %s → %s (final URL: %s)",
            url,
            response.status_code,
            response.url,
        )
        return response
    except RequestException as exc:
        logger.error("Failed to fetch %s: %s", url, exc)
        raise


def normalise_url(url: str) -> str:
    """
    Ensure *url* has an explicit scheme.

    headersvalidator follows RFC 9110 §4.1: if no scheme is provided, https://
    is assumed (preference for secure transport, HSTS-style).

    :param url: Raw URL string, with or without a scheme.
    :returns: URL guaranteed to start with ``http://`` or ``https://``.
    :rtype: str
    """
    url = url.strip()
    if "://" not in url:
        url = "https://" + url
        logger.debug("No scheme provided; assumed https:// → %s", url)
    return url


def extract_headers(response: Response) -> dict[str, str]:
    """
    Return a normalised {lowercase-name: value} dict of all response headers.

    RFC 9110 §5.1 states field names are case-insensitive; we lower-case them
    here so checkers can do simple dict lookups.

    :param response: HTTP response whose headers should be extracted.
    :returns: Mapping of ``{lowercase-field-name: value}`` for every header
        present in the response.
    :rtype: dict[str, str]
    """
    return {k.lower(): v for k, v in response.headers.items()}
