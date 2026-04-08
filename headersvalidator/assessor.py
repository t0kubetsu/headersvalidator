"""
Public library API for headersvalidator.

Usage
-----
    from headersvalidator.assessor import assess
    from headersvalidator.models import Status

    report = assess("https://example.com")

    print(report.status)     # Status.PASS | WARN | FAIL
    print(report.score)      # 0-100 security score
    for result in report.results:
        print(result.name, result.status, result.reason)

This module is the *only* public entry point that performs network I/O.
Everything else (checker, reporter, models) is pure computation.
"""

from __future__ import annotations

import logging

from headersvalidator.checker import HeadersChecker
from headersvalidator.constants import HTTP_TIMEOUT
from headersvalidator.http_utils import extract_headers, fetch_headers, normalise_url
from headersvalidator.models import HeadersReport

logger = logging.getLogger("headersvalidator")


def assess(
    url: str,
    timeout: float = HTTP_TIMEOUT,
    verify_tls: bool = True,
    user_agent: str | None = None,
) -> HeadersReport:
    """
    Fetch *url* and validate its HTTP response headers.

    This is the single public entry point that performs network I/O.
    A bare hostname (e.g. ``example.com``) is accepted; ``https://`` is
    prepended automatically (RFC 9110 §4.1 preference for secure transport).

    :param url: Target URL.  Scheme is optional; ``https://`` is assumed.
    :param timeout: Per-request socket timeout in seconds.
    :param verify_tls: If ``False``, TLS certificate errors are ignored
        (useful for internal or self-signed hosts).
    :param user_agent: Override the default headersvalidator User-Agent string.
    :returns: Structured report with per-header results and aggregate
        status/score.
    :rtype: HeadersReport
    :raises requests.RequestException: If the HTTP request fails entirely
        (unreachable host, DNS failure, TLS error, etc.).
    """
    url = normalise_url(url)
    logger.info("Starting header validation for %s", url)

    # ---- Network I/O (single point — easy to mock in tests) ----------
    response = fetch_headers(
        url, timeout=timeout, verify_tls=verify_tls, user_agent=user_agent
    )

    # ---- Extract normalised headers ----------------------------------
    headers = extract_headers(response)
    logger.debug("Received %d headers from %s", len(headers), response.url)

    # ---- Run all rules -----------------------------------------------
    checker = HeadersChecker(headers)
    results = checker.check_all()

    # ---- Build and return the report ---------------------------------
    report = HeadersReport(
        url=url,
        status_code=response.status_code,
        final_url=response.url,
        results=results,
    )

    logger.info(
        "Validation complete for %s — status=%s score=%d/100",
        report.final_url,
        report.status.value,
        report.score,
    )
    return report
