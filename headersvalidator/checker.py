"""
Core HTTP header validation logic.

HeadersChecker applies every rule from constants.HEADER_RULES to the
headers extracted from an HTTP response and returns a list of HeaderResult
objects — one per evaluated header.

Design mirrors chainvalidator's checker.py: the checker is a stateful class
that holds the raw header dict and produces structured results.  All I/O has
already been done before this class is instantiated.
"""

from __future__ import annotations

import logging
from typing import Optional

from headersvalidator.constants import HEADER_RULES, RULES_BY_NAME
from headersvalidator.models import HeaderResult, Status

logger = logging.getLogger("headersvalidator")


class HeadersChecker:
    """
    Validate HTTP response headers against RFC 9110 / RFC 9111 / OWASP rules.

    :param headers: Mapping of ``{lowercase-field-name: value}`` extracted
        from the HTTP response.  Use
        :func:`headersvalidator.http_utils.extract_headers` to build this.
    """

    def __init__(self, headers: dict[str, str]) -> None:
        self._headers = headers

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_all(self) -> list[HeaderResult]:
        """
        Run every rule in ``HEADER_RULES`` and return one result per header.

        Headers with a known rule are evaluated; unknown headers are silently
        ignored (the IANA registry is open and can grow).

        :returns: One :class:`~headersvalidator.models.HeaderResult` per
            evaluated header, in the same order as ``HEADER_RULES``.
        :rtype: list[HeaderResult]
        """
        results: list[HeaderResult] = []
        for rule in HEADER_RULES:
            result = self._check_one(rule)
            results.append(result)
            _log_result(result)
        return results

    def check_header(self, name: str) -> Optional[HeaderResult]:
        """
        Validate a single header by canonical name (case-insensitive).

        :param name: HTTP field name, e.g. ``"Strict-Transport-Security"``.
        :returns: Validation result, or ``None`` if no rule is registered
            for *name*.
        :rtype: HeaderResult or None
        """
        rule = RULES_BY_NAME.get(name.lower())
        if rule is None:
            logger.warning("No rule defined for header %r", name)
            return None
        result = self._check_one(rule)
        _log_result(result)
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_one(self, rule: dict) -> HeaderResult:
        """
        Apply a single rule entry from ``HEADER_RULES`` to ``self._headers``.

        :param rule: A rule dict as defined in
            :data:`headersvalidator.constants.HEADER_RULES`.
        :returns: Populated result object with status, reason, and metadata.
        :rtype: HeaderResult
        """
        name: str = rule["name"]
        key = name.lower()
        value: Optional[str] = self._headers.get(key)
        present = value is not None
        required: bool = rule["required"]
        check_fn = rule["check"]
        recommended: str = rule["recommended"]
        source: str = rule["source"]
        iana_status: str = rule["iana_status"]

        # ------ Absent header ----------------------------------------
        if not present:
            if required:
                logger.warning("FAIL  [absent] %s", name)
                return HeaderResult(
                    name=name,
                    status=Status.FAIL,
                    present=False,
                    value=None,
                    recommended=recommended,
                    source=source,
                    reason=f"Header is absent. OWASP requires it. Recommended: {recommended}",
                    iana_status=iana_status,
                )
            else:
                # Optional header — note absence without failing
                logger.debug("INFO  [absent/optional] %s", name)
                return HeaderResult(
                    name=name,
                    status=Status.INFO,
                    present=False,
                    value=None,
                    recommended=recommended,
                    source=source,
                    reason="Header is absent (optional). Consider adding it.",
                    iana_status=iana_status,
                )

        # ------ Present header — run the value check -----------------
        status, reason = check_fn(value)
        logger.debug(
            "%-5s [present] %-45s value=%r",
            status.value,
            name,
            value[:80] if value else "",
        )
        return HeaderResult(
            name=name,
            status=status,
            present=True,
            value=value,
            recommended=recommended,
            source=source,
            reason=reason,
            iana_status=iana_status,
        )


# ---------------------------------------------------------------------------
# Module-level logging helper
# ---------------------------------------------------------------------------


def _log_result(result: HeaderResult) -> None:
    """
    Emit a structured log line for *result* at the appropriate level.

    :param result: The :class:`~headersvalidator.models.HeaderResult` to log.
    """
    msg = "%-12s %-45s %s" % (result.status.value, result.name, result.reason)
    if result.status == Status.FAIL:
        logger.error(msg)
    elif result.status in (Status.WARN, Status.DEPRECATED):
        logger.warning(msg)
    elif result.status == Status.PASS:
        logger.info(msg)
    else:
        logger.debug(msg)
