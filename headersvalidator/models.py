"""
Data models for headersvalidator.

Status, HeaderResult, and HeadersReport are the public-facing result types
returned by assess() and consumed by reporter / library users.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


class Status(str, Enum):
    """Overall or per-header validation outcome."""

    PASS = "PASS"  # Header present and value meets all criteria
    WARN = "WARN"  # Header present but value is sub-optimal / advisory
    FAIL = "FAIL"  # Header absent or value violates a hard rule
    INFO = "INFO"  # Informational — not graded (e.g. Server disclosure)
    DEPRECATED = "DEPRECATED"  # Header is obsolete and should be removed


# ---------------------------------------------------------------------------
# Per-header result
# ---------------------------------------------------------------------------


@dataclass
class HeaderResult:
    """Validation result for a single HTTP response header."""

    name: str
    """Canonical header field name (case-insensitive comparison used internally)."""

    status: Status
    """Pass / Warn / Fail / Info / Deprecated."""

    present: bool
    """Whether the header was present in the response."""

    value: Optional[str]
    """Raw header value as received, or None if absent."""

    recommended: Optional[str]
    """Recommended value or directive string from the reference sources."""

    source: str
    """Reference that drives this rule (RFC 9110, RFC 9111, OWASP, IANA)."""

    reason: str
    """Human-readable explanation of the verdict."""

    iana_status: str = "permanent"
    """Registration status in the IANA HTTP Field Name Registry."""

    # ------------------------------------------------------------------
    @property
    def is_pass(self) -> bool:
        return self.status == Status.PASS

    @property
    def is_fail(self) -> bool:
        return self.status == Status.FAIL

    @property
    def is_warn(self) -> bool:
        return self.status == Status.WARN


# ---------------------------------------------------------------------------
# Aggregate report
# ---------------------------------------------------------------------------


@dataclass
class HeadersReport:
    """Complete validation report for a single HTTP endpoint."""

    url: str
    """The URL that was checked."""

    status_code: int
    """HTTP status code of the response."""

    final_url: str
    """Effective URL after any redirects."""

    results: list[HeaderResult] = field(default_factory=list)
    """One HeaderResult per evaluated header."""

    # ------------------------------------------------------------------
    # Aggregate convenience properties
    # ------------------------------------------------------------------

    @property
    def status(self) -> Status:
        """Overall status: FAIL if any header fails, WARN if any warns, else PASS."""
        statuses = {r.status for r in self.results}
        if Status.FAIL in statuses:
            return Status.FAIL
        if Status.WARN in statuses:
            return Status.WARN
        return Status.PASS

    @property
    def is_pass(self) -> bool:
        return self.status == Status.PASS

    @property
    def passed(self) -> list[HeaderResult]:
        return [r for r in self.results if r.status == Status.PASS]

    @property
    def warned(self) -> list[HeaderResult]:
        return [r for r in self.results if r.status == Status.WARN]

    @property
    def failed(self) -> list[HeaderResult]:
        return [r for r in self.results if r.status == Status.FAIL]

    @property
    def deprecated(self) -> list[HeaderResult]:
        return [r for r in self.results if r.status == Status.DEPRECATED]

    @property
    def score(self) -> int:
        """
        Compute a 0–100 security score from the graded results.

        Each PASS = 2 pts, WARN = 1 pt, FAIL/DEPRECATED = 0 pts.
        Only graded results (not INFO) are counted.

        :returns: Integer score in the range 0–100.
        :rtype: int
        """
        graded = [r for r in self.results if r.status != Status.INFO]
        if not graded:
            return 0
        earned = sum(
            2 if r.status == Status.PASS else (1 if r.status == Status.WARN else 0)
            for r in graded
        )
        maximum = len(graded) * 2
        return round(earned / maximum * 100)

    def by_name(self, name: str) -> Optional[HeaderResult]:
        """
        Return the result for the given header name (case-insensitive).

        :param name: HTTP field name, e.g. ``"Strict-Transport-Security"``.
        :returns: The matching :class:`HeaderResult`, or ``None`` if not found.
        :rtype: HeaderResult or None
        """
        name_lower = name.lower()
        for result in self.results:
            if result.name.lower() == name_lower:
                return result
        return None
