"""Verdict panel: extract and display prioritised security actions.

Analyses a :class:`~headersvalidator.models.HeadersReport` and produces a
ranked list of :class:`VerdictAction` items highlighting the most important
improvements an operator should make.  Severity is context-aware:

* Tier-1 required header absent (STS, CSP, XFO, XCTO) → ``CRITICAL``.
* Tier-2 required header absent (Referrer-Policy, Permissions-Policy) → ``HIGH``.
* Required header present, bad value      → ``HIGH``.
* Required header sub-optimal value       → ``MEDIUM``.
* Optional header present, bad value      → ``MEDIUM``.
* Optional header sub-optimal value       → suppressed (results table only).
* Deprecated header present               → ``MEDIUM``.

The tier distinction reflects actual exploit impact: Tier-1 headers directly
enable well-known attacks (SSL stripping, XSS, clickjacking, MIME sniffing)
when absent; Tier-2 headers are privacy hygiene and defence-in-depth measures.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from headersvalidator.constants import HEADER_RULES
from headersvalidator.models import HeadersReport, Status

# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


class VerdictSeverity(str, Enum):
    """Severity level for a verdict action item.

    Ordered from most to least urgent: ``CRITICAL`` → ``HIGH`` → ``MEDIUM``.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"


@dataclass
class VerdictAction:
    """A single prioritised action derived from a :class:`~headersvalidator.models.HeaderResult`.

    :param text: Human-readable action description shown in the verdict panel.
    :param severity: Importance level of this action.
    :param header_name: Name of the originating header.
    """

    text: str
    severity: VerdictSeverity
    header_name: str


@dataclass
class Grade:
    """Letter grade summarising the overall HTTP security posture.

    Computed by :func:`calculate_grade` from the list of
    :class:`VerdictAction` items produced by :func:`extract_verdict_actions`.
    The grading system uses a **penalty-point** model: zero points means a
    perfect configuration (A+) and points accumulate as issues are found.

    :param letter: Letter grade (``"A+"`` through ``"F"``).
    :param penalty: Total penalty points (0 = perfect).
    :param rationale: Human-readable explanation of the grade.
    """

    letter: str
    penalty: int
    rationale: str


# ---------------------------------------------------------------------------
# Internal tables
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: dict[VerdictSeverity, int] = {
    VerdictSeverity.CRITICAL: 0,
    VerdictSeverity.HIGH: 1,
    VerdictSeverity.MEDIUM: 2,
}

_PENALTY: dict[VerdictSeverity, int] = {
    VerdictSeverity.CRITICAL: 10,
    VerdictSeverity.HIGH: 5,
    VerdictSeverity.MEDIUM: 2,
}

# Penalty thresholds for letter grades (inclusive upper bound; 0 → A+).
_GRADE_THRESHOLDS: list[tuple[int, str]] = [
    (0, "A+"),
    (10, "A"),
    (20, "B"),
    (30, "C"),
    (40, "D"),
]

# Headers whose ``required`` flag is True in HEADER_RULES.
_REQUIRED_HEADERS: frozenset[str] = frozenset(
    rule["name"] for rule in HEADER_RULES if rule["required"]
)

# Per-header severity when absent (required headers only).
# Tier-1 headers enable active exploits when absent → CRITICAL.
# Tier-2 headers are privacy/defence-in-depth hygiene → HIGH.
_ABSENT_SEVERITY: dict[str, VerdictSeverity] = {
    rule["name"]: VerdictSeverity(rule["absent_severity"])
    for rule in HEADER_RULES
    if rule.get("absent_severity")
}

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def calculate_grade(actions: list[VerdictAction]) -> Grade:
    """Calculate the overall security grade from a list of verdict actions.

    Uses a **penalty-point** model: start at 0 (perfect) and accumulate
    points for each outstanding issue.  Lower is better.

    Penalty weights:

    * ``CRITICAL`` → 10 points
    * ``HIGH``     →  5 points
    * ``MEDIUM``   →  2 points

    Grade thresholds:

    +----------------+-------+
    | Penalty points | Grade |
    +================+=======+
    | 0              | A+    |
    +----------------+-------+
    | 1–10           | A     |
    +----------------+-------+
    | 11–20          | B     |
    +----------------+-------+
    | 21–30          | C     |
    +----------------+-------+
    | 31–40          | D     |
    +----------------+-------+
    | > 40           | F     |
    +----------------+-------+

    :param actions: Deduplicated, severity-sorted list from
        :func:`extract_verdict_actions`.
    :returns: Grade with letter, penalty points, and rationale.
    :rtype: Grade
    """
    penalty = sum(_PENALTY[a.severity] for a in actions)

    letter = "F"
    for threshold, grade_letter in _GRADE_THRESHOLDS:
        if penalty <= threshold:
            letter = grade_letter
            break

    if penalty == 0:
        rationale = "No issues found — all evaluated headers pass."
    else:
        n_critical = sum(1 for a in actions if a.severity is VerdictSeverity.CRITICAL)
        n_high = sum(1 for a in actions if a.severity is VerdictSeverity.HIGH)
        n_medium = sum(1 for a in actions if a.severity is VerdictSeverity.MEDIUM)
        parts: list[str] = []
        if n_critical:
            parts.append(f"{n_critical} critical")
        if n_high:
            parts.append(f"{n_high} high")
        if n_medium:
            parts.append(f"{n_medium} medium")
        rationale = f"{', '.join(parts)} issue(s) found ({penalty} penalty point(s))."

    return Grade(letter=letter, penalty=penalty, rationale=rationale)


def extract_verdict_actions(report: HeadersReport) -> list[VerdictAction]:
    """Extract prioritised action items from *report*.

    Results with ``Status.PASS`` or ``Status.INFO`` are silently skipped.
    For every other result the severity is determined by the combination of
    the header's ``required`` flag, its ``absent_severity`` tier, and the status:

    * Tier-1 required + ``FAIL`` (absent)  → ``CRITICAL``
    * Tier-2 required + ``FAIL`` (absent)  → ``HIGH``
    * Required + ``FAIL`` (present)        → ``HIGH``
    * Required + ``WARN``                  → ``MEDIUM``
    * Optional + ``FAIL``                  → ``MEDIUM``
    * Optional + ``WARN``                  → suppressed (results table only)
    * ``DEPRECATED``                       → ``MEDIUM``

    The result is sorted from most to least urgent.

    :param report: Validation report to analyse.
    :returns: Severity-sorted list of action items; empty when everything passes.
    :rtype: list[VerdictAction]
    """
    actions: list[VerdictAction] = []

    for result in report.results:
        if result.status in (Status.PASS, Status.INFO):
            continue

        if result.status == Status.DEPRECATED:
            actions.append(
                VerdictAction(
                    text=f"Remove {result.name}: deprecated header should not be sent",
                    severity=VerdictSeverity.MEDIUM,
                    header_name=result.name,
                )
            )
            continue

        required = result.name in _REQUIRED_HEADERS

        if result.status == Status.FAIL:
            if not result.present:
                sev = _ABSENT_SEVERITY.get(result.name, VerdictSeverity.HIGH) if required else VerdictSeverity.HIGH
                verb = "Add"
            else:
                sev = VerdictSeverity.HIGH if required else VerdictSeverity.MEDIUM
                verb = "Fix"
        else:  # WARN
            if not required:
                # Optional headers with sub-optimal values are informational;
                # they appear in the results table but not in the verdict panel.
                continue
            sev = VerdictSeverity.MEDIUM
            verb = "Review"

        actions.append(
            VerdictAction(
                text=f"{verb} {result.name}: {result.reason}",
                severity=sev,
                header_name=result.name,
            )
        )

    actions.sort(key=lambda a: _SEVERITY_ORDER[a.severity])
    return actions
