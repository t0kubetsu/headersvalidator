"""Rich terminal output for headersvalidator.

Pure display functions that receive a :class:`~headersvalidator.models.HeadersReport`
and render it to the terminal using Rich.  The CLI calls these; the library
never touches them.
"""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from headersvalidator.models import HeadersReport, Status
from headersvalidator.verdict import (
    Grade,
    VerdictAction,
    VerdictSeverity,
    calculate_grade,
    extract_verdict_actions,
)

# One shared console; callers can pass their own for testing
_console = Console(highlight=False)

# Status → (colour, symbol)
_STATUS_STYLE: dict[Status, tuple[str, str]] = {
    Status.PASS: ("green", "✔"),
    Status.WARN: ("yellow", "⚠"),
    Status.FAIL: ("red", "✘"),
    Status.INFO: ("cyan", "ℹ"),
    Status.DEPRECATED: ("magenta", "⊘"),
}

# Severity → Rich colour string
_SEVERITY_STYLE: dict[VerdictSeverity, str] = {
    VerdictSeverity.CRITICAL: "bold red",
    VerdictSeverity.HIGH: "bold yellow",
    VerdictSeverity.MEDIUM: "bold cyan",
    VerdictSeverity.INFO: "dim",
}

# Grade letter → Rich colour string
_GRADE_STYLE: dict[str, str] = {
    "A+": "bold bright_green",
    "A": "bold green",
    "B": "bold yellow",
    "C": "bold yellow",
    "D": "bold red",
    "F": "bold bright_red",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def print_full_report(report: HeadersReport, console: Console | None = None) -> None:
    """Render a complete, colour-coded terminal report for *report*.

    Prints a rule header, per-header results table, security verdict panel,
    and a closing rule in order.

    :param report: Validation report returned by :func:`headersvalidator.assessor.assess`.
    :param console: Optional Rich console to write to; defaults to the module-level console.
    """
    con = console or _console
    con.rule(f"[bold cyan]HTTP Headers Report — {report.url}[/bold cyan]")
    if report.final_url != report.url:
        con.print(
            f"  [dim]→ redirected to[/dim] [cyan]{report.final_url}[/cyan]",
            highlight=False,
        )
    con.print()
    _print_results_table(report, con)
    actions = extract_verdict_actions(report)
    grade = calculate_grade(actions)
    _print_verdict(actions, grade, con)
    con.rule("[dim]End of Report[/dim]")


def print_results_table(report: HeadersReport, console: Console | None = None) -> None:
    """Print only the per-header results table.

    :param report: Validation report whose results should be tabulated.
    :param console: Optional Rich console; defaults to the module-level console.
    """
    _print_results_table(report, console or _console)


# ---------------------------------------------------------------------------
# Internal renderers
# ---------------------------------------------------------------------------


def _status_text(status: Status) -> Text:
    """Build a colour-coded Rich :class:`~rich.text.Text` label for *status*.

    :param status: Validation status to render.
    :returns: Rich Text object with colour styling applied.
    :rtype: rich.text.Text
    """
    colour, symbol = _STATUS_STYLE[status]
    return Text(f"{symbol} {status.value}", style=f"bold {colour}")


def _grade_text(grade: Grade) -> Text:
    """Build a styled Rich :class:`~rich.text.Text` for the grade summary line.

    The text assembles "Security Verdict", the letter grade (styled by
    :data:`_GRADE_STYLE`), and the rationale into a single :class:`~rich.text.Text`.

    :param grade: Computed grade to render.
    :returns: Rich Text with letter grade styled according to its value.
    :rtype: rich.text.Text
    """
    style = _GRADE_STYLE.get(grade.letter, "bold white")
    return Text.assemble(
        ("Security Verdict  ", "bold white"),
        (grade.letter, style),
        ("  ", ""),
        (grade.rationale, "dim"),
    )


def _print_results_table(report: HeadersReport, con: Console) -> None:
    """Render the per-header results as a Rich table to *con*.

    :param report: Validation report whose results should be tabulated.
    :param con: Rich console to write to.
    """
    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white",
        expand=False,
        border_style="dim",
    )
    table.add_column("Status", style="bold", min_width=8, no_wrap=True)
    table.add_column("Header", style="cyan", min_width=36, no_wrap=True)
    table.add_column("Present", justify="center", min_width=7)
    table.add_column("IANA", style="dim", min_width=11)
    table.add_column("Source", style="dim", min_width=22)
    table.add_column("Reason / Value", min_width=50)

    for result in report.results:
        colour, symbol = _STATUS_STYLE[result.status]
        status_cell = f"[{colour}]{symbol} {result.status.value}[/{colour}]"
        present_cell = "[green]yes[/green]" if result.present else "[dim]no[/dim]"

        # Truncate long values for display
        reason = result.reason
        if result.present and result.value:
            short_val = result.value[:60] + ("…" if len(result.value) > 60 else "")
            reason = f"{reason}\n[dim]value: {short_val}[/dim]"

        table.add_row(
            status_cell,
            result.name,
            present_cell,
            result.iana_status,
            result.source,
            reason,
        )

    con.print(table)
    con.print()


def _print_verdict(actions: list[VerdictAction], grade: Grade, con: Console) -> None:
    """Render the security verdict panel to *con*.

    Displays a table of prioritised action items (CRITICAL → HIGH → MEDIUM)
    inside a Rich panel whose border colour reflects the overall grade.

    :param actions: Severity-sorted list from :func:`~headersvalidator.verdict.extract_verdict_actions`.
    :param grade: Overall grade from :func:`~headersvalidator.verdict.calculate_grade`.
    :param con: Rich console to write to.
    """
    border_colour = _GRADE_STYLE.get(grade.letter, "bold white").split()[-1]

    table = Table(
        box=box.SIMPLE, show_header=True, header_style="bold white", expand=True
    )
    table.add_column("Priority", style="bold", min_width=10, no_wrap=True)
    table.add_column("Action")

    for action in actions:
        sev_style = _SEVERITY_STYLE[action.severity]
        table.add_row(
            Text(action.severity.value, style=sev_style),
            action.text,
        )

    if not actions:
        table.add_row(
            Text("PASS", style="bold green"),
            "No issues found — all evaluated headers pass.",
        )

    con.print(
        Panel(
            table,
            title=_grade_text(grade),
            border_style=border_colour,
            expand=False,
            padding=(0, 1),
        )
    )
    con.print()
