"""
Rich terminal output for headersvalidator.

Mirrors chainvalidator's reporter.py: pure display functions that receive
a HeadersReport and render it to the terminal using Rich.
The CLI calls these; the library never touches them.
"""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from headersvalidator.models import HeadersReport, Status

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


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def print_full_report(report: HeadersReport, console: Console | None = None) -> None:
    """
    Render a complete, colour-coded terminal report for *report*.

    Prints the summary panel, per-header results table, and score panel in order.

    :param report: Validation report returned by :func:`headersvalidator.assessor.assess`.
    :param console: Optional Rich console to write to; defaults to the module-level console.
    """
    con = console or _console
    _print_summary_panel(report, con)
    _print_results_table(report, con)
    _print_score_panel(report, con)


def print_summary_panel(report: HeadersReport, console: Console | None = None) -> None:
    """
    Print only the top-level summary panel.

    :param report: Validation report to summarise.
    :param console: Optional Rich console; defaults to the module-level console.
    """
    _print_summary_panel(report, console or _console)


def print_results_table(report: HeadersReport, console: Console | None = None) -> None:
    """
    Print only the per-header results table.

    :param report: Validation report whose results should be tabulated.
    :param console: Optional Rich console; defaults to the module-level console.
    """
    _print_results_table(report, console or _console)


# ---------------------------------------------------------------------------
# Internal renderers
# ---------------------------------------------------------------------------


def _status_text(status: Status) -> Text:
    """
    Build a colour-coded Rich :class:`~rich.text.Text` label for *status*.

    :param status: Validation status to render.
    :returns: Rich Text object with colour styling applied.
    :rtype: rich.text.Text
    """
    colour, symbol = _STATUS_STYLE[status]
    return Text(f"{symbol} {status.value}", style=f"bold {colour}")


def _print_summary_panel(report: HeadersReport, con: Console) -> None:
    """
    Render the top-level summary Rich panel to *con*.

    :param report: Validation report to summarise.
    :param con: Rich console to write to.
    """
    overall = report.status
    colour, symbol = _STATUS_STYLE[overall]

    lines = [
        f"  URL          {report.url}",
        f"  Final URL    {report.final_url}",
        f"  HTTP Status  {report.status_code}",
        f"  Verdict      [{colour}]{symbol} {overall.value}[/{colour}]",
        f"  Score        {report.score}/100",
        "",
        f"  PASS {len(report.passed):>3}   "
        f"[yellow]WARN {len(report.warned):>3}[/yellow]   "
        f"[red]FAIL {len(report.failed):>3}[/red]   "
        f"[magenta]DEPRECATED {len(report.deprecated):>3}[/magenta]",
    ]
    con.print(
        Panel(
            "\n".join(lines),
            title="[bold]headersvalidator[/bold] — HTTP Security Header Report",
            border_style=colour,
            expand=False,
            padding=(0, 2),
        )
    )
    con.print()


def _print_results_table(report: HeadersReport, con: Console) -> None:
    """
    Render the per-header results as a Rich table to *con*.

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


def _print_score_panel(report: HeadersReport, con: Console) -> None:
    """
    Render the security score panel with a progress bar to *con*.

    :param report: Validation report whose score should be displayed.
    :param con: Rich console to write to.
    """
    score = report.score
    if score >= 80:
        colour, label = "green", "Good"
    elif score >= 50:
        colour, label = "yellow", "Needs improvement"
    else:
        colour, label = "red", "Poor"

    bar_width = 40
    filled = round(score / 100 * bar_width)
    bar = f"[{colour}]{'█' * filled}[/{colour}][dim]{'░' * (bar_width - filled)}[/dim]"

    missing_required = [r for r in report.failed if not r.present]
    tip = ""
    if missing_required:
        tip = "\n  Quick win: add " + ", ".join(r.name for r in missing_required[:3])
        if len(missing_required) > 3:
            tip += f" (+{len(missing_required) - 3} more)"

    con.print(
        Panel(
            f"  Security Score  {bar}  [{colour}]{score}/100 — {label}[/{colour}]{tip}",
            border_style=colour,
            expand=False,
            padding=(0, 1),
        )
    )
