"""
Typer CLI for headersvalidator.

Sub-commands
------------
  check   Validate the HTTP headers of a URL
  info    Reference tables (rules, IANA status, sources)
  version Print version and exit

The CLI never touches the "headersvalidator" logger — all display goes
through Rich, following the same pattern as chainvalidator's cli.py.
"""

from __future__ import annotations

import typer
from rich import box
from rich.console import Console
from rich.table import Table

app = typer.Typer(
    name="headersvalidator",
    help=(
        "Validate HTTP response headers against RFC 9110, RFC 9111, "
        "OWASP HTTP Headers Cheat Sheet, and the IANA HTTP Field Name Registry."
    ),
    add_completion=False,
)

console = Console(highlight=False)

# ---------------------------------------------------------------------------
# headersvalidator check <url>
# ---------------------------------------------------------------------------


@app.command()
def check(
    url: str = typer.Argument(
        ..., help="URL to validate (scheme optional; https:// assumed)."
    ),
    timeout: float = typer.Option(
        10.0, "--timeout", "-t", help="Request timeout in seconds."
    ),
    no_tls_verify: bool = typer.Option(
        False, "--no-tls-verify", help="Skip TLS certificate verification."
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON."),
    fail_on_warn: bool = typer.Option(
        False, "--strict", help="Exit code 1 on WARN as well as FAIL."
    ),
) -> None:
    """
    Fetch *URL* and validate its HTTP response headers.

    Exit codes:
      0  All required headers pass
      1  One or more headers fail (or warn with --strict)
      2  Network / connection error
    """
    import requests

    from headersvalidator.assessor import assess
    from headersvalidator.reporter import print_full_report

    try:
        report = assess(url, timeout=timeout, verify_tls=not no_tls_verify)
    except requests.RequestException as exc:
        console.print(f"[red]Error:[/red] Could not reach {url!r}: {exc}")
        raise typer.Exit(code=2)

    if json_output:
        _print_json(report)
        _exit_for_status(report.status, fail_on_warn)
        return

    print_full_report(report, console=console)

    _exit_for_status(report.status, fail_on_warn)


# ---------------------------------------------------------------------------
# headersvalidator info <topic>
# ---------------------------------------------------------------------------

info_app = typer.Typer(help="Reference tables.")
app.add_typer(info_app, name="info")


@info_app.command("rules")
def info_rules() -> None:
    """Show all header rules with their source and recommended values."""
    from headersvalidator.constants import HEADER_RULES

    table = Table(
        title="Header Validation Rules",
        box=box.ROUNDED,
        header_style="bold white",
        show_lines=True,
    )
    table.add_column("Header", style="cyan", min_width=38)
    table.add_column("Required", justify="center")
    table.add_column("IANA Status", style="dim", min_width=12)
    table.add_column("Source", style="dim", min_width=24)
    table.add_column("Recommended Value", min_width=40)

    for rule in HEADER_RULES:
        req = "[red]yes[/red]" if rule["required"] else "[dim]no[/dim]"
        table.add_row(
            rule["name"],
            req,
            rule["iana_status"],
            rule["source"],
            rule["recommended"],
        )
    console.print(table)


@info_app.command("sources")
def info_sources() -> None:
    """List the reference sources used by headersvalidator."""
    table = Table(
        title="Reference Sources", box=box.SIMPLE_HEAD, header_style="bold white"
    )
    table.add_column("Name", style="cyan", min_width=18)
    table.add_column("Description", min_width=60)
    table.add_column("URL", style="dim")

    rows = [
        (
            "RFC 9110",
            "HTTP Semantics — defines field names, semantics, and requirements",
            "https://www.rfc-editor.org/rfc/rfc9110",
        ),
        (
            "RFC 9111",
            "HTTP Caching — Cache-Control directive grammar and semantics",
            "https://www.rfc-editor.org/rfc/rfc9111",
        ),
        (
            "OWASP Headers CS",
            "OWASP HTTP Headers Cheat Sheet — security pass/fail criteria",
            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
        ),
        (
            "IANA HTTP Fields",
            "IANA HTTP Field Name Registry — permanent/provisional/obsoleted status",
            "https://www.iana.org/assignments/http-fields/http-fields.xhtml",
        ),
    ]
    for name, desc, url in rows:
        table.add_row(name, desc, url)
    console.print(table)


@info_app.command("iana")
def info_iana() -> None:
    """Show IANA registration status for every evaluated header."""
    from headersvalidator.constants import HEADER_RULES

    table = Table(
        title="IANA HTTP Field Name Registry Status",
        box=box.ROUNDED,
        header_style="bold white",
    )
    table.add_column("Header", style="cyan", min_width=38)
    table.add_column("IANA Status", min_width=14)
    table.add_column("Primary Source")

    status_colours = {
        "permanent": "green",
        "provisional": "yellow",
        "deprecated": "dim",
        "obsoleted": "red",
    }
    for rule in HEADER_RULES:
        s = rule["iana_status"]
        colour = status_colours.get(s, "white")
        table.add_row(rule["name"], f"[{colour}]{s}[/{colour}]", rule["source"])
    console.print(table)


# ---------------------------------------------------------------------------
# headersvalidator --version
# ---------------------------------------------------------------------------


@app.callback(invoke_without_command=True)
def main(
    version: bool = typer.Option(
        False, "--version", "-v", is_eager=True, help="Show version."
    ),
) -> None:
    if version:
        from headersvalidator import __version__

        console.print(f"headersvalidator {__version__}")
        raise typer.Exit()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _exit_for_status(status, fail_on_warn: bool) -> None:
    """
    Raise :class:`typer.Exit` with code 1 when the report warrants a failure exit.

    :param status: Overall :class:`~headersvalidator.models.Status` of the report.
    :param fail_on_warn: If ``True``, exit 1 on WARN as well as FAIL (``--strict`` mode).
    """
    from headersvalidator.models import Status

    if status == Status.FAIL:
        raise typer.Exit(code=1)
    if fail_on_warn and status == Status.WARN:
        raise typer.Exit(code=1)


def _print_json(report) -> None:
    """
    Serialise *report* to JSON and print it to the console.

    :param report: :class:`~headersvalidator.models.HeadersReport` to serialise.
    """
    import json

    out = {
        "url": report.url,
        "final_url": report.final_url,
        "status_code": report.status_code,
        "status": report.status.value,
        "score": report.score,
        "results": [
            {
                "name": r.name,
                "status": r.status.value,
                "present": r.present,
                "value": r.value,
                "recommended": r.recommended,
                "source": r.source,
                "iana_status": r.iana_status,
                "reason": r.reason,
            }
            for r in report.results
        ],
    }
    console.print(json.dumps(out, indent=2))


if __name__ == "__main__":  # pragma: no cover
    app()
