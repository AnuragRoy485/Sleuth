"""Command-line interface for Sleuth."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from . import __version__
from .scanner import Scanner
from .rules import get_all_rules
from .reporters import ConsoleReporter, JsonReporter, SarifReporter

app = typer.Typer(
    name="sleuth",
    help="Sleuth — High-performance Python-native secrets & API key scanner with entropy analysis and SARIF support.",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()


@app.command()
def scan(
    path: Path = typer.Argument(
        ...,
        exists=True,
        help="File or directory to scan",
        show_default=False,
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Write JSON report to this file",
    ),
    sarif: Optional[Path] = typer.Option(
        None,
        "--sarif",
        help="Write SARIF 2.1.0 report (perfect for GitHub Code Scanning)",
    ),
    entropy: bool = typer.Option(
        True,
        "--entropy/--no-entropy",
        help="Enable high-entropy string detection",
    ),
    entropy_threshold: float = typer.Option(
        4.5,
        "--entropy-threshold",
        help="Minimum Shannon entropy to flag a string (default 4.5)",
    ),
    threads: int = typer.Option(
        8,
        "--threads",
        "-t",
        help="Number of concurrent workers",
    ),
    max_size: int = typer.Option(
        2,
        "--max-size",
        help="Maximum file size to scan in MB (default 2)",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show detailed context for each finding",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Only output findings count / exit code (useful for CI)",
    ),
    no_progress: bool = typer.Option(
        False,
        "--no-progress",
        help="Disable progress bar",
    ),
):
    """
    Scan a file or directory for secrets, API keys, tokens and high-entropy strings.
    """
    if quiet:
        no_progress = True

    scanner = Scanner(
        entropy_threshold=entropy_threshold,
        enable_entropy=entropy,
        max_file_size=max_size * 1024 * 1024,
        threads=threads,
    )

    if not quiet:
        console.print(f"[bold cyan]Sleuth[/bold cyan] v{__version__} — scanning [bold]{path}[/bold] ...")

    findings = scanner.scan(path, show_progress=not no_progress)

    # Console output
    if not quiet:
        reporter = ConsoleReporter(verbose=verbose)
        reporter.report(findings, str(path))

    # JSON
    if output:
        JsonReporter().report(findings, str(path), output)
        if not quiet:
            console.print(f"\n[green]JSON report written to[/green] {output}")

    # SARIF
    if sarif:
        SarifReporter().report(findings, str(path), sarif)
        if not quiet:
            console.print(f"[green]SARIF report written to[/green] {sarif}")

    # Exit code for CI
    if findings:
        critical_or_high = any(f.severity in ("CRITICAL", "HIGH") for f in findings)
        if quiet:
            print(len(findings))
        raise typer.Exit(code=1 if critical_or_high else 0)

    if quiet:
        print(0)
    raise typer.Exit(code=0)


@app.command("rules")
def list_rules():
    """List all built-in detection rules."""
    rules = get_all_rules()
    console.print(f"\n[bold]Built-in rules ({len(rules)}):[/bold]\n")

    from rich.table import Table
    table = Table(show_header=True, header_style="bold")
    table.add_column("ID", style="cyan")
    table.add_column("Severity")
    table.add_column("Description")
    table.add_column("Tags")

    for r in rules:
        color = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue",
        }.get(r.severity, "white")
        table.add_row(
            r.id,
            f"[{color}]{r.severity}[/{color}]",
            r.description,
            ", ".join(r.tags),
        )

    console.print(table)
    console.print()


@app.command()
def version():
    """Show version information."""
    console.print(f"Sleuth v{__version__}")


def main():
    app()


if __name__ == "__main__":
    main()
