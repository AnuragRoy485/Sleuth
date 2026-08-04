"""Beautiful console output using rich."""

from __future__ import annotations

from typing import List

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from ..scanner import Finding


SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "blue",
}


class ConsoleReporter:
    def __init__(self, verbose: bool = False):
        self.console = Console()
        self.verbose = verbose

    def report(self, findings: List[Finding], scanned_path: str) -> None:
        self.console.print()

        if not findings:
            self.console.print(
                Panel(
                    "[bold green]✓ No secrets found[/bold green]",
                    title="Sleuth Results",
                    border_style="green",
                )
            )
            return

        # Summary
        critical = sum(1 for f in findings if f.severity == "CRITICAL")
        high = sum(1 for f in findings if f.severity == "HIGH")
        medium = sum(1 for f in findings if f.severity == "MEDIUM")
        low = sum(1 for f in findings if f.severity == "LOW")

        summary = Text()
        summary.append(f"Found {len(findings)} potential secret(s)\n", style="bold")
        if critical:
            summary.append(f"  CRITICAL : {critical}\n", style="bold red")
        if high:
            summary.append(f"  HIGH     : {high}\n", style="red")
        if medium:
            summary.append(f"  MEDIUM   : {medium}\n", style="yellow")
        if low:
            summary.append(f"  LOW      : {low}\n", style="blue")
        summary.append(f"\nScanned: {scanned_path}", style="dim")

        self.console.print(
            Panel(summary, title="[bold]Sleuth Results[/bold]", border_style="red")
        )
        self.console.print()

        # Detailed findings table
        table = Table(
            title="Findings",
            box=box.ROUNDED,
            show_lines=True,
            expand=True,
        )
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Rule", width=22)
        table.add_column("File:Line", width=35)
        table.add_column("Match / Entropy", overflow="fold")

        for f in findings:
            color = SEVERITY_COLORS.get(f.severity, "white")
            location = f"{f.file_path}:{f.line_number}"
            match_display = f.match
            if len(match_display) > 60:
                match_display = match_display[:57] + "..."
            if f.entropy is not None:
                match_display += f"  (entropy={f.entropy:.2f})"

            table.add_row(
                Text(f.severity, style=color),
                f.rule_id,
                location,
                match_display,
            )

        self.console.print(table)

        if self.verbose:
            self.console.print("\n[bold]Detailed Context:[/bold]\n")
            for i, f in enumerate(findings, 1):
                self.console.print(
                    f"[bold cyan]#{i}[/bold cyan] [{SEVERITY_COLORS.get(f.severity)}]{f.severity}[/] "
                    f"{f.rule_id} — {f.description}"
                )
                self.console.print(f"  [dim]{f.file_path}:{f.line_number}[/dim]")
                if f.context:
                    self.console.print(Panel(f.context, border_style="dim", expand=False))
                self.console.print()
