"""
Reporter/Reporter.py — Live console output and JSON report generation.

Provides the :class:`Reporter` used by all other modules to log findings,
status messages, and produce the final summary and report file.
"""
from __future__ import annotations

import json
import logging
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Generator, Tuple

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table

from Models import Finding

logger = logging.getLogger(__name__)

# Single shared console instance (stdout)
console = Console()


class Reporter:
    """Collects findings and drives all user-visible output.

    Responsibilities:
    - Live rich-formatted findings to stdout as they are discovered
    - Informational / error logging helpers
    - Final JSON report persistence
    - End-of-run summary table
    """

    def __init__(self, output_file: str) -> None:
        self.output_file: str = output_file
        self.findings: list[Finding] = []
        self.pages_crawled: int = 0
        self.inputs_tested: int = 0

    # ------------------------------------------------------------------
    # Display helpers
    # ------------------------------------------------------------------

    def print_banner(self) -> None:
        """Print the tool banner to the console."""
        console.print(
            Panel(
                "[bold red]Affix' XSS Tester[/bold red]  |  Playwright-based async XSS scanner\n"
                "[dim]Use responsibly and only on systems you are authorised to test.[/dim]",
                expand=False,
                style="bold white on black",
            )
        )

    def log_finding(self, finding: Finding) -> None:
        """Record *finding* and print a highlighted one-liner to the console."""
        self.findings.append(finding)
        console.print(
            f"[bold red on black] VULN [/bold red on black] "
            f"[cyan]{finding.url}[/cyan]  "
            f"param=[yellow]{finding.parameter}[/yellow]  "
            f"via=[green]{finding.detection_method}[/green]  "
            f"id=[dim]{finding.test_id}[/dim]"
        )
        logger.debug("Payload that fired: %r", finding.payload)

    def log_info(self, message: str) -> None:
        """Print a standard informational message (supports Rich markup)."""
        console.print(f"[dim]\\[*][/dim] {message}")

    def log_error(self, message: str) -> None:
        """Print an error message (supports Rich markup)."""
        console.print(f"[bold red]\\[!][/bold red] {message}")

    def log_debug(self, message: str) -> None:
        """Emit a structured debug log (not printed to console)."""
        logger.debug(message)

    @contextmanager
    def testing_progress(self, total: int) -> Generator[Tuple[Progress, TaskID], None, None]:
        """Context manager that renders a Rich progress bar for the testing phase.

        Yields ``(progress, task_id)`` so callers can call
        ``progress.advance(task_id)`` as each injection completes.
        Uses the shared *console* so that ``log_finding`` / ``log_info`` output
        is rendered above the live bar without corrupting the display.
        """
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=console,
            transient=False,
        ) as progress:
            task_id = progress.add_task("[cyan]Testing…[/cyan]", total=total)
            yield progress, task_id

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self) -> None:
        """Serialise all findings to the JSON report file."""
        data = [asdict(f) for f in self.findings]
        try:
            Path(self.output_file).write_text(json.dumps(data, indent=2))
            console.print(f"\n[green]\\[+][/green] Report saved: [bold]{self.output_file}[/bold]")
        except OSError as exc:
            console.print(f"[red]\\[!][/red] Failed to save report: {exc}")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def print_summary(self) -> None:
        """Print an end-of-run summary table."""
        table = Table(title="Scan Summary", box=box.ROUNDED, show_header=True)
        table.add_column("Metric", style="bold cyan", min_width=22)
        table.add_column("Value", style="white", justify="right")

        table.add_row("Pages crawled", str(self.pages_crawled))
        table.add_row("Inputs tested", str(self.inputs_tested))

        if self.findings:
            count_str = f"[bold red]{len(self.findings)}[/bold red]"
        else:
            count_str = f"[bold green]{len(self.findings)}[/bold green]"

        table.add_row("Findings", count_str)

        console.print()
        console.print(table)
