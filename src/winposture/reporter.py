"""Output formatting for WinPosture audit reports.

Supports:
  - Rich-formatted terminal output
  - HTML report via Jinja2 template
  - JSON export
"""

from __future__ import annotations

import dataclasses
import json
import logging
from pathlib import Path

from winposture.models import AuditReport, CheckResult, Severity, Status
from winposture.scoring import score_label

log = logging.getLogger(__name__)

# Rich status/severity → color mapping
_STATUS_COLORS: dict[Status, str] = {
    Status.PASS: "green",
    Status.FAIL: "red",
    Status.WARN: "yellow",
    Status.INFO: "cyan",
    Status.ERROR: "magenta",
}

_SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}

_SCORE_COLORS = {
    "Excellent": "bold green",
    "Good": "green",
    "Fair": "yellow",
    "Poor": "red",
    "Critical": "bold red",
}


class Reporter:
    """Formats and outputs audit reports.

    Args:
        verbose:   If True, show details/remediation for every check result.
        no_color:  If True, disable Rich color markup.
    """

    def __init__(self, verbose: bool = False, no_color: bool = False) -> None:
        self.verbose = verbose
        self.no_color = no_color

    def print_terminal(self, report: AuditReport) -> None:
        """Print the audit report to the terminal using Rich.

        Args:
            report: The completed AuditReport to display.
        """
        try:
            from rich.console import Console
            from rich.panel import Panel
            from rich.table import Table
            from rich import box
        except ImportError:
            log.warning("Rich not installed — falling back to plain text output")
            self._print_plain(report)
            return

        console = Console(no_color=self.no_color)

        # Banner
        label = score_label(report.score)
        score_color = _SCORE_COLORS.get(label, "white")
        console.print(
            Panel.fit(
                f"[bold]WinPosture Security Audit[/bold]\n"
                f"Host: [cyan]{report.hostname}[/cyan]  |  "
                f"OS: [cyan]{report.os_version}[/cyan]\n"
                f"Score: [{score_color}]{report.score}/100 — {label}[/{score_color}]  |  "
                f"Duration: {report.scan_duration:.1f}s\n"
                f"[green]PASS: {report.pass_count}[/green]  "
                f"[red]FAIL: {report.fail_count}[/red]  "
                f"[yellow]WARN: {report.warn_count}[/yellow]",
                title="[bold blue]WinPosture[/bold blue]",
                border_style="blue",
            )
        )

        if not report.results:
            console.print("[yellow]No check results — no modules were loaded.[/yellow]")
            return

        # Results table
        table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold")
        table.add_column("Category", style="dim", width=14)
        table.add_column("Check", min_width=30)
        table.add_column("Status", width=8, justify="center")
        table.add_column("Severity", width=10, justify="center")
        if self.verbose:
            table.add_column("Details")
            table.add_column("Remediation")

        # Group by category for readability
        categories = sorted({r.category for r in report.results})
        for category in categories:
            for result in report.results:
                if result.category != category:
                    continue
                status_color = _STATUS_COLORS.get(result.status, "white")
                sev_color = _SEVERITY_COLORS.get(result.severity, "white")
                row = [
                    result.category,
                    result.check_name,
                    f"[{status_color}]{result.status.value}[/{status_color}]",
                    f"[{sev_color}]{result.severity.value}[/{sev_color}]",
                ]
                if self.verbose:
                    row.append(result.details or "—")
                    row.append(result.remediation or "—")
                table.add_row(*row)

        console.print(table)

    def save_html(self, report: AuditReport, path: str) -> None:
        """Render and save an HTML report.

        Args:
            report: The AuditReport to render.
            path:   File path to write the HTML output.
        """
        try:
            from jinja2 import Environment, FileSystemLoader, select_autoescape
        except ImportError:
            log.error("Jinja2 not installed — cannot generate HTML report")
            return

        template_dir = Path(__file__).parent.parent.parent / "templates"
        env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(["html"]),
        )
        try:
            template = env.get_template("report.html.j2")
        except Exception as exc:
            log.error("Could not load HTML template: %s", exc)
            return

        html = template.render(
            report=report,
            score_label=score_label(report.score),
            status_colors={s.value: c for s, c in _STATUS_COLORS.items()},
        )
        output = Path(path)
        output.write_text(html, encoding="utf-8")
        log.info("HTML report saved to %s", output)
        print(f"HTML report saved: {output}")

    def save_json(self, report: AuditReport, path: str) -> None:
        """Serialize the AuditReport to JSON and write to disk.

        Args:
            report: The AuditReport to serialize.
            path:   File path to write the JSON output.
        """

        def _default(obj):
            if hasattr(obj, "isoformat"):  # datetime
                return obj.isoformat()
            if isinstance(obj, (Status, Severity)):
                return obj.value
            raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

        data = dataclasses.asdict(report)
        output = Path(path)
        output.write_text(json.dumps(data, indent=2, default=_default), encoding="utf-8")
        log.info("JSON report saved to %s", output)
        print(f"JSON report saved: {output}")

    def _print_plain(self, report: AuditReport) -> None:
        """Minimal plain-text fallback when Rich is unavailable."""
        print(f"WinPosture  |  {report.hostname}  |  Score: {report.score}/100")
        print(f"PASS: {report.pass_count}  FAIL: {report.fail_count}  WARN: {report.warn_count}")
        for r in report.results:
            print(f"[{r.status.value:4}] [{r.severity.value:8}] {r.category}: {r.check_name}")
            if self.verbose and r.details:
                print(f"       Details: {r.details}")
            if self.verbose and r.remediation:
                print(f"       Fix:     {r.remediation}")
