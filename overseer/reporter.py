"""
Reporting and visualization formatting for Overseer.
Supports rich terminal formatting, live event streaming, and JSON export.
"""

import json
import sys
from typing import Optional

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    HAVE_RICH = True
except ImportError:
    HAVE_RICH = False

from overseer.models import (
    DuplicateFinding,
    FindingKind,
    Severity,
    SyscallEvent,
    SyscallReport,
)


class Reporter:
    """Formats and prints live trace events, findings, and final reports."""

    def __init__(self, quiet: bool = False, verbose: bool = False, use_color: bool = True):
        self.quiet = quiet
        self.verbose = verbose
        self.use_color = use_color
        self.console = Console(highlight=False) if HAVE_RICH else None

    def log_syscall(self, event: SyscallEvent):
        """Print individual syscall if verbose mode is active."""
        if not self.verbose:
            return

        call_str = event.format_call()
        ret_part = f"-> {event.ret_str}" if event.ret_str else ""
        loc_part = f"[{event.location}]" if event.location else ""

        if HAVE_RICH and self.console:
            color = "red" if event.is_error else "cyan"
            self.console.print(
                f"[dim]#{event.sequence:04d}[/dim] [yellow]tid:{event.thread_id}[/yellow] "
                f"[{color}]{call_str}[/{color}] {ret_part} [dim]{loc_part}[/dim]"
            )
        else:
            print(f"#{event.sequence:04d} tid:{event.thread_id} {call_str} {ret_part} {loc_part}")

    def log_finding(self, finding: DuplicateFinding):
        """Print a live alert when a duplicate syscall pattern is detected."""
        curr = finding.current_event
        prev = finding.previous_event

        curr_loc = f"{curr.location or 'unknown'}"
        prev_loc = f"{prev.location or 'unknown'}"

        if HAVE_RICH and self.console:
            sev_colors = {
                Severity.ERROR: "bold white on red",
                Severity.WARNING: "bold black on yellow",
                Severity.INFO: "bold white on blue",
            }
            badge = f"[{sev_colors.get(finding.severity, 'bold white')}] {finding.severity.value.upper()} [/{sev_colors.get(finding.severity, 'bold white')}]"
            title = f"{badge} [bold]{finding.kind.value.upper()}[/bold]: {finding.message}"

            content = (
                f"[bold cyan]Current Call:[/bold cyan]  #{curr.sequence:04d} {curr.format_call()} -> {curr.ret_str}\n"
                f"              Location: [green]{curr_loc}[/green]\n"
                f"[bold yellow]Previous Call:[/bold yellow] #{prev.sequence:04d} {prev.format_call()} -> {prev.ret_str}\n"
                f"              Location: [green]{prev_loc}[/green]"
            )
            if finding.window_distance > 1:
                content += f"\n              Distance: {finding.window_distance} syscalls ago"

            self.console.print(Panel(content, title=title, border_style="red" if finding.severity == Severity.ERROR else "yellow"))
        else:
            print(f"\n*** [{finding.severity.value.upper()}] {finding.kind.value.upper()}: {finding.message} ***")
            print(f"  Current:  #{curr.sequence:04d} {curr.format_call()} -> {curr.ret_str} at {curr_loc}")
            print(f"  Previous: #{prev.sequence:04d} {prev.format_call()} -> {prev.ret_str} at {prev_loc}")
            if finding.window_distance > 1:
                print(f"  Distance: {finding.window_distance} syscalls ago")
            print()

    def print_summary(self, report: SyscallReport):
        """Print a comprehensive final report with statistics and duplicate breakdown."""
        if HAVE_RICH and self.console:
            self._print_summary_rich(report)
        else:
            self._print_summary_plain(report)

    def _print_summary_rich(self, report: SyscallReport):
        self.console.print()
        self.console.rule("[bold cyan]Overseer Syscall Duplicate Analysis Report[/bold cyan]")
        self.console.print(f"[bold]Target Program:[/bold] {report.target}")
        self.console.print(f"[bold]Total Syscalls:[/bold] {report.total_syscalls}")
        self.console.print(f"[bold]Unique Syscalls:[/bold] {report.unique_syscalls}")
        self.console.print(f"[bold]Flagged Duplicates:[/bold] [red]{len(report.findings)}[/red]")
        if report.duration_seconds > 0:
            self.console.print(f"[bold]Duration:[/bold] {report.duration_seconds:.2f}s")
        self.console.print()

        if not report.findings:
            self.console.print("[green]✔ No duplicate syscalls detected![/green]\n")
            return

        table = Table(title="Flagged Duplicated Syscalls", header_style="bold magenta")
        table.add_column("Seq", style="dim", width=6)
        table.add_column("Severity", width=10)
        table.add_column("Kind", width=12)
        table.add_column("Syscall & Arguments", style="cyan")
        table.add_column("Return", style="yellow", width=14)
        table.add_column("Location", style="green")

        for f in report.findings:
            sev_style = "red bold" if f.severity == Severity.ERROR else "yellow" if f.severity == Severity.WARNING else "blue"
            table.add_row(
                f"#{f.current_event.sequence:04d}",
                f"[{sev_style}]{f.severity.value.upper()}[/{sev_style}]",
                f.kind.value,
                f.current_event.format_call(),
                str(f.current_event.ret_str),
                f.current_event.location or "??",
            )
        self.console.print(table)
        self.console.print()

        # Duplicate counts by syscall
        if report.duplicate_counts:
            d_table = Table(title="Duplicate Frequency by Syscall", header_style="bold blue")
            d_table.add_column("Syscall", style="bold")
            d_table.add_column("Total Calls", justify="right")
            d_table.add_column("Duplicates", justify="right", style="red")
            d_table.add_column("Dup Rate", justify="right")

            for name, dup_cnt in sorted(report.duplicate_counts.items(), key=lambda x: x[1], reverse=True):
                total = report.syscall_counts.get(name, dup_cnt)
                pct = (dup_cnt / total * 100.0) if total > 0 else 0.0
                d_table.add_row(name, str(total), str(dup_cnt), f"{pct:.1f}%")
            self.console.print(d_table)
            self.console.print()

    def _print_summary_plain(self, report: SyscallReport):
        print("\n" + "=" * 60)
        print(" Overseer Syscall Duplicate Analysis Report")
        print("=" * 60)
        print(f"Target:             {report.target}")
        print(f"Total Syscalls:     {report.total_syscalls}")
        print(f"Unique Syscalls:    {report.unique_syscalls}")
        print(f"Flagged Duplicates: {len(report.findings)}")
        print(f"Duration:           {report.duration_seconds:.2f}s\n")

        if not report.findings:
            print("No duplicate syscalls detected.")
            return

        print(f"{'Seq':<6} {'Severity':<10} {'Kind':<14} {'Syscall':<30} {'Location'}")
        print("-" * 75)
        for f in report.findings:
            print(
                f"#{f.current_event.sequence:<5} "
                f"{f.severity.value.upper():<10} "
                f"{f.kind.value:<14} "
                f"{f.current_event.name:<30} "
                f"{f.current_event.location or '??'}"
            )

        print("\nDuplicate Breakdown:")
        for name, cnt in sorted(report.duplicate_counts.items(), key=lambda x: x[1], reverse=True):
            tot = report.syscall_counts.get(name, cnt)
            pct = (cnt / tot * 100.0) if tot > 0 else 0.0
            print(f"  {name:<16}: {cnt} duplicates / {tot} total ({pct:.1f}%)")
        print("=" * 60 + "\n")

    def export_json(self, report: SyscallReport, filepath: str):
        """Export report to a JSON file."""
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2)
