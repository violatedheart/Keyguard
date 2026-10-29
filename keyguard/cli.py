"""Rich command-line interface. No process-control actions are implemented."""

import argparse
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Sequence

from rich.console import Console
from rich.table import Table
from rich.text import Text

from keyguard import __version__
from keyguard.allowlist import add_user_entry, default_allowlist_path, load_allowlist
from keyguard.config import load_config
from keyguard.models import ProcessReport, ScanReport
from keyguard.reporting import export_report
from keyguard.scanner import Scanner


def create_parser() -> argparse.ArgumentParser:
    """Build CLI arguments with explicit filesystem writes and no destructive verbs."""
    parser = argparse.ArgumentParser(prog="keyguard", description="Read-only Windows keylogger-risk triage")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--config", type=Path, help="Weights/configuration JSON; otherwise bundled defaults")
    parser.add_argument("--allowlist", type=Path, help="Editable user allowlist JSON; default: local app data / KeyGuard")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="Full scan; show Medium and High processes")
    scan.add_argument("--all", action="store_true", help="Show all processes, including Low")
    inspect = subparsers.add_parser("inspect", help="Detailed process report")
    inspect.add_argument("pid", type=int)
    export = subparsers.add_parser("export", help="Run a fresh scan and save a full report")
    formats = export.add_mutually_exclusive_group(required=True)
    formats.add_argument("--json", action="store_true")
    formats.add_argument("--html", action="store_true")
    export.add_argument("--output", "-o", type=Path, help="New report filename; existing files are not overwritten")
    allow = subparsers.add_parser("allow", help="Explicitly add an executable path + hash exception")
    allow.add_argument("exe", type=Path)
    subparsers.add_parser("watch", help="Scan every 30 seconds by default and alert on new High processes")
    return parser


def show_scan(report: ScanReport, console: Console, show_all: bool = False) -> None:
    """Display findings and coverage even when no process crosses the risk threshold."""
    table = Table(title=f"KeyGuard — {report.generated_at}")
    for column in ("PID", "Process", "Score", "Risk", "Reasons"):
        table.add_column(column, overflow="fold")
    count = 0
    for item in report.processes:
        if not show_all and item.level == "Low":
            continue
        count += 1
        reasons = "; ".join(reason for finding in item.findings for reason in finding["reasons"])
        if item.issues:
            reasons += f"; {len(item.issues)} coverage issue(s): use inspect {item.process.pid}"
        table.add_row(*(Text(value) for value in (str(item.process.pid), item.process.name,
                                                str(item.score), item.level, reasons)))
    console.print(table, markup=False)
    console.print(f"Scanned {len(report.processes)} processes; displayed {count}. Scores are heuristic, not a diagnosis.", markup=False)
    incomplete = sum(bool(item.issues) for item in report.processes)
    console.print(f"{incomplete} processes have coverage issues. Low scores with missing evidence do not establish safety.", markup=False)
    for issue in report.issues:
        console.print(f"Note: {issue}", markup=False)
    risky_entries = [entry for entry in report.persistence if entry["risky_locations"]]
    if risky_entries:
        console.print(f"{len(risky_entries)} persistence entries reference risky locations (including entries without a running match).", markup=False)
        for entry in risky_entries:
            console.print(f"  {entry['kind']}: {entry['name']} -> {entry['command']}", markup=False)


def show_process(item: ProcessReport, console: Console) -> None:
    """Print the full process evidence, including neutral observations and gaps."""
    console.print(f"PID {item.process.pid} | {item.process.name} | {item.score}/100 {item.level}", markup=False)
    console.print(f"Executable: {item.process.exe or '(unavailable)'}", markup=False)
    console.print(f"Parent: {item.process.ppid} {item.process.parent_name or '(unavailable)'}", markup=False)
    for finding in item.findings:
        console.print(f"{finding['weight']:+d} [{finding['module']}] " + "; ".join(finding["reasons"]), markup=False)
    for issue in item.issues:
        console.print(f"Coverage: {issue}", markup=False)
    console.print(json.dumps(item.observations, indent=2, ensure_ascii=False), markup=False)


def new_high_items(report: ScanReport, previous: set[tuple[int, float | None]]) -> tuple[list[ProcessReport], set[tuple[int, float | None]]]:
    """Track process instances; alert on entry or re-entry into the High tier."""
    high = [item for item in report.processes if item.level == "High"]
    identities = {(item.process.pid, item.process.create_time) for item in high}
    return [item for item in high if (item.process.pid, item.process.create_time) not in previous], identities


def watch(scanner: Scanner, console: Console, interval: int) -> None:
    """Scan at a configurable interval until Ctrl+C; alert on the first High snapshot."""
    previous: set[tuple[int, float | None]] = set()
    while True:
        started = time.monotonic()
        report = scanner.scan()
        alerts, previous = new_high_items(report, previous)
        show_scan(report, console)
        for item in alerts:
            console.print(f"ALERT: new High item — PID {item.process.pid} {item.process.name} ({item.score}/100)", style="bold red", markup=False)
            console.bell()
        time.sleep(max(0, interval - (time.monotonic() - started)))


def main(argv: Sequence[str] | None = None) -> int:
    """Dispatch commands; fail clearly without tracebacks on expected OS errors."""
    parser = create_parser()
    args = parser.parse_args(argv)
    console = Console(highlight=False)
    if args.command == "inspect" and args.pid <= 0:
        parser.error("pid must be a positive integer")
    try:
        allow_path = args.allowlist or default_allowlist_path()
        if args.command == "allow":
            entry = add_user_entry(args.exe, allow_path)
            console.print(f"Allowlisted {entry['path']}\nSHA-256: {entry['sha256']}\nSaved to {allow_path}", markup=False)
            return 0
        config = load_config(args.config)
        scanner = Scanner(config, load_allowlist(allow_path))
        if args.command == "watch":
            console.print("Press Ctrl+C to stop. Allowlist/configuration edits take effect after restarting watch.", markup=False)
            watch(scanner, console, config["watch_interval_seconds"])
        else:
            report = scanner.scan(args.pid if args.command == "inspect" else None)
            if args.command == "export":
                format_name = "json" if args.json else "html"
                destination = args.output or Path(f"keyguard-{datetime.now():%Y%m%d-%H%M%S-%f}.{format_name}")
                export_report(report, destination, format_name)
                console.print(f"Saved {destination.resolve()}", markup=False)
            elif args.command == "inspect":
                show_process(report.processes[0], console)
                for issue in report.issues:
                    console.print(f"Note: {issue}", markup=False)
            else:
                show_scan(report, console, args.all)
        return 0
    except KeyboardInterrupt:
        console.print("Stopped.", markup=False)
        return 130
    except (OSError, ValueError, KeyError, LookupError, RuntimeError) as exc:
        console.print(f"KeyGuard: {exc}", style="red", markup=False)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
