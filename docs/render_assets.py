"""Render documentation diagrams and genuine CLI output from synthetic records.

Run from the repository root with ``python docs/render_assets.py``. Add ``--png``
to export PNGs with an installed Inkscape CLI. No live scan or input API is used.
"""

import argparse
import io
import shutil
import subprocess
from html import escape
from pathlib import Path

from rich.console import Console

from keyguard.cli import show_process, show_scan
from keyguard.config import load_config
from keyguard.models import Finding, ProcessReport, ProcessSnapshot, ScanReport
from keyguard.scoring import score_findings

BACKGROUND = "#0c1524"
PANEL = "#16243a"
INK = "#edf4ff"
MUTED = "#b3c4dc"
TEAL = "#64e3c4"
TERMINAL_TEMPLATE = """<svg xmlns="http://www.w3.org/2000/svg" role="img"
viewBox="0 0 {width} {height}" aria-labelledby="{unique_id}-description">
<title id="{unique_id}-description">Synthetic KeyGuard CLI example; no live system data</title>
<style>
.{unique_id}-matrix {{font-family:'DejaVu Sans Mono',monospace;font-size:{char_height}px;line-height:{line_height}px;}}
.{unique_id}-title {{font-size:18px;font-weight:bold;font-family:'DejaVu Sans',sans-serif;}}
{styles}
</style>
<defs><clipPath id="{unique_id}-clip-terminal"><rect x="0" y="0" width="{terminal_width}" height="{terminal_height}"/></clipPath>{lines}</defs>
{chrome}
<g transform="translate({terminal_x},{terminal_y})" clip-path="url(#{unique_id}-clip-terminal)">
{backgrounds}<g class="{unique_id}-matrix">{matrix}</g></g></svg>
"""


def text(x: int, y: int, value: str, size: int = 25, color: str = INK,
         weight: int = 400, mono: bool = False) -> str:
    """Create an escaped SVG text node with an installed-font fallback."""
    family = "DejaVu Sans Mono,monospace" if mono else "DejaVu Sans,sans-serif"
    return (f'<text x="{x}" y="{y}" font-size="{size}" fill="{color}" '
            f'font-weight="{weight}" font-family="{family}">{escape(value)}</text>')


def rect(x: int, y: int, width: int, height: int, color: str = PANEL, radius: int = 18) -> str:
    """Create an SVG rounded panel."""
    return f'<rect x="{x}" y="{y}" width="{width}" height="{height}" rx="{radius}" fill="{color}"/>'


def svg_document(title: str, description: str, height: int, shapes: list[str]) -> str:
    """Wrap a diagram in accessible, self-contained SVG markup."""
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="1440" height="{height}" '
            f'viewBox="0 0 1440 {height}" role="img" aria-labelledby="title description">'
            f'<title id="title">{escape(title)}</title><desc id="description">{escape(description)}</desc>'
            f'{rect(0, 0, 1440, height, BACKGROUND, 0)}' + "".join(shapes) + "</svg>\n")


def quickstart_svg() -> str:
    """Explain the actual standalone executable workflow with precise commands."""
    shapes = [text(64, 82, "KeyGuard", 48, weight=700),
              text(64, 129, "From a first scan to an evidence report", 28, MUTED),
              rect(1070, 48, 306, 44, "#15382f", 22),
              text(1092, 78, "READ-ONLY / WINDOWS", 19, TEAL, 700),
              text(64, 188, "Extract the Windows artifact ZIP. Open PowerShell in the folder containing keyguard.exe.", 23, MUTED)]
    cards = [
        (64, "01", "Scan", [r".\keyguard.exe scan"],
         ["See Medium and High processes.", "Use scan --all to include Low."]),
        (510, "02", "Inspect", [r".\keyguard.exe inspect 4242"],
         ["Read reasons and coverage notes.", "Use a PID from your own scan."]),
        (956, "03", "Export", [r".\keyguard.exe export --html `", "--output report.html"],
         ["Save a fresh, complete scan.", "Open the HTML file locally."]),
    ]
    for x, number, title, commands, descriptions in cards:
        shapes.extend([rect(x, 228, 420, 314), text(x + 24, 276, number, 23, TEAL, 700),
                       text(x + 24, 322, title, 34, weight=700)])
        for index, command in enumerate(commands):
            shapes.append(text(x + 24, 375 + index * 28, command, 20, TEAL, mono=True))
        for index, description in enumerate(descriptions):
            shapes.append(text(x + 24, 472 + index * 30, description, 21, MUTED))
    shapes.append(text(64, 604, "Read the score as a triage priority", 28, weight=700))
    for x, label, color in [(64, "0-29  LOW", "#64e3c4"), (510, "30-59  MEDIUM", "#ffd17d"),
                             (956, "60-100  HIGH", "#ff9b9b")]:
        shapes.extend([rect(x, 632, 420, 72), text(x + 24, 678, label, 25, color, 700)])
    shapes.extend([text(64, 752, "High is a reason to investigate. Low with missing evidence does not establish safety.", 23, MUTED),
                   text(64, 795, "Coverage limited? Run as administrator when appropriate. KeyGuard never elevates itself.", 22, MUTED),
                   text(64, 850, "No keystroke capture. No injection. No process-control actions.", 24, TEAL, 700)])
    return svg_document("KeyGuard visual quick start",
                        "Scan, inspect a PID from your results, and export HTML. Scores are heuristic. Read coverage notes.",
                        900, shapes)


def architecture_svg() -> str:
    """Illustrate observed metadata, explicit trust policy, and scored output."""
    shapes = [text(64, 82, "How KeyGuard reaches a risk score", 44, weight=700),
              text(64, 130, "Read-only observations -> weighted evidence -> a report you can review", 27, MUTED),
              text(64, 203, "OBSERVE", 20, TEAL, 700),
              text(558, 203, "CORRELATE", 20, TEAL, 700),
              text(1030, 203, "REVIEW", 20, TEAL, 700)]
    sources = [
        (235, "Processes + windows", "Names, paths, age, parent, visibility"),
        (355, "On-disk executables", "PE imports + offline signature trust"),
        (475, "Startup definitions", "Run keys, folders, tasks, services"),
        (595, "TCP peers", "Established non-loopback connections"),
    ]
    for y, heading, body in sources:
        shapes.extend([rect(64, y, 430, 100), text(85, y + 37, heading, 25, weight=700),
                       text(85, y + 73, body, 19, MUTED)])
    shapes.extend([
        '<path d="M494 285H524 M494 405H524 M494 525H524 M494 645H524 M524 285V645 M524 325H558" '
        'fill="none" stroke="#5e819e" stroke-width="3"/>',
        '<path d="M548 318L558 325L548 332" fill="none" stroke="#5e819e" stroke-width="3"/>',
        rect(558, 235, 400, 180), text(582, 276, "One process snapshot", 28, weight=700),
        text(582, 323, "Join evidence by executable + PID", 20, MUTED),
        text(582, 359, "Keep findings and coverage gaps", 20, MUTED),
        text(582, 391, "No input or packet contents", 20, TEAL),
        rect(558, 445, 400, 130), text(582, 484, "Explicit policy", 28, weight=700),
        text(582, 523, "config.json: scoring weights*", 19, MUTED),
        text(582, 554, "Allowlist: verified rules / path + hash", 19, MUTED),
        '<path d="M758 415V445 M758 575V610 M958 650H994V465H1030" fill="none" stroke="#5e819e" stroke-width="3"/>',
        '<path d="M1020 458L1030 465L1020 472" fill="none" stroke="#5e819e" stroke-width="3"/>',
        rect(558, 610, 400, 85, "#15382f"), text(582, 645, "Deduplicate + apply weights", 20, TEAL, 700),
        text(582, 677, "Sum discounts + risk; clamp to 0-100", 19, MUTED),
        rect(1030, 235, 346, 460), text(1054, 282, "Explain the result", 27, weight=700),
        text(1054, 338, "Low / Medium / High", 23, TEAL, 700),
        text(1054, 387, "Human-readable reasons", 21, MUTED),
        text(1054, 432, "Coverage notes", 21, MUTED),
        text(1054, 496, "CLI: scan / inspect / watch", 20, MUTED),
        text(1054, 541, "Offline JSON / HTML", 21, MUTED),
        text(1054, 617, "A score is not proof", 24, TEAL, 700),
        text(1054, 654, "of keylogging.", 24, TEAL, 700),
        text(64, 757, "* Weights are configurable. Risk tiers stay fixed: Low 0-29 / Medium 30-59 / High 60-100.", 22, MUTED),
        text(64, 805, "User-mode coverage cannot establish the absence of kernel-level or rootkit keyloggers.", 22, MUTED),
    ])
    return svg_document("KeyGuard detection architecture",
                        "Metadata from processes, executable files, startup definitions and TCP peers is combined with scoring weights and allowlists into explainable reports.",
                        850, shapes)


def sample_report() -> ScanReport:
    """Construct invented process evidence using the real default scoring engine."""
    weights = load_config()["weights"]
    rows: list[ProcessReport] = []
    common = [Finding("keyboard_imports", "imports", "Imports GetAsyncKeyState"),
              Finding("unsigned", "signature", "No embedded Authenticode signature (catalog signatures not checked)"),
              Finding("suspicious_location", "location", "Executable runs from %TEMP%")]
    for pid, name, visible in [(4242, "demo-probe.exe", False), (4343, "demo-hotkeys.exe", True)]:
        process = ProcessSnapshot(pid, name, rf"C:\Users\Demo\AppData\Local\Temp\{name}",
                                  1000, 100.0, visible, "explorer.exe", r"C:\Windows\explorer.exe", 50.0)
        findings = list(common)
        if not visible:
            findings.extend([
                Finding("no_window", "location", "No visible top-level window in the current desktop/session"),
                Finding("background_keyboard", "behavior", "Keyboard API imports combined with no visible top-level window"),
            ])
        score, level, evidence = score_findings(findings, weights)
        rows.append(ProcessReport(process, score, level, evidence, [],
                                  {"keyboard_apis": ["GetAsyncKeyState"], "risky_locations": ["%TEMP%"]}))
    normal = ProcessSnapshot(4444, "demo-editor.exe", r"C:\Program Files\Demo\demo-editor.exe", 1000,
                             50.0, True, "explorer.exe", r"C:\Windows\explorer.exe", 1.0)
    rows.append(ProcessReport(normal, 0, "Low", [], [], {}))
    return ScanReport("Synthetic example / invented process records", False, rows, [], [
        "Reduced coverage: Run as administrator to inspect more protected processes, connections, and persistence entries.",
        "Window visibility covers only the current desktop/session; no visible window is weak evidence.",
    ])


def terminal_svgs(destination: Path) -> None:
    """Render actual CLI table/findings with clear labels and no real process data."""
    report = sample_report()
    console = Console(record=True, file=io.StringIO(), width=132, force_terminal=True,
                      color_system="truecolor", highlight=False)
    console.print("SYNTHETIC EXAMPLE / invented processes and paths", style="bold yellow")
    console.print("PS> keyguard scan", style="bold cyan")
    console.print()
    show_scan(report, console)
    (destination / "scan-example.svg").write_text(console.export_svg(
        title="KeyGuard / scan / synthetic example", code_format=TERMINAL_TEMPLATE,
        unique_id="keyguard-scan"), encoding="utf-8")
    original = Console(record=True, file=io.StringIO(), width=110, color_system=None, highlight=False)
    show_process(report.processes[0], original)
    lines = original.export_text().splitlines()
    excerpt = lines[:lines.index("{")]
    console = Console(record=True, file=io.StringIO(), width=110, force_terminal=True,
                      color_system="truecolor", highlight=False)
    console.print("SYNTHETIC EXAMPLE / findings excerpt / invented process", style="bold yellow")
    console.print("PS> keyguard inspect 4242", style="bold cyan")
    console.print()
    console.print("\n".join(excerpt), markup=False)
    console.print()
    console.print("The full command continues with JSON observations and global coverage notes.", style="dim")
    console.print("Review evidence and coverage. A High score is not proof of keylogging.", style="bold yellow")
    (destination / "inspect-example.svg").write_text(console.export_svg(
        title="KeyGuard / inspect / synthetic excerpt", code_format=TERMINAL_TEMPLATE,
        unique_id="keyguard-inspect"), encoding="utf-8")


def main() -> int:
    """Generate four SVGs and optionally rasterize them with a local Inkscape CLI."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--png", action="store_true", help="Also render PNGs using Inkscape")
    args = parser.parse_args()
    destination = Path(__file__).resolve().parent / "images"
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "quickstart.svg").write_text(quickstart_svg(), encoding="utf-8")
    (destination / "architecture.svg").write_text(architecture_svg(), encoding="utf-8")
    terminal_svgs(destination)
    if args.png:
        inkscape = shutil.which("inkscape")
        if not inkscape:
            parser.error("Inkscape is required for --png; SVGs have already been generated")
        for path in sorted(destination.glob("*.svg")):
            subprocess.run([inkscape, str(path), "--export-type=png", "--export-width=1800",
                            f"--export-filename={path.with_suffix('.png')}"], check=True)
    print(f"Documentation images written to {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
