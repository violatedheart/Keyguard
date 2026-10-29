"""Offline report export with HTML escaping and no external assets."""

import html
import json
from pathlib import Path
from typing import Any

from keyguard.models import ScanReport


def render_html(report: ScanReport) -> str:
    """Render a self-contained report and escape every untrusted system string."""
    rows: list[str] = []

    def escape(value: Any) -> str:
        """Escape data for HTML text and attribute contexts."""
        return html.escape(str(value), quote=True)

    for process in report.processes:
        reasons = "".join(f"<li>{escape(reason)} (weight {finding['weight']:+d})</li>"
                          for finding in process.findings for reason in finding["reasons"])
        issues = "".join(f"<li>{escape(issue)}</li>" for issue in process.issues)
        rows.append(f"<tr><td>{process.process.pid}</td><td>{escape(process.process.name)}<br>"
                    f"<small>{escape(process.process.exe)}</small></td><td>{process.score} {process.level}</td>"
                    f"<td><ul>{reasons}</ul><details><summary>Coverage issues</summary><ul>{issues}</ul></details></td></tr>")
    global_issues = "".join(f"<li>{escape(issue)}</li>" for issue in report.issues)
    raw = escape(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>KeyGuard report</title><style>
body{{font:16px system-ui,sans-serif;max-width:1200px;margin:2rem auto;padding:0 1rem;background:#101827;color:#e8eef8}}
table{{border-collapse:collapse;width:100%}}td,th{{padding:.8rem;text-align:left;border-bottom:1px solid #526070;vertical-align:top}}
small,pre{{overflow-wrap:anywhere;white-space:pre-wrap}}summary{{cursor:pointer}}li{{margin:.3rem 0}}
</style></head><body><h1>KeyGuard risk report</h1><p>{escape(report.generated_at)} | version {escape(report.version)}</p>
<p>Read-only heuristic triage. A score is not proof of a keylogger. Low scores with coverage gaps do not establish safety.</p>
<ul>{global_issues}</ul><table><thead><tr><th>PID</th><th>Process</th><th>Risk</th><th>Reasons</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<details><summary>Complete evidence, persistence entries, and coverage</summary><pre>{raw}</pre></details>
</body></html>"""


def export_report(report: ScanReport, destination: Path, format_name: str) -> None:
    """Create a new report file; refuse implicit overwrites of existing files."""
    if format_name == "json":
        content = json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n"
    elif format_name == "html":
        content = render_html(report)
    else:
        raise ValueError(f"Unknown report format: {format_name}")
    with destination.open("x", encoding="utf-8") as stream:
        stream.write(content)
