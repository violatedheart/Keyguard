"""Executable directory and visible-window signals."""

from collections.abc import Mapping

from keyguard.models import Detection, Finding, ProcessSnapshot
from keyguard.paths import suspicious_paths


def analyze_location(process: ProcessSnapshot, roots: Mapping[str, str]) -> Detection:
    """Treat background execution as weak evidence and missing coverage as unknown."""
    labels = suspicious_paths(process.exe, roots)
    result = Detection(data={"risky_locations": labels, "visible_window": process.visible_window})
    if labels:
        result.findings.append(Finding("suspicious_location", "location",
                                       "Executable runs from " + ", ".join(labels)))
    if process.visible_window is False:
        result.findings.append(Finding("no_window", "location", "No visible top-level window in the current desktop/session"))
    elif process.visible_window is None:
        result.issues.append("Visible-window enumeration unavailable for this process")
    return result
