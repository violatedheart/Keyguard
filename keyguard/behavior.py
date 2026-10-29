"""Conservative name, start-time, background, and parent heuristics."""

import ntpath
import os
from difflib import SequenceMatcher

from keyguard.models import Detection, Finding, ProcessSnapshot
from keyguard.paths import canonical

SYSTEM_NAMES = frozenset({"svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe",
                          "services.exe", "smss.exe", "spoolsv.exe", "explorer.exe"})
EXPECTED_PARENTS = {
    "svchost.exe": {"services.exe"}, "lsass.exe": {"wininit.exe"},
    "services.exe": {"wininit.exe"}, "spoolsv.exe": {"services.exe"},
}
SCRIPT_PARENTS = frozenset({"powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
                            "mshta.exe", "winword.exe", "excel.exe", "outlook.exe"})


def analyze_behavior(process: ProcessSnapshot, keyboard: bool, risky_location: bool,
                     now: float, recent_seconds: int) -> Detection:
    """Emit contextual signals without assuming every service or new process is bad."""
    result = Detection()
    name = process.name.casefold()
    if name not in SYSTEM_NAMES:
        substitutions = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s"})
        lookalike = name.translate(substitutions)
        matches = [known for known in SYSTEM_NAMES if lookalike == known or
                   SequenceMatcher(None, name, known).ratio() >= 0.88]
        if matches:
            result.findings.append(Finding("system_name_mimic", "behavior",
                                           f"Name {process.name} resembles {', '.join(sorted(matches))}"))
    system_root = os.environ.get("SystemRoot", "")
    if name in SYSTEM_NAMES and process.exe and system_root:
        expected = [ntpath.join(system_root, "System32"), ntpath.join(system_root, "SysWOW64")]
        valid_path = any(canonical(process.exe) == canonical(ntpath.join(root, name)) for root in expected)
        if name == "explorer.exe":
            valid_path = canonical(process.exe) == canonical(ntpath.join(system_root, "explorer.exe"))
        if not valid_path:
            result.findings.append(Finding("system_wrong_path", "behavior",
                                           f"System process name {process.name} outside expected Windows directory"))
    if process.create_time is not None and 0 <= now - process.create_time <= recent_seconds:
        result.findings.append(Finding("recent_process", "behavior",
                                       f"Process started within the last {recent_seconds} seconds"))
    if keyboard and process.visible_window is False:
        result.findings.append(Finding("background_keyboard", "behavior",
                                       "Keyboard API imports combined with no visible top-level window"))
    parent = process.parent_name.casefold()
    # Parent identity is useful only if its creation time predates the child's.
    parent_reliable = (process.create_time is not None and process.parent_create_time is not None
                       and process.parent_create_time <= process.create_time)
    if parent_reliable:
        if name in EXPECTED_PARENTS and parent not in EXPECTED_PARENTS[name]:
            result.findings.append(Finding("odd_parent", "behavior",
                                           f"Unexpected parent {process.parent_name} for {process.name}"))
        elif keyboard and risky_location and parent in SCRIPT_PARENTS:
            result.findings.append(Finding("odd_parent", "behavior",
                                           f"Keyboard-capable executable in risky location launched by {process.parent_name}"))
    elif process.ppid:
        result.issues.append("Parent identity unavailable or parent PID reused; parent heuristic skipped")
    return result
