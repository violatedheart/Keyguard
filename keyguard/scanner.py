"""Orchestrate independent read-only collectors and join evidence by process."""

import os
import time
from dataclasses import asdict, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil

from keyguard.allowlist import analyze_allowlist
from keyguard.behavior import analyze_behavior
from keyguard.location import analyze_location
from keyguard.models import Detection, ProcessReport, ProcessSnapshot, ScanReport, SignatureInfo
from keyguard.network import analyze_network, collect_connections
from keyguard.paths import canonical, risk_roots, shell_folders
from keyguard.pe_analyzer import analyze_imports
from keyguard.persistence import analyze_persistence, collect_persistence
from keyguard.scoring import score_findings
from keyguard.signature import analyze_signature, is_microsoft, verify_signature


def is_administrator() -> bool:
    """Check elevation through a query-only process token; never request elevation."""
    if os.name != "nt":
        return False
    import win32api
    import win32con
    import win32security
    try:
        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
        try:
            return bool(win32security.GetTokenInformation(token, win32security.TokenElevation))
        finally:
            token.Close()
    except Exception:
        return False


def visible_processes() -> tuple[set[int] | None, list[str]]:
    """Enumerate visible top-level windows in the calling desktop/session only."""
    import win32gui
    import win32process
    visible: set[int] = set()
    issues: list[str] = []

    def visit(hwnd: int, unused: Any) -> bool:
        """Record visible window owner PIDs without reading window contents."""
        try:
            if win32gui.IsWindowVisible(hwnd):
                visible.add(win32process.GetWindowThreadProcessId(hwnd)[1])
        except Exception as exc:
            issues.append(f"Window owner lookup failed: {exc}")
        return True

    try:
        win32gui.EnumWindows(visit, None)
    except Exception as exc:
        return None, [f"Window enumeration unavailable: {exc}"]
    return (None if issues else visible), issues


def snapshot_processes(visible: set[int] | None) -> tuple[list[ProcessSnapshot], dict[int, list[str]]]:
    """Read process metadata and avoid trusting parent PIDs that have been reused."""
    snapshots: list[ProcessSnapshot] = []
    issues: dict[int, list[str]] = {}
    attrs = ["pid", "name", "exe", "ppid", "create_time"]
    try:
        for process in psutil.process_iter(attrs=attrs, ad_value=None):
            info = process.info
            pid = process.pid
            row = ProcessSnapshot(pid, info.get("name") or f"PID {pid}", info.get("exe") or "",
                                  info.get("ppid") or 0, info.get("create_time"),
                                  None if visible is None else pid in visible)
            snapshots.append(row)
            if not row.exe:
                issues.setdefault(pid, []).append("Executable path unavailable (protected process, exited process, or access denied)")
            if row.create_time is None:
                issues.setdefault(pid, []).append("Process creation time unavailable")
    except (psutil.Error, OSError) as exc:
        issues.setdefault(-1, []).append(f"Process enumeration incomplete: {exc}")
    by_pid = {row.pid: row for row in snapshots}
    for index, row in enumerate(snapshots):
        parent = by_pid.get(row.ppid)
        if parent:
            snapshots[index] = replace(row, parent_name=parent.name, parent_exe=parent.exe,
                                       parent_create_time=parent.create_time)
    return snapshots, issues


def file_identity(path: str) -> tuple[str, int, int]:
    """Create a scan-local cache key and allow detection of common file replacements."""
    stat = Path(path).stat()
    return canonical(path), stat.st_size, stat.st_mtime_ns


class Scanner:
    """Collect a fresh snapshot each scan; caches never persist across watch cycles."""

    def __init__(self, config: dict[str, Any], allowlist: dict[str, Any]) -> None:
        """Keep validated configuration and user rules without changing the system."""
        self.config = config
        self.allowlist = allowlist
        self._signatures: dict[tuple[str, int, int], SignatureInfo] = {}
        self._imports: dict[tuple[str, int, int], Detection] = {}

    def signature(self, path: str) -> SignatureInfo:
        """Verify each on-disk executable version at most once per scan."""
        try:
            key = file_identity(path)
            if key not in self._signatures:
                self._signatures[key] = verify_signature(path)
            return self._signatures[key]
        except OSError as exc:
            return SignatureInfo(detail=f"Cannot access executable: {exc}")

    def imports(self, path: str) -> Detection:
        """Cache import parsing while retaining all coverage errors."""
        try:
            key = file_identity(path)
            if key not in self._imports:
                self._imports[key] = analyze_imports(path, self.config["max_pe_bytes"])
            return self._imports[key]
        except OSError as exc:
            return Detection(issues=[f"Cannot read executable imports: {exc}"], data={"keyboard_apis": []})

    def scan(self, pid: int | None = None) -> ScanReport:
        """Scan Windows metadata only; optionally return one selected process."""
        if os.name != "nt":
            raise RuntimeError("Live scanning requires Windows 10/11. Mocked unit tests can run on other platforms.")
        self._signatures.clear()
        self._imports.clear()
        now = time.time()
        admin = is_administrator()
        issues: list[str] = ["Window visibility covers only the current desktop/session; no visible window is weak evidence."]
        if not admin:
            issues.append("Reduced coverage: Run as administrator to inspect more protected processes, connections, and persistence entries.")
        folders, errors = shell_folders()
        issues.extend(errors)
        roots = risk_roots(folders)
        visible, errors = visible_processes()
        issues.extend(errors)
        snapshots, snapshot_issues = snapshot_processes(visible)
        issues.extend(snapshot_issues.pop(-1, []))
        connections, errors = collect_connections()
        issues.extend(errors)
        entries, errors = collect_persistence(folders, roots, self.signature)
        issues.extend(errors)
        if pid is not None:
            snapshots = [row for row in snapshots if row.pid == pid]
            if not snapshots:
                raise LookupError(f"PID {pid} was not present in the process snapshot")
        reports: list[ProcessReport] = []
        for row in snapshots:
            row_issues = list(snapshot_issues.get(row.pid, []))
            modules: list[Detection] = []
            signature = SignatureInfo(detail="Executable path unavailable")
            imports = Detection(data={"keyboard_apis": []})
            allowed = Detection(data={"allowlisted": False})
            before = None
            if row.exe:
                try:
                    before = file_identity(row.exe)
                except OSError as exc:
                    row_issues.append(f"Executable inaccessible: {exc}")
                imports = self.imports(row.exe)
                signature = self.signature(row.exe)
                allowed = analyze_allowlist(row.exe, signature, self.allowlist)
                modules.extend([imports, analyze_signature(signature, self.config["trusted_publishers"]), allowed])
            location = analyze_location(row, roots)
            keyboard = bool(imports.data.get("keyboard_apis"))
            known = (bool(allowed.data["allowlisted"]) or is_microsoft(signature) or
                     (signature.status == "valid" and bool(signature.publisher) and signature.publisher.casefold()
                      in {publisher.casefold() for publisher in self.config["trusted_publishers"]}))
            modules.extend([
                location,
                analyze_persistence(row.exe, entries),
                analyze_network(connections.get(row.pid, []), keyboard, known),
                analyze_behavior(row, keyboard, bool(location.data["risky_locations"]), now, self.config["recent_seconds"]),
            ])
            observations: dict[str, Any] = {}
            findings = []
            module_scores = []
            for module in modules:
                findings.extend(module.findings)
                row_issues.extend(module.issues)
                observations.update(module.data)
                module_scores.append(module.scored(self.config["weights"]))
            observations["modules"] = module_scores
            if before is not None:
                file_changed = False
                try:
                    if file_identity(row.exe) != before:
                        file_changed = True
                        row_issues.append("Executable changed during scan; file-based evidence may be inconsistent; rescan")
                except OSError as exc:
                    file_changed = True
                    row_issues.append(f"Executable disappeared during scan: {exc}")
                if file_changed:
                    findings = [finding for finding in findings if self.config["weights"][finding.code] >= 0]
                    findings.extend(analyze_network(connections.get(row.pid, []), keyboard, False).findings)
                    observations["trust_discounts_withheld"] = True
                    row_issues.append("Trust and allowlist discounts withheld because the file changed or disappeared")
            try:
                current = psutil.Process(row.pid)
                if row.create_time is not None and current.create_time() != row.create_time:
                    row_issues.append("PID was reused during scan; observations describe the original snapshot")
                elif not current.is_running():
                    row_issues.append("Process exited during scan")
            except (psutil.Error, OSError) as exc:
                row_issues.append(f"Process identity recheck unavailable (may have exited): {exc}")
            score, level, scored = score_findings(findings, self.config["weights"])
            reports.append(ProcessReport(row, score, level, scored, list(dict.fromkeys(row_issues)), observations))
        reports.sort(key=lambda item: (-item.score, item.process.pid))
        return ScanReport(datetime.now(timezone.utc).isoformat(), admin, reports,
                          [asdict(entry) for entry in entries], list(dict.fromkeys(issues)))
