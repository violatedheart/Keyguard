"""Read startup registry keys, folders, scheduled tasks, and service definitions."""

import ntpath
import os
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import psutil

from keyguard.models import Detection, Finding, SignatureInfo
from keyguard.paths import canonical, command_targets, expand_path, suspicious_paths
from keyguard.signature import is_microsoft


@dataclass
class PersistenceEntry:
    """A startup command, including offline/unmatched suspicious entries."""

    kind: str
    name: str
    command: str
    targets: list[str] = field(default_factory=list)
    risky_locations: list[str] = field(default_factory=list)
    non_microsoft: bool = False
    signature_status: str = "not_checked"


def registry_entries() -> tuple[list[PersistenceEntry], list[str]]:
    """Enumerate current-user and machine Run/RunOnce in both registry views."""
    import winreg
    entries: list[PersistenceEntry] = []
    issues: list[str] = []
    for hive, label in ((winreg.HKEY_CURRENT_USER, "HKCU"), (winreg.HKEY_LOCAL_MACHINE, "HKLM")):
        for view, view_label in ((winreg.KEY_WOW64_64KEY, "64"), (winreg.KEY_WOW64_32KEY, "32")):
            for suffix in ("Run", "RunOnce"):
                subkey = rf"Software\Microsoft\Windows\CurrentVersion\{suffix}"
                try:
                    with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | view) as key:
                        count = winreg.QueryInfoKey(key)[1]
                        for index in range(count):
                            name, value, kind = winreg.EnumValue(key, index)
                            if kind in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) and isinstance(value, str):
                                entries.append(PersistenceEntry("registry", f"{label}/{view_label}/{suffix}/{name}", value))
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    issues.append(f"Registry {label}/{view_label}/{suffix}: {exc}")
    return entries, issues


def startup_entries(folders: Mapping[str, str]) -> tuple[list[PersistenceEntry], list[str]]:
    """Resolve existing Startup shortcuts without saving or invoking their targets."""
    entries: list[PersistenceEntry] = []
    issues: list[str] = []
    roots = dict(folders)
    if not roots.get("Startup") and os.environ.get("APPDATA"):
        roots["Startup"] = ntpath.join(os.environ["APPDATA"], "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
    if not roots.get("CommonStartup") and os.environ.get("ProgramData"):
        roots["CommonStartup"] = ntpath.join(os.environ["ProgramData"], "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
    shell = None
    for label in ("Startup", "CommonStartup"):
        if not roots.get(label):
            issues.append(f"Cannot discover {label} folder")
            continue
        directory = Path(roots[label])
        try:
            if not directory.exists():
                continue
            for item in directory.iterdir():
                if not item.is_file() or item.name.casefold() == "desktop.ini":
                    continue
                try:
                    if item.suffix.casefold() == ".lnk":
                        if shell is None:
                            import win32com.client
                            shell = win32com.client.Dispatch("WScript.Shell")
                        shortcut = shell.CreateShortcut(str(item))
                        target = shortcut.TargetPath
                        command = f'"{target}" {shortcut.Arguments}'
                    else:
                        command = f'"{item}"'
                    entries.append(PersistenceEntry("startup", f"{label}/{item.name}", command))
                except Exception as exc:
                    # COM error classes are unavailable on non-Windows test hosts.
                    issues.append(f"Startup item {item}: {exc}")
        except OSError as exc:
            issues.append(f"Startup folder {directory}: {exc}")
    return entries, issues


def task_entries() -> tuple[list[PersistenceEntry], list[str]]:
    """Read hidden and visible scheduled tasks recursively through the Task API."""
    import win32com.client
    entries: list[PersistenceEntry] = []
    issues: list[str] = []

    def walk(folder: Any) -> None:
        """Visit a task folder; retain partial results if access is denied."""
        try:
            for task in folder.GetTasks(1):  # TASK_ENUM_HIDDEN
                try:
                    for action in task.Definition.Actions:
                        if action.Type == 0:  # TASK_ACTION_EXEC
                            entries.append(PersistenceEntry("task", task.Path,
                                                            f'"{action.Path}" {action.Arguments}'))
                except Exception as exc:
                    issues.append(f"Task {task.Path}: {exc}")
        except Exception as exc:
            issues.append(f"Task enumeration: {exc}")
        try:
            for child in folder.GetFolders(0):
                walk(child)
        except Exception as exc:
            issues.append(f"Task folder traversal: {exc}")

    try:
        scheduler = win32com.client.Dispatch("Schedule.Service")
        scheduler.Connect()
        walk(scheduler.GetFolder("\\"))
    except Exception as exc:
        issues.append(f"Scheduled task coverage unavailable: {exc}")
    return entries, issues


def service_entries() -> tuple[list[PersistenceEntry], list[str]]:
    """Read services, including stopped services; never start or modify them."""
    entries: list[PersistenceEntry] = []
    issues: list[str] = []
    try:
        for service in psutil.win_service_iter():
            try:
                info = service.as_dict()
                entries.append(PersistenceEntry("service", info["name"], info.get("binpath", "")))
            except (psutil.Error, OSError) as exc:
                issues.append(f"Service metadata unavailable: {exc}")
    except (psutil.Error, OSError) as exc:
        issues.append(f"Service enumeration unavailable: {exc}")
    return entries, issues


def collect_persistence(folders: Mapping[str, str], roots: Mapping[str, str],
                        verify: Callable[[str], SignatureInfo]) -> tuple[list[PersistenceEntry], list[str]]:
    """Collect and annotate all sources once; authenticate service publishers."""
    entries: list[PersistenceEntry] = []
    issues: list[str] = []
    for collector in (registry_entries, lambda: startup_entries(folders), task_entries, service_entries):
        try:
            batch, errors = collector()
            entries.extend(batch)
            issues.extend(errors)
        except Exception as exc:
            issues.append(f"Persistence source unavailable: {exc}")
    for entry in entries:
        entry.targets = command_targets(entry.command)
        entry.risky_locations = sorted({label for path in entry.targets for label in suspicious_paths(path, roots)})
        if not entry.targets:
            issues.append(f"Unresolved persistence command: {entry.kind}/{entry.name}")
        if entry.kind == "service" and entry.targets:
            info = verify(expand_path(entry.targets[0]))
            entry.signature_status = info.status
            entry.non_microsoft = info.status in {"valid", "unsigned", "invalid"} and not is_microsoft(info)
            if info.status == "unknown":
                issues.append(f"Service publisher unknown: {entry.name}: {info.detail}")
    return entries, issues


def analyze_persistence(executable: str, entries: list[PersistenceEntry]) -> Detection:
    """Associate exact paths with running processes, preserving each source reason."""
    matches = [entry for entry in entries if executable and
               any(canonical(path) == canonical(executable) for path in entry.targets)]
    result = Detection(data={"persistence": [asdict(entry) for entry in matches]})
    for entry in matches:
        if entry.risky_locations:
            result.findings.append(Finding("persistence_suspicious", "persistence",
                                           f"{entry.kind} persistence {entry.name} references {', '.join(entry.risky_locations)}"))
        if entry.kind == "service" and entry.non_microsoft:
            result.findings.append(Finding("non_microsoft_service", "persistence",
                                           f"Service {entry.name} executable is not verified as Microsoft-signed (embedded signature: {entry.signature_status})"))
    return result
