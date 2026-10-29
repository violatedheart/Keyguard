"""Mock all persistence sources without changing registry, tasks, or services."""

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import psutil
import pytest

from keyguard import persistence
from keyguard.models import SignatureInfo


def test_registry_both_views(monkeypatch: pytest.MonkeyPatch) -> None:
    """Enumerate both hives, both views, and both startup key names read-only."""
    handle = MagicMock()
    handle.__enter__.return_value = handle
    fake = SimpleNamespace(HKEY_CURRENT_USER=1, HKEY_LOCAL_MACHINE=2,
                           KEY_WOW64_64KEY=256, KEY_WOW64_32KEY=512, KEY_READ=1,
                           REG_SZ=1, REG_EXPAND_SZ=2, OpenKey=MagicMock(return_value=handle),
                           QueryInfoKey=MagicMock(return_value=(0, 1, 0)),
                           EnumValue=MagicMock(return_value=("Probe", r'"C:\Temp\probe.exe"', 1)))
    monkeypatch.setitem(sys.modules, "winreg", fake)
    entries, issues = persistence.registry_entries()
    assert len(entries) == 8 and not issues
    assert fake.OpenKey.call_count == 8
    assert all(call.args[3] in (257, 513) for call in fake.OpenKey.call_args_list)
    fake.OpenKey.side_effect = PermissionError("denied")
    assert persistence.registry_entries()[1]


def install_com(monkeypatch: pytest.MonkeyPatch, dispatch: MagicMock) -> None:
    """Install a minimal mocked COM module hierarchy on any host OS."""
    client = SimpleNamespace(Dispatch=dispatch)
    monkeypatch.setitem(sys.modules, "win32com", SimpleNamespace(client=client))
    monkeypatch.setitem(sys.modules, "win32com.client", client)


def test_startup_shortcut(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Read shortcut targets without calling Save or executing the shortcut."""
    (tmp_path / "probe.lnk").write_bytes(b"test fixture")
    shell = MagicMock()
    shell.CreateShortcut.return_value = SimpleNamespace(TargetPath=r"C:\Temp\probe.exe", Arguments="--benign")
    install_com(monkeypatch, MagicMock(return_value=shell))
    entries, _ = persistence.startup_entries({"Startup": str(tmp_path), "CommonStartup": str(tmp_path / "absent")})
    assert len(entries) == 1 and "probe.exe" in entries[0].command
    shell.Save.assert_not_called()


def test_scheduled_tasks_recursive(monkeypatch: pytest.MonkeyPatch) -> None:
    """Include hidden tasks and nested folders while ignoring non-executable actions."""
    action = SimpleNamespace(Type=0, Path=r"C:\Temp\probe.exe", Arguments="--benign")
    task = SimpleNamespace(Path=r"\Example\Probe", Definition=SimpleNamespace(Actions=[action]))
    child = SimpleNamespace(GetTasks=MagicMock(return_value=[task]), GetFolders=MagicMock(return_value=[]))
    root = SimpleNamespace(GetTasks=MagicMock(return_value=[]), GetFolders=MagicMock(return_value=[child]))
    scheduler = MagicMock()
    scheduler.GetFolder.return_value = root
    install_com(monkeypatch, MagicMock(return_value=scheduler))
    entries, issues = persistence.task_entries()
    assert len(entries) == 1 and not issues
    child.GetTasks.assert_called_once_with(1)
    scheduler.GetFolder.side_effect = PermissionError("denied")
    assert persistence.task_entries()[1]


def test_services_and_join(monkeypatch: pytest.MonkeyPatch) -> None:
    """Annotate non-Microsoft services and retain unmatched risky startup commands."""
    service = SimpleNamespace(as_dict=MagicMock(return_value={"name": "Probe", "binpath": r'"C:\Temp\probe.exe"'}))
    monkeypatch.setattr(psutil, "win_service_iter", MagicMock(return_value=[service]), raising=False)
    monkeypatch.setattr(persistence, "registry_entries", MagicMock(return_value=([], [])))
    monkeypatch.setattr(persistence, "startup_entries", MagicMock(return_value=([], [])))
    monkeypatch.setattr(persistence, "task_entries", MagicMock(return_value=([
        persistence.PersistenceEntry("task", "offline", r'"C:\Temp\offline.exe"')], [])))
    entries, issues = persistence.collect_persistence({}, {"%TEMP%": r"C:\Temp"}, MagicMock(return_value=SignatureInfo("unsigned")))
    assert not issues and len(entries) == 2
    result = persistence.analyze_persistence(r"c:\temp\PROBE.exe", entries)
    assert {finding.code for finding in result.findings} == {"persistence_suspicious", "non_microsoft_service"}
    assert entries[0].risky_locations == ["%TEMP%"]  # The offline task is retained.


def test_service_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    """Service enumeration errors preserve reduced coverage."""
    monkeypatch.setattr(psutil, "win_service_iter", MagicMock(side_effect=psutil.AccessDenied()), raising=False)
    entries, issues = persistence.service_entries()
    assert not entries and issues
