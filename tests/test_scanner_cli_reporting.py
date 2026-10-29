"""Full mocked scan pipeline, exports, watch identity, and CLI commands."""

import io
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from rich.console import Console

from keyguard import cli, scanner
from keyguard.models import Detection, Finding, ProcessReport, ProcessSnapshot, ScanReport, SignatureInfo
from keyguard.persistence import PersistenceEntry
from keyguard.reporting import export_report, render_html


@pytest.fixture
def mocked_scan(monkeypatch: pytest.MonkeyPatch, config: dict[str, Any], process: ProcessSnapshot) -> ScanReport:
    """Build a realistic High result using mocked OS collection boundaries."""
    monkeypatch.setattr(scanner, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(scanner, "is_administrator", MagicMock(return_value=False))
    monkeypatch.setattr(scanner, "shell_folders", MagicMock(return_value=({}, [])))
    monkeypatch.setattr(scanner, "risk_roots", MagicMock(return_value={"%TEMP%": r"C:\Users\Tester\Temp"}))
    monkeypatch.setattr(scanner, "visible_processes", MagicMock(return_value=(set(), [])))
    monkeypatch.setattr(scanner, "snapshot_processes", MagicMock(return_value=([process], {})))
    monkeypatch.setattr(scanner, "collect_connections", MagicMock(return_value=({401: [{"remote": ["192.0.2.10", 443]}]}, [])))
    entry = PersistenceEntry("registry", "Probe", process.exe, [process.exe], ["%TEMP%"])
    monkeypatch.setattr(scanner, "collect_persistence", MagicMock(return_value=([entry], [])))
    monkeypatch.setattr(scanner, "file_identity", MagicMock(return_value=(process.exe, 10, 20)))
    monkeypatch.setattr(scanner.Scanner, "signature", MagicMock(return_value=SignatureInfo("unsigned")))
    monkeypatch.setattr(scanner.Scanner, "imports", MagicMock(return_value=Detection(
        [Finding("keyboard_imports", "imports", "Imports GetAsyncKeyState")], data={"keyboard_apis": ["GetAsyncKeyState"]})))
    alive = SimpleNamespace(create_time=MagicMock(return_value=process.create_time), is_running=MagicMock(return_value=True))
    monkeypatch.setattr(scanner.psutil, "Process", MagicMock(return_value=alive))
    return scanner.Scanner(config, {"entries": []}).scan()


def test_pipeline(mocked_scan: ScanReport) -> None:
    """Combine independent module signals and preserve admin coverage notes."""
    row = mocked_scan.processes[0]
    assert row.level == "High" and row.score == 100
    assert row.observations["keyboard_apis"] == ["GetAsyncKeyState"]
    assert row.observations["connections"]
    assert any("administrator" in issue for issue in mocked_scan.issues)
    assert mocked_scan.to_dict()["processes"][0]["process"]["pid"] == 401
    assert mocked_scan.processes[0].observations["modules"][0]["score"] == 18


def test_file_change_withholds_discounts(mocked_scan: ScanReport, config: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    """A file replacement cannot retain a stale Microsoft or allowlist discount."""
    monkeypatch.setattr(scanner.Scanner, "signature", MagicMock(return_value=SignatureInfo("valid", "Microsoft Corporation")))
    monkeypatch.setattr(scanner, "file_identity", MagicMock(side_effect=[("file", 10, 1), ("file", 10, 2)]))
    report = scanner.Scanner(config, {"entries": []}).scan()
    row = report.processes[0]
    assert row.observations["trust_discounts_withheld"]
    assert "microsoft_signed" not in {finding["code"] for finding in row.findings}
    assert "keyboard_network" in {finding["code"] for finding in row.findings}


def test_exports_escape_and_no_overwrite(tmp_path: Path, mocked_scan: ScanReport) -> None:
    """Escape hostile process strings in HTML and refuse accidental overwrites."""
    mocked_scan.processes[0].issues.append('<script>alert("unsafe")</script>')
    rendered = render_html(mocked_scan)
    assert "<script>" not in rendered and "&lt;script&gt;" in rendered
    assert "Content-Security-Policy" in rendered
    path = tmp_path / "report.json"
    export_report(mocked_scan, path, "json")
    assert json.loads(path.read_text(encoding="utf-8"))["schema_version"] == 1
    with pytest.raises(FileExistsError):
        export_report(mocked_scan, path, "json")
    export_report(mocked_scan, tmp_path / "report.html", "html")


def test_watch_identity(mocked_scan: ScanReport) -> None:
    """Do not repeat High alerts; a reused PID with a different start time is new."""
    alerts, seen = cli.new_high_items(mocked_scan, set())
    assert len(alerts) == 1
    assert not cli.new_high_items(mocked_scan, seen)[0]
    assert cli.new_high_items(mocked_scan, {(401, 900.0)})[0]
    row = mocked_scan.processes[0]
    row.level = "Low"
    assert cli.new_high_items(mocked_scan, seen)[1] == set()
    row.level = "High"
    assert cli.new_high_items(mocked_scan, set())[0]


@pytest.mark.parametrize("arguments", [["scan"], ["scan", "--all"], ["inspect", "401"]])
def test_cli_display(arguments: list[str], mocked_scan: ScanReport, monkeypatch: pytest.MonkeyPatch) -> None:
    """Dispatch the documented read-only commands through the same report object."""
    monkeypatch.setattr(cli.Scanner, "scan", MagicMock(return_value=mocked_scan))
    assert cli.main(arguments) == 0


def test_cli_export(tmp_path: Path, mocked_scan: ScanReport, monkeypatch: pytest.MonkeyPatch) -> None:
    """The export CLI performs a fresh scan and writes the selected format."""
    monkeypatch.setattr(cli.Scanner, "scan", MagicMock(return_value=mocked_scan))
    path = tmp_path / "scan.json"
    assert cli.main(["export", "--json", "--output", str(path)]) == 0
    assert path.exists()


def test_watch_stop(mocked_scan: ScanReport, monkeypatch: pytest.MonkeyPatch) -> None:
    """A watch cycle reports High alerts and can be interrupted without process actions."""
    engine = MagicMock()
    engine.scan.side_effect = [mocked_scan, KeyboardInterrupt()]
    monkeypatch.setattr(cli.time, "sleep", MagicMock())
    output = io.StringIO()
    with pytest.raises(KeyboardInterrupt):
        cli.watch(engine, Console(file=output, width=120), 30)
    assert "ALERT: new High item" in output.getvalue()


def test_snapshot_access_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    """Missing process attributes are reported while accessible processes remain usable."""
    fake = SimpleNamespace(pid=99, info={"name": "protected.exe", "exe": None, "ppid": 0, "create_time": None})
    monkeypatch.setattr(scanner.psutil, "process_iter", MagicMock(return_value=[fake]))
    snapshots, issues = scanner.snapshot_processes(None)
    assert snapshots[0].exe == "" and snapshots[0].visible_window is None
    assert issues[99]


def test_import_cache_cleared_between_versions(tmp_path: Path, config: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    """Repeated processes share parsing, while changed files get a fresh result."""
    path = tmp_path / "probe.exe"
    path.write_bytes(b"MZ")
    analyze = MagicMock(return_value=Detection(data={"keyboard_apis": []}))
    monkeypatch.setattr(scanner, "analyze_imports", analyze)
    engine = scanner.Scanner(config, {"entries": []})
    engine.imports(str(path))
    engine.imports(str(path))
    assert analyze.call_count == 1
    path.write_bytes(b"MZchanged")
    engine.imports(str(path))
    assert analyze.call_count == 2


def test_low_is_hidden_by_default(normal_process: ProcessSnapshot) -> None:
    """Default display filters Low rows while --all includes them."""
    row = ProcessReport(normal_process, 0, "Low", [], [], {})
    report = ScanReport("test", False, [row], [], [])
    output = io.StringIO()
    cli.show_scan(report, Console(file=output), False)
    assert "editor.exe" not in output.getvalue()
    output = io.StringIO()
    cli.show_scan(report, Console(file=output), True)
    assert "editor.exe" in output.getvalue()
