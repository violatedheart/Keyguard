"""Mocked directory, name, background, recency, and parent signals."""

from dataclasses import replace

import pytest

from keyguard.behavior import analyze_behavior
from keyguard.location import analyze_location
from keyguard.models import ProcessSnapshot
from keyguard.paths import command_targets, expand_path, is_under, risk_roots


def test_directory_boundary_and_redirected_downloads() -> None:
    """Avoid prefix-only path matches and honor redirected Downloads."""
    assert is_under(r"C:\Temp\x.exe", r"C:\Temp")
    assert not is_under(r"C:\TempBackup\x.exe", r"C:\Temp")
    assert not is_under(r"D:\Temp\x.exe", r"C:\Temp")
    assert risk_roots({"Downloads": r"D:\Inbox"}, {}) == {"Downloads": r"D:\Inbox"}
    assert expand_path(r"%TEMP%\x.exe", {"TEMP": r"C:\Scratch"}) == r"C:\Scratch\x.exe"


@pytest.mark.parametrize(("command", "expected"), [
    ('"C:\\Program Files\\Tool\\tool.exe" --file "C:\\Temp\\input.py"', [r"C:\Program Files\Tool\tool.exe", r"C:\Temp\input.py"]),
    (r"C:\Program Files\Tool\tool.exe --silent", [r"C:\Program Files\Tool\tool.exe"]),
    (r"relative.exe --silent", []),
])
def test_command_targets(command: str, expected: list[str]) -> None:
    """Parse common startup forms without executing shell text."""
    assert command_targets(command) == expected


def test_location(process: ProcessSnapshot) -> None:
    """Return separate weak window and strong risky-directory findings."""
    result = analyze_location(process, {"%TEMP%": r"C:\Users\Tester\Temp"})
    assert {finding.code for finding in result.findings} == {"suspicious_location", "no_window"}
    assert analyze_location(replace(process, visible_window=None), {}).issues


def test_behavior_combination(process: ProcessSnapshot) -> None:
    """Exercise the documented svch0st and suspicious-parent examples."""
    result = analyze_behavior(process, True, True, 1000, 120)
    assert {finding.code for finding in result.findings} == {
        "system_name_mimic", "recent_process", "background_keyboard", "odd_parent"}


def test_normal_and_reused_parent(normal_process: ProcessSnapshot) -> None:
    """Avoid parent signals from a newer process that reused the parent PID."""
    assert not analyze_behavior(normal_process, False, False, 1000, 120).findings
    row = replace(normal_process, name="svchost.exe", parent_name="evil.exe", parent_create_time=999.0)
    result = analyze_behavior(row, False, False, 1000, 120)
    assert "odd_parent" not in {finding.code for finding in result.findings}
    assert result.issues


def test_system_wrong_path(process: ProcessSnapshot, monkeypatch: pytest.MonkeyPatch) -> None:
    """An exact system name in Temp must not bypass masquerading detection."""
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    result = analyze_behavior(replace(process, name="svchost.exe"), False, True, 1000, 120)
    assert "system_wrong_path" in {finding.code for finding in result.findings}
    row = replace(process, name="svchost.exe", exe=r"C:\Windows\System32\Temp\svchost.exe")
    assert "system_wrong_path" in {finding.code for finding in analyze_behavior(row, False, False, 1000, 120).findings}
