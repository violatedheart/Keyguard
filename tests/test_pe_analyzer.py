"""Mock PE parsing, including delayed imports and unreadable executables."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pefile
import pytest

from keyguard.pe_analyzer import analyze_imports


def test_normal_and_delay_imports(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Find target APIs in both tables and close the PE object after parsing."""
    path = tmp_path / "sample.exe"
    path.write_bytes(b"MZ")
    pe = MagicMock()
    pe.DIRECTORY_ENTRY_IMPORT = [SimpleNamespace(imports=[SimpleNamespace(name=b"GetAsyncKeyState"),
                                                        SimpleNamespace(name=None)])]
    pe.DIRECTORY_ENTRY_DELAY_IMPORT = [SimpleNamespace(imports=[SimpleNamespace(name=b"SetWindowsHookExW"),
                                                              SimpleNamespace(name=b"Sleep")])]
    monkeypatch.setattr(pefile, "PE", MagicMock(return_value=pe))
    result = analyze_imports(str(path), 1024)
    assert result.data["keyboard_apis"] == ["GetAsyncKeyState", "SetWindowsHookExW"]
    assert result.findings[0].code == "keyboard_imports"
    pe.close.assert_called_once()


@pytest.mark.parametrize("error", [PermissionError("denied"), pefile.PEFormatError("bad PE")])
def test_parse_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: Exception) -> None:
    """Unreadable or malformed images become coverage issues rather than safe evidence."""
    path = tmp_path / "bad.exe"
    path.write_bytes(b"MZ")
    monkeypatch.setattr(pefile, "PE", MagicMock(side_effect=error))
    result = analyze_imports(str(path), 1024)
    assert result.issues and not result.findings


def test_size_limit(tmp_path: Path) -> None:
    """Skip oversized files without attempting PE parsing."""
    path = tmp_path / "large.exe"
    path.write_bytes(b"123")
    assert "exceeds" in analyze_imports(str(path), 2).issues[0]
