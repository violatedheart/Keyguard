"""Allowlist identity checks, content pinning, validation, and explicit writes."""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from keyguard import allowlist
from keyguard.models import SignatureInfo


def test_builtin_requires_publisher_and_root(monkeypatch: pytest.MonkeyPatch) -> None:
    """A familiar filename alone must not suppress risk."""
    monkeypatch.setenv("ProgramFiles", r"C:\Program Files")
    path = r"C:\Program Files\NVDA\nvda.exe"
    signed = SignatureInfo("valid", "NV Access Limited")
    empty = {"entries": []}
    assert allowlist.analyze_allowlist(path, signed, empty).data["allowlisted"]
    assert not allowlist.analyze_allowlist(r"C:\Temp\nvda.exe", signed, empty).data["allowlisted"]
    assert not allowlist.analyze_allowlist(path, SignatureInfo("unsigned", "NV Access Limited"), empty).data["allowlisted"]
    assert not allowlist.analyze_allowlist(path, SignatureInfo("valid", "NV Access Limited Evil"), empty).data["allowlisted"]


def test_user_hash_match_and_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    """A replaced executable loses its user exception."""
    path = r"C:\Tools\app.exe"
    data = {"entries": [{"path": path, "sha256": "a" * 64}]}
    monkeypatch.setattr(allowlist, "sha256_file", MagicMock(return_value="a" * 64))
    assert allowlist.analyze_allowlist(path, SignatureInfo(), data).data["allowlisted"]
    monkeypatch.setattr(allowlist, "sha256_file", MagicMock(return_value="b" * 64))
    result = allowlist.analyze_allowlist(path, SignatureInfo(), data)
    assert not result.data["allowlisted"] and "mismatch" in result.issues[0]


def test_add_entry_atomic(tmp_path: Path) -> None:
    """The explicit allow command persists the exact content digest."""
    executable = tmp_path / "app.exe"
    executable.write_bytes(b"benign test fixture")
    destination = tmp_path / "config" / "allowlist.json"
    entry = allowlist.add_user_entry(executable, destination)
    assert entry["sha256"] == allowlist.sha256_file(executable)
    assert allowlist.load_allowlist(destination)["entries"] == [entry]
    allowlist.add_user_entry(executable, destination)
    assert len(allowlist.load_allowlist(destination)["entries"]) == 1


def test_reject_broad_rule(tmp_path: Path) -> None:
    """Do not accept basename-only rules that a malicious process can impersonate."""
    path = tmp_path / "allowlist.json"
    path.write_text(json.dumps({"schema_version": 1, "entries": [{"path": "nvda.exe", "sha256": "a" * 64}]}), encoding="utf-8")
    with pytest.raises(ValueError, match="absolute"):
        allowlist.load_allowlist(path)
