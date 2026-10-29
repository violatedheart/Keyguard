"""Signature status interpretation and verified-publisher-only discounts."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from keyguard import signature
from keyguard.models import SignatureInfo


@pytest.mark.parametrize(("status", "expected"), [(0, "valid"), (0x800B0100, "unsigned"),
                                                   (0x80096010, "invalid"), (0x800B0109, "invalid"),
                                                   (0x80070005, "unknown"), (-2146762496, "unsigned")])
def test_status(status: int, expected: str) -> None:
    """Do not label access failures as an invalid or unsigned signature."""
    assert signature.classify_status(status) == expected


@pytest.mark.parametrize(("info", "code"), [
    (SignatureInfo("unsigned"), "unsigned"),
    (SignatureInfo("invalid", "Microsoft Corporation"), "invalid_signature"),
    (SignatureInfo("valid", "Microsoft Corporation"), "microsoft_signed"),
    (SignatureInfo("valid", "Microsoft Corporation Evil"), "valid_signature"),
    (SignatureInfo("valid", "Example Inc"), "trusted_publisher"),
])
def test_signature_signals(info: SignatureInfo, code: str) -> None:
    """Publisher strings give discounts only after a successful trust check."""
    result = signature.analyze_signature(info, ["Example Inc"])
    assert result.findings[0].code == code


def test_unknown_has_no_risk_finding() -> None:
    """Unknown trust stays visible as a coverage issue."""
    result = signature.analyze_signature(SignatureInfo(detail="access denied"), [])
    assert not result.findings and "access denied" in result.issues[0]


def test_native_state_is_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mock the Windows FFI boundary and verify provider-state cleanup."""
    actions: list[int] = []

    def verify(hwnd: object, action: object, data: object) -> int:
        """Simulate WinVerifyTrust allocating state then closing it."""
        record = data._obj  # type: ignore[attr-defined]
        actions.append(record.dwStateAction)
        record.hWVTStateData = 1234
        return 0

    native = MagicMock(side_effect=verify)
    monkeypatch.setattr(signature, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(signature.ctypes, "WinDLL", MagicMock(return_value=SimpleNamespace(WinVerifyTrust=native)), raising=False)
    monkeypatch.setattr(signature, "_verified_signer", MagicMock(return_value=("Microsoft Corporation", "Microsoft")))
    result = signature.verify_signature(r"C:\Windows\sample.exe")
    assert result.publisher == "Microsoft Corporation" and result.status == "valid"
    assert actions == [1, 2]
