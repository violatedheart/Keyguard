"""Real Windows API boundary smoke checks, skipped on other operating systems."""

import os
import sys

import pytest

from keyguard.config import load_config
from keyguard.pe_analyzer import analyze_imports
from keyguard.scanner import is_administrator, visible_processes
from keyguard.signature import verify_signature

pytestmark = [pytest.mark.windows, pytest.mark.skipif(os.name != "nt", reason="Windows API smoke test")]


def test_real_pe_and_winverifytrust() -> None:
    """Exercise native trust layouts and parse a genuine Python PE without executing it."""
    info = verify_signature(sys.executable)
    assert info.status in {"valid", "unsigned", "invalid"}, info
    assert info.status_code.startswith("0x")
    result = analyze_imports(sys.executable, load_config()["max_pe_bytes"])
    assert not result.issues


def test_real_window_and_token_queries() -> None:
    """Exercise pywin32 query-only interfaces in the Windows test runner session."""
    assert isinstance(is_administrator(), bool)
    visible, issues = visible_processes()
    assert isinstance(visible, set), issues
