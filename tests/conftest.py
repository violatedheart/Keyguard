"""Reusable deterministic process and configuration fixtures."""

from dataclasses import replace
from typing import Any

import pytest

from keyguard.config import load_config
from keyguard.models import ProcessSnapshot


@pytest.fixture
def config() -> dict[str, Any]:
    """Provide a fresh real default configuration for every test."""
    return load_config()


@pytest.fixture
def process() -> ProcessSnapshot:
    """Model a background executable with a reliable parent identity."""
    return ProcessSnapshot(401, "svch0st.exe", r"C:\Users\Tester\Temp\svch0st.exe", 100,
                           950.0, False, "powershell.exe", r"C:\Windows\System32\powershell.exe", 900.0)


@pytest.fixture
def normal_process(process: ProcessSnapshot) -> ProcessSnapshot:
    """Model an old foreground application outside risky directories."""
    return replace(process, name="editor.exe", exe=r"C:\Program Files\Editor\editor.exe",
                   create_time=100.0, parent_create_time=50.0, visible_window=True,
                   parent_name="explorer.exe")
