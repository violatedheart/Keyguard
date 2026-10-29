"""Load and strictly validate all scoring weights from JSON resources."""

import json
from importlib.resources import files
from pathlib import Path
from typing import Any

SIGNALS = frozenset({
    "keyboard_imports", "unsigned", "invalid_signature", "valid_signature",
    "microsoft_signed", "trusted_publisher", "suspicious_location", "no_window",
    "persistence_suspicious", "non_microsoft_service", "keyboard_network",
    "system_name_mimic", "system_wrong_path", "recent_process",
    "background_keyboard", "odd_parent", "builtin_allowlist", "user_allowlist",
})


def default_data(name: str) -> dict[str, Any]:
    """Read packaged defaults, also available inside the single-file executable."""
    return json.loads(files("keyguard.data").joinpath(name).read_text(encoding="utf-8"))


def load_config(path: Path | None = None) -> dict[str, Any]:
    """Load complete configuration; reject missing weights and unsafe types."""
    config = json.loads(path.read_text(encoding="utf-8")) if path else default_data("config.json")
    if not isinstance(config, dict):
        raise ValueError("Configuration must be a JSON object")
    weights = config.get("weights", {})
    if not isinstance(weights, dict):
        raise ValueError("config.weights must be a JSON object")
    if set(weights) != SIGNALS:
        raise ValueError("config.weights must contain exactly: " + ", ".join(sorted(SIGNALS)))
    for key, value in weights.items():
        if type(value) is not int or not -100 <= value <= 100:
            raise ValueError(f"Weight {key} must be an integer between -100 and 100")
        discount = key in {"valid_signature", "microsoft_signed", "trusted_publisher",
                           "builtin_allowlist", "user_allowlist"}
        if (discount and value > 0) or (not discount and value < 0):
            raise ValueError(f"Weight {key} has the wrong sign")
    for key in ("recent_seconds", "watch_interval_seconds", "max_pe_bytes"):
        if type(config.get(key)) is not int or config[key] <= 0:
            raise ValueError(f"{key} must be a positive integer")
    publishers = config.get("trusted_publishers")
    if not isinstance(publishers, list) or not all(isinstance(p, str) and p for p in publishers):
        raise ValueError("trusted_publishers must be a list of nonempty signer organizations")
    return config
