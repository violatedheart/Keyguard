"""Scoring thresholds, discounts, deduplication, and configuration errors."""

import json
from pathlib import Path
from typing import Any

import pytest

from keyguard.config import load_config
from keyguard.models import Detection, Finding
from keyguard.scoring import score_findings


@pytest.mark.parametrize(("weight", "level"), [(0, "Low"), (29, "Low"), (30, "Medium"),
                                                (59, "Medium"), (60, "High"), (100, "High")])
def test_thresholds(weight: int, level: str) -> None:
    """Check both sides of every advertised risk boundary."""
    score, actual, _ = score_findings([Finding("signal", "test", "reason")], {"signal": weight})
    assert (score, actual) == (weight, level)


def test_deduplicate_and_clamp() -> None:
    """Repeated persistence sources keep reasons but cannot inflate the score."""
    findings = [Finding("risk", "test", "first"), Finding("risk", "test", "second"), Finding("risk", "test", "first")]
    score, _, evidence = score_findings(findings, {"risk": 140})
    assert score == 100
    assert evidence[0]["reasons"] == ["first", "second"]
    assert score_findings([Finding("trust", "test", "signed")], {"trust": -20})[0] == 0


def test_unknown_signal_is_not_silently_ignored() -> None:
    """A missing configured weight must fail rather than change scoring silently."""
    with pytest.raises(ValueError, match="No configured weight"):
        score_findings([Finding("missing", "test", "reason")], {})


def test_module_score_keeps_signed_contribution() -> None:
    """Explain a trust discount without confusing it with a negative risk score."""
    result = Detection([Finding("signed", "signature", "Verified publisher")]).scored({"signed": -20})
    assert result["score"] == 0 and result["contribution"] == -20
    assert result["findings"][0]["reasons"] == ["Verified publisher"]


@pytest.mark.parametrize("change", ["missing", "boolean", "wrong_sign", "interval", "publishers"])
def test_reject_bad_config(tmp_path: Path, config: dict[str, Any], change: str) -> None:
    """Reject malformed and misleading scoring settings before live scanning."""
    if change == "missing":
        del config["weights"]["unsigned"]
    elif change == "boolean":
        config["weights"]["unsigned"] = True
    elif change == "wrong_sign":
        config["weights"]["user_allowlist"] = 20
    elif change == "interval":
        config["watch_interval_seconds"] = 0
    else:
        config["trusted_publishers"] = "Microsoft"
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises(ValueError):
        load_config(path)


def test_root_defaults_match_packaged_defaults() -> None:
    """Prevent source checkout and executable resources from drifting apart."""
    root = Path(__file__).resolve().parents[1]
    assert load_config(root / "config.json") == load_config()


@pytest.mark.parametrize("value", [[], {"weights": []}])
def test_config_requires_objects(tmp_path: Path, value: object) -> None:
    """Reject JSON arrays with useful errors rather than an attribute traceback."""
    path = tmp_path / "config.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="JSON object"):
        load_config(path)
