"""Explainable scoring with weights supplied exclusively by configuration."""

from typing import Any

from keyguard.models import Finding


def score_findings(findings: list[Finding], weights: dict[str, int]) -> tuple[int, str, list[dict[str, Any]]]:
    """Count each signal once, retain all reasons, and clamp the final sum to 0..100."""
    grouped: dict[str, dict[str, Any]] = {}
    for finding in findings:
        if finding.code not in weights:
            raise ValueError(f"No configured weight for signal {finding.code}")
        if finding.code not in grouped:
            grouped[finding.code] = {
                "code": finding.code, "module": finding.module,
                "weight": weights[finding.code], "reasons": [],
            }
        if finding.reason not in grouped[finding.code]["reasons"]:
            grouped[finding.code]["reasons"].append(finding.reason)
    score = max(0, min(100, sum(item["weight"] for item in grouped.values())))
    level = "High" if score >= 60 else "Medium" if score >= 30 else "Low"
    return score, level, list(grouped.values())
