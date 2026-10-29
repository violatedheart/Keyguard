"""Serializable records shared by collectors and the scoring engine."""

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class Finding:
    """An explainable scoring signal; unknown observations belong in issues."""

    code: str
    module: str
    reason: str


@dataclass
class Detection:
    """Unscored findings, coverage issues, and raw module observations."""

    findings: list[Finding] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)

    def scored(self, weights: dict[str, int]) -> dict[str, Any]:
        """Return module findings and score using the same supplied scan weights.

        Contribution retains negative trust discounts. The displayed module score
        is clamped to 0..100, while process scoring combines the original signals.
        """
        from keyguard.scoring import score_findings
        score, level, findings = score_findings(self.findings, weights)
        return {"score": score, "level": level,
                "contribution": sum(item["weight"] for item in findings),
                "findings": findings, "issues": list(self.issues), "observations": dict(self.data)}


@dataclass(frozen=True)
class SignatureInfo:
    """Offline embedded Authenticode result and verified signer organization."""

    status: str = "unknown"
    publisher: str = ""
    subject: str = ""
    status_code: str = ""
    detail: str = ""


@dataclass(frozen=True)
class ProcessSnapshot:
    """Best-effort process identity captured without memory inspection."""

    pid: int
    name: str
    exe: str
    ppid: int
    create_time: float | None
    visible_window: bool | None
    parent_name: str = ""
    parent_exe: str = ""
    parent_create_time: float | None = None


@dataclass
class ProcessReport:
    """All evidence and final weighted score for one process instance."""

    process: ProcessSnapshot
    score: int
    level: str
    findings: list[dict[str, Any]]
    issues: list[str]
    observations: dict[str, Any]


@dataclass
class ScanReport:
    """A complete scan, including persistence entries with no running match."""

    generated_at: str
    is_admin: bool
    processes: list[ProcessReport]
    persistence: list[dict[str, Any]]
    issues: list[str]
    version: str = "1.0.0"
    schema_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        """Return only JSON-compatible records."""
        return asdict(self)
