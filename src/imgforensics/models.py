from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

class Status(str, Enum):
    DETECTED = "DETECTED"
    NOT_DETECTED = "NOT DETECTED"
    POSSIBLE = "POSSIBLE"
    LIKELY = "LIKELY"
    UNLIKELY = "UNLIKELY"
    INCONCLUSIVE = "INCONCLUSIVE"
    EXPERIMENTAL = "EXPERIMENTAL"
    UNSUPPORTED = "UNSUPPORTED"

class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

@dataclass
class Finding:
    finding: str
    category: str
    status: Status
    severity: Severity
    confidence: float
    evidence: list[Any] = field(default_factory=list)
    method: str = ""
    limitations: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not 0 <= self.confidence <= 1:
            raise ValueError("confidence must be between 0 and 1")

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["status"] = self.status.value
        result["severity"] = self.severity.value
        return result

@dataclass
class Report:
    file: dict[str, Any]
    hashes: dict[str, str]
    findings: list[Finding]
    case: dict[str, Any]
    artifacts: list[str] = field(default_factory=list)
    evidence_graph: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"file": self.file, "hashes": self.hashes,
                "findings": [f.to_dict() for f in self.findings],
                "case": self.case, "artifacts": self.artifacts, "evidence_graph": self.evidence_graph}
