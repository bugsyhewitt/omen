"""Finding data model for omen.

A Finding is one detected trace vulnerability. Each finding carries the
MAIAN-class category, a severity, a human-readable description, and
reproducibility evidence (source location and/or bytecode opcode evidence).
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Severity levels, aligned with the H1 (HackerOne) taxonomy."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


# Default severity per MAIAN class. These reflect the worst-case impact of
# each class: a contract that can be destroyed or leak all its funds is
# higher severity than one that merely locks funds.
DEFAULT_SEVERITY = {
    "prodigal": Severity.HIGH,
    "suicidal": Severity.HIGH,
    "greedy": Severity.MEDIUM,
    "reentrancy": Severity.HIGH,
    # access-control is the #1 loss category by volume (OWASP 2025/2026,
    # $953M tracked): a missing owner/role guard on a privileged function is
    # high-severity by default. tx.origin auth misuse is a persistent
    # medium-severity finding (exploitable only via a phishing/relay flow).
    "access-control": Severity.HIGH,
    "tx-origin": Severity.MEDIUM,
}


@dataclass
class Evidence:
    """Reproducibility evidence attached to a finding.

    For source-mode findings this is source locations. For bytecode/address
    findings this is the offending opcode(s) and their byte offsets. The
    optional trace/calldata/expected fields support concrete validation
    (replaying an exploit transaction trace) per the omen niche.
    """

    source_mapping: list[str] = field(default_factory=list)
    opcodes: list[dict[str, Any]] = field(default_factory=list)
    trace: list[dict[str, Any]] = field(default_factory=list)
    calldata: str | None = None
    expected_outcome: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """A single detected trace vulnerability."""

    category: str  # one of omen.CATEGORIES
    severity: Severity
    title: str
    description: str
    detector: str  # the underlying detector that produced this (e.g. slither check id)
    contract: str | None = None
    confidence: str = "medium"
    evidence: Evidence = field(default_factory=Evidence)

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "detector": self.detector,
            "contract": self.contract,
            "confidence": self.confidence,
            "evidence": self.evidence.to_dict(),
        }
