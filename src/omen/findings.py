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


# Severity ordering, low -> high. Used by the --min-severity filter (POST_V01
# Rotation 2): a bounty hunter triaging a large scan across omen's ten
# detection classes — which span informational..critical — wants to surface
# only the high-impact leads first. This mirrors the --min-confidence filter
# but on the severity axis. The order is the inverse of how the enum is
# declared (declared worst-first for readability; ranked best-first here so a
# higher rank means a worse finding, consistent with confidence_rank).
SEVERITY_ORDER = (
    Severity.INFORMATIONAL,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)


def severity_rank(severity: "Severity | str") -> int:
    """Map a Severity (or its string value) onto its rank.

    informational=0, low=1, medium=2, high=3, critical=4 — higher is worse, so
    a ``--min-severity`` threshold keeps findings whose rank is >= the
    threshold's rank. Unknown / unexpected severities are treated as the lowest
    rank (informational) so a stricter-than-informational threshold never
    silently keeps them.
    """
    try:
        sev = severity if isinstance(severity, Severity) else Severity(
            (severity or "").strip().lower()
        )
    except ValueError:
        return 0
    try:
        return SEVERITY_ORDER.index(sev)
    except ValueError:
        return 0


# Confidence ordering, low -> high. Used by the --min-confidence filter
# (POST_V01 Rank 8). Slither emits low/medium/high confidence on its findings;
# omen's bytecode heuristics (POST_V01 Rank 1) default to "low". A bounty
# hunter scanning a large batch wants to suppress the noisier low-confidence
# leads, so omen ranks confidence on this scale and filters findings whose
# rank is below the requested threshold.
CONFIDENCE_ORDER = ("low", "medium", "high")


def confidence_rank(confidence: str) -> int:
    """Map a confidence string onto its rank (low=0, medium=1, high=2).

    Unknown / unexpected confidence strings are treated as the lowest rank so
    they are never silently kept by a stricter-than-low threshold.
    """
    try:
        return CONFIDENCE_ORDER.index((confidence or "").strip().lower())
    except ValueError:
        return 0


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
    # delegatecall and upgrade (R5, POST_V01 Rank 4) are proxy/upgrade-pattern
    # bugs. Both underlying Slither detectors are HIGH impact: a
    # controlled-delegatecall lets an attacker run arbitrary code in the
    # contract's storage context, and an unprotected-upgrade lets anyone seize
    # the implementation of an upgradeable proxy — an instant critical on any
    # Immunefi program. Both default to high.
    "delegatecall": Severity.HIGH,
    "upgrade": Severity.HIGH,
    # overflow and weak-randomness (R8, POST_V01 Rank 7) are the
    # medium-severity completeness classes. POST_V01 frames both as MEDIUM:
    # arithmetic-precision bugs (divide-before-multiply / tautology) and weak
    # PRNG (blockhash/block.timestamp as randomness) are persistent but rarely
    # the sole root cause of a critical. These defaults apply to bytecode/
    # address mode and to any source finding whose Slither impact omen cannot
    # parse. [Worker decision (R8): in source mode the analyzer maps Slither's
    # own per-finding impact onto severity, so a weak-prng finding — which
    # Slither classifies HIGH in 0.11.x — will surface as HIGH at runtime; the
    # MEDIUM here is the documented default/fallback, consistent with how every
    # other category's runtime severity already follows Slither's impact.]
    "overflow": Severity.MEDIUM,
    "weak-randomness": Severity.MEDIUM,
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
