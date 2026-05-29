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


def sort_key(finding: "Finding") -> tuple[int, int]:
    """Severity-then-confidence sort key, worst-and-most-confident first.

    POST_V01 Rotation 2 (Rank 3, ``--sort severity``). Negated so a plain
    ascending ``sorted()`` puts the highest-severity, highest-confidence finding
    at the top — the order a bounty hunter reads a whole-program scan in. Python
    list sorting is stable, so findings that tie on (severity, confidence)
    preserve their original detector-registration order, keeping the output
    deterministic.
    """
    return (-severity_rank(finding.severity), -confidence_rank(finding.confidence))


# Sentinel for "never gate" — the default for --fail-on (POST_V01 Rotation 2,
# R2.5). When fail_on is "never" omen always exits 0 on a clean run regardless
# of what it found, preserving the pre-R2.5 exit-code behaviour. Any real
# severity name turns omen into a CI gate: findings at or above that severity
# make the run exit non-zero.
FAIL_ON_NEVER = "never"


def fail_on_triggered(
    findings: "list[Finding]", fail_on: "str | None"
) -> bool:
    """Decide whether a --fail-on severity gate trips for *findings*.

    POST_V01 Rotation 2, R2.5 — the CI exit-code gate. ``fail_on`` is either
    ``"never"`` / ``None`` (the default — never trip, omen exits 0 on a clean
    run as it always has) or a severity name (``informational``/``low``/
    ``medium``/``high``/``critical``). The gate trips — returns ``True`` — when
    at least one finding's severity ranks at or above the threshold.

    This is the standard security-scanner CI pattern (cf. Slither's
    ``--fail-high``, semgrep/trivy/bandit severity gates): a clean scan exits 0,
    a scan that surfaces a lead at or above the chosen severity exits non-zero
    so a pipeline step fails. It is evaluated against the findings that survived
    the ``--min-severity``/``--min-confidence`` filters but *before* any
    ``--limit`` cap, so a display cap can never hide a finding from the gate.
    """
    if fail_on is None:
        return False
    normalized = fail_on.strip().lower()
    if not normalized or normalized == FAIL_ON_NEVER:
        return False
    threshold = severity_rank(normalized)
    return any(severity_rank(f.severity) >= threshold for f in findings)


def parse_limit(limit: "int | str | None") -> int | None:
    """Validate and normalise a ``--limit`` value (POST_V01 Rotation 2, R2.4).

    Returns ``None`` for "no limit" (the default — keep every finding), or a
    positive integer cap. ``0`` and negatives are rejected: a zero/negative cap
    is almost always a mistake (it would silently hide every lead), so omen
    surfaces it as a ``ValueError`` rather than emitting an empty report. A
    string is accepted (the CLI hands argparse ints, but the primitive stays
    usable from library/JSON callers) and parsed as a base-10 integer.
    """
    if limit is None:
        return None
    if isinstance(limit, str):
        text = limit.strip()
        if not text:
            return None
        try:
            limit = int(text, 10)
        except ValueError:
            raise ValueError(f"--limit must be a positive integer, got {limit!r}")
    if not isinstance(limit, int) or isinstance(limit, bool):
        raise ValueError(f"--limit must be a positive integer, got {limit!r}")
    if limit <= 0:
        raise ValueError(f"--limit must be a positive integer (>= 1), got {limit}")
    return limit


def parse_severity_overrides(
    value: "str | None",
) -> "dict[str, Severity]":
    """Parse a ``--severity-override`` spec into a {category: Severity} map.

    The spec is a comma-separated list of ``CATEGORY=SEVERITY`` pairs, e.g.
    ``reentrancy=critical,tx-origin=high``. It lets an org pin the severity omen
    reports for a given detection class to match its own risk model, instead of
    accepting omen's built-in defaults (and, in source mode, Slither's
    per-finding impact). This is the org-specific risk-tuning lever the R2.10
    config work deliberately deferred ("no per-category overrides" was the
    Simplicity-Gate floor for the flat config map); it now lives as its own flag
    that composes with the existing filter/sort/gate pipeline.

    Resolution rules (mirroring the other comma-list parsers):
      - ``None`` / blank -> empty map (no override; the default behaviour).
      - Pairs split on commas; surrounding whitespace and empty segments (a
        trailing comma) are ignored.
      - Each pair is ``CATEGORY=SEVERITY``; both sides are trimmed and the
        severity is lower-cased. A missing ``=`` (or an empty side) is an error.
      - ``CATEGORY`` must be a known omen category; ``SEVERITY`` must be one of
        informational/low/medium/high/critical.
      - A later pair for the same category wins (last-write), so a repeated
        category is not an error — the rightmost value is the effective one.

    Raises ``ValueError`` (which the CLI turns into a usage error, exit 2) with a
    message naming the offending token and the valid choices.
    """
    from . import CATEGORIES

    raw = (value or "").strip()
    if not raw:
        return {}

    sev_choices = ", ".join(s.value for s in SEVERITY_ORDER)
    cat_choices = ", ".join(CATEGORIES)

    overrides: dict[str, Severity] = {}
    for segment in raw.split(","):
        pair = segment.strip()
        if not pair:
            continue  # tolerate trailing/double commas
        if "=" not in pair:
            raise ValueError(
                f"--severity-override entry {pair!r} must be CATEGORY=SEVERITY "
                f"(e.g. reentrancy=critical)"
            )
        cat_part, sev_part = pair.split("=", 1)
        category = cat_part.strip()
        sev_text = sev_part.strip().lower()
        if not category or not sev_text:
            raise ValueError(
                f"--severity-override entry {pair!r} must be CATEGORY=SEVERITY "
                f"(e.g. reentrancy=critical)"
            )
        if category not in CATEGORIES:
            raise ValueError(
                f"--severity-override: unknown category {category!r}; "
                f"choose from {cat_choices}"
            )
        try:
            severity = Severity(sev_text)
        except ValueError:
            raise ValueError(
                f"--severity-override: unknown severity {sev_text!r} for "
                f"{category!r}; choose from {sev_choices}"
            )
        overrides[category] = severity  # last-write wins for a repeated category
    return overrides


def apply_severity_overrides(
    findings: "list[Finding]",
    overrides: "dict[str, Severity]",
) -> "list[Finding]":
    """Re-stamp each finding's severity from *overrides* (by category).

    Returns the same list, mutated in place: any finding whose category appears
    in *overrides* has its ``severity`` replaced with the configured value; the
    rest are untouched. An empty *overrides* map is a no-op. This runs in
    ``analyze`` *before* the ``--min-severity`` filter, ``--sort severity``
    ordering, the ``--limit`` cap, and the ``--fail-on`` gate, so an override
    flows through the whole pipeline: pinning ``tx-origin=high`` both surfaces it
    under ``--min-severity high`` and trips ``--fail-on high``, and pinning a
    class *down* (e.g. ``greedy=informational``) lets ``--min-severity low`` drop
    its noise. Only the severity changes — category, confidence, evidence, and
    the detector id are preserved, so the finding stays fully traceable.
    """
    if not overrides:
        return findings
    for finding in findings:
        new_sev = overrides.get(finding.category)
        if new_sev is not None:
            finding.severity = new_sev
    return findings


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
