"""Analysis orchestration for omen.

The analyzer ties the pieces together:
  1. load the input (sol / bytecode / address)
  2. run the requested checks
  3. produce a list of Finding objects

Source mode delegates to Slither's detectors (static + symbolic primitives).
Bytecode / address mode delegates to opcode-level signature scanning.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import CATEGORIES, __version__
from .detectors import (
    VYPER_SUPPORTED_CATEGORIES,
    scan_bytecode_opcodes,
    scan_greedy,
    scan_prodigal,
    scan_reentrancy,
    slither_detector_classes,
)
from .findings import (
    DEFAULT_SEVERITY,
    Evidence,
    Finding,
    Severity,
    confidence_rank,
    severity_rank,
)
from .solc_env import require_solc
from .sources import InputError, SourceInput, load_input
from .vyper_env import require_vyper


def resolve_checks(check: str) -> list[str]:
    """Expand the --check value into a concrete list of categories."""
    if check == "all":
        return list(CATEGORIES)
    if check not in CATEGORIES:
        raise ValueError(
            f"unknown check {check!r}; choose from {', '.join(CATEGORIES)} or 'all'"
        )
    return [check]


@dataclass
class AnalysisReport:
    """The full result of an omen run."""

    tool: str
    version: str
    input_type: str
    origin: str
    checks: list[str]
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "version": self.version,
            "input_type": self.input_type,
            "origin": self.origin,
            "checks": self.checks,
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }


def _impact_to_severity(category: str, impact: str | None) -> Severity:
    """Map a Slither impact string onto an omen Severity.

    Falls back to the category default if the impact is unrecognized.
    """
    if impact:
        try:
            return Severity(impact.strip().lower())
        except ValueError:
            pass
    return DEFAULT_SEVERITY.get(category, Severity.MEDIUM)


def _resolve_vyper_checks(checks: list[str]) -> list[str]:
    """Filter a check list down to the categories Slither supports for Vyper.

    POST_V01 Rank 6: Slither's Vyper front-end only supports a subset of the
    Solidity detectors. For `--check all` we silently narrow to the supported
    subset; for an explicit single unsupported class we raise a clear error so
    the user is not handed an always-empty report.
    """
    supported = [c for c in checks if c in VYPER_SUPPORTED_CATEGORIES]
    if not supported:
        names = ", ".join(sorted(VYPER_SUPPORTED_CATEGORIES))
        requested = ", ".join(checks)
        raise InputError(
            f"check(s) {requested!r} are not supported for Vyper input; "
            f"Slither's Vyper front-end covers only: {names}. "
            "Re-run with one of those or with --check all."
        )
    return supported


def _analyze_source(src: SourceInput, checks: list[str]) -> list[Finding]:
    """Run Slither detectors for the requested categories on a source file.

    Handles both Solidity (`.sol`, needs solc) and Vyper (`.vy`, needs the
    `vyper` binary) input. Slither auto-detects the language from the file
    extension via crytic-compile; omen's job is to ensure the right compiler
    is present and, for Vyper, to restrict to the supported detector subset.
    """
    if src.input_type == "vyper":
        require_vyper()  # raises VyperUnavailableError with actionable guidance
        checks = _resolve_vyper_checks(checks)
        source_path = src.vyper_path
    else:
        require_solc()  # raises SolcUnavailableError with actionable guidance
        source_path = src.sol_path

    from slither import Slither

    slither = Slither(source_path)

    # Register every detector class needed by the requested checks, keeping
    # a reverse map from slither check-id -> omen category.
    checkid_to_category: dict[str, str] = {}
    for category in checks:
        for det_cls in slither_detector_classes(category):
            slither.register_detector(det_cls)
            arg = getattr(det_cls, "ARGUMENT", None)
            if isinstance(arg, str):
                checkid_to_category[arg] = category

    results = slither.run_detectors()

    findings: list[Finding] = []
    for group in results:
        for raw in group:
            check_id = raw.get("check", "")
            category = checkid_to_category.get(check_id)
            if category is None:
                continue  # detector we didn't ask for (defensive)

            description = (raw.get("description") or "").strip()
            impact = raw.get("impact")
            confidence = (raw.get("confidence") or "medium").strip().lower()

            source_mapping = _extract_source_mapping(raw)
            contract = _extract_contract_name(raw)

            findings.append(
                Finding(
                    category=category,
                    severity=_impact_to_severity(category, impact),
                    title=f"{category} contract ({check_id})",
                    description=description,
                    detector=f"slither:{check_id}",
                    contract=contract,
                    confidence=confidence,
                    evidence=Evidence(source_mapping=source_mapping),
                )
            )
    return findings


def _extract_source_mapping(raw: dict[str, Any]) -> list[str]:
    """Pull human-readable source locations out of a Slither result dict."""
    locations: list[str] = []
    for element in raw.get("elements", []) or []:
        sm = element.get("source_mapping") or {}
        filename = sm.get("filename_short") or sm.get("filename_used")
        lines = sm.get("lines") or []
        if filename and lines:
            locations.append(f"{filename}#{lines[0]}-{lines[-1]}")
        elif filename:
            locations.append(str(filename))
    return locations


def _extract_contract_name(raw: dict[str, Any]) -> str | None:
    for element in raw.get("elements", []) or []:
        if element.get("type") == "contract":
            return element.get("name")
    # fall back to the contract enclosing the first element
    for element in raw.get("elements", []) or []:
        td = (element.get("type_specific_fields") or {}).get("parent") or {}
        if td.get("type") == "contract":
            return td.get("name")
    return None


# The precision caveat appended to every low-confidence bytecode heuristic.
# POST_V01 Rank 1 requires these opcode heuristics to be reported honestly:
# they trade precision for address-mode recall, and source mode is better.
_HEURISTIC_CAVEAT = (
    " This is a coarse opcode-level heuristic for bytecode/address mode and "
    "may be a false positive; running omen on the contract's source provides "
    "higher-precision analysis."
)


def _analyze_bytecode(src: SourceInput, checks: list[str]) -> list[Finding]:
    """Run opcode-level scanning for bytecode / address input.

    The suicidal class has a precise bytecode signature (the SELFDESTRUCT
    opcode), reported at high confidence. For prodigal, greedy, and
    reentrancy (POST_V01 Rank 1) omen falls back to coarse opcode-pattern
    heuristics reported at LOW confidence — they exist so that on-chain,
    source-unverified contracts produce triage leads instead of silent
    misses, while honestly flagging that source-mode is more precise.
    """
    assert src.bytecode is not None
    findings: list[Finding] = []
    contract = src.address if src.address else None
    bytecode = src.bytecode

    if "suicidal" in checks:
        hits = scan_bytecode_opcodes(bytecode)
        suicidal_hits = [h for h in hits if h["category"] == "suicidal"]
        if suicidal_hits:
            offsets = ", ".join(f"0x{h['offset']:x}" for h in suicidal_hits)
            findings.append(
                Finding(
                    category="suicidal",
                    severity=DEFAULT_SEVERITY["suicidal"],
                    title="suicidal contract (selfdestruct opcode present)",
                    description=(
                        "The deployed bytecode contains a SELFDESTRUCT opcode "
                        f"at offset(s) {offsets}. If the path reaching it lacks "
                        "access control, anyone can destroy the contract (the "
                        "MAIAN 'suicidal' class, e.g. the Parity multisig "
                        "incident)."
                    ),
                    detector="omen:bytecode-selfdestruct",
                    contract=contract,
                    confidence="high",
                    evidence=Evidence(opcodes=suicidal_hits),
                )
            )

    if "prodigal" in checks:
        hits = scan_prodigal(bytecode)
        if hits:
            offsets = ", ".join(f"0x{h['offset']:x}" for h in hits)
            findings.append(
                Finding(
                    category="prodigal",
                    severity=DEFAULT_SEVERITY["prodigal"],
                    title="prodigal contract (caller-controlled value transfer)",
                    description=(
                        "A CALL with a non-zero value argument and a "
                        "caller-controlled (CALLDATALOAD-derived) destination "
                        f"was found at offset(s) {offsets}. If unguarded, this "
                        "lets an arbitrary caller redirect the contract's ether "
                        "(the MAIAN 'prodigal' class)." + _HEURISTIC_CAVEAT
                    ),
                    detector="omen:bytecode-prodigal",
                    contract=contract,
                    confidence="low",
                    evidence=Evidence(opcodes=hits),
                )
            )

    if "greedy" in checks:
        hits = scan_greedy(bytecode)
        if hits:
            offsets = ", ".join(f"0x{h['offset']:x}" for h in hits)
            findings.append(
                Finding(
                    category="greedy",
                    severity=DEFAULT_SEVERITY["greedy"],
                    title="greedy contract (accepts ether, no release path)",
                    description=(
                        "The bytecode inspects CALLVALUE (payable) at "
                        f"offset(s) {offsets} but contains no value-sending "
                        "opcode (CALL/CALLCODE/DELEGATECALL/SELFDESTRUCT). Ether "
                        "can enter but has no way out (the MAIAN 'greedy' / "
                        "locked-ether class)." + _HEURISTIC_CAVEAT
                    ),
                    detector="omen:bytecode-greedy",
                    contract=contract,
                    confidence="low",
                    evidence=Evidence(opcodes=hits),
                )
            )

    if "reentrancy" in checks:
        hits = scan_reentrancy(bytecode)
        if hits:
            offsets = ", ".join(f"0x{h['offset']:x}" for h in hits)
            findings.append(
                Finding(
                    category="reentrancy",
                    severity=DEFAULT_SEVERITY["reentrancy"],
                    title="reentrancy contract (state write after external call)",
                    description=(
                        "An SSTORE follows a CALL before the next segment "
                        f"terminator at offset(s) {offsets} — a "
                        "checks-effects-interactions violation that can enable "
                        "reentrancy (the classic withdraw-before-update bug)."
                        + _HEURISTIC_CAVEAT
                    ),
                    detector="omen:bytecode-reentrancy",
                    contract=contract,
                    confidence="low",
                    evidence=Evidence(opcodes=hits),
                )
            )

    return findings


def _filter_by_confidence(
    findings: list[Finding], min_confidence: str
) -> list[Finding]:
    """Drop findings whose confidence ranks below *min_confidence*.

    POST_V01 Rank 8. ``min_confidence="low"`` (the default) keeps everything;
    ``"medium"`` drops low-confidence findings; ``"high"`` keeps only
    high-confidence findings. This matters most for bytecode/address mode,
    where the prodigal/greedy/reentrancy heuristics (Rank 1) emit at
    confidence ``low`` and dominate large batch scans with triage noise.
    """
    threshold = confidence_rank(min_confidence)
    if threshold <= 0:
        return findings  # "low" or unknown -> keep all
    return [f for f in findings if confidence_rank(f.confidence) >= threshold]


def _filter_by_severity(
    findings: list[Finding], min_severity: str
) -> list[Finding]:
    """Drop findings whose severity ranks below *min_severity*.

    POST_V01 Rotation 2 (severity sibling of the Rank 8 confidence filter).
    ``min_severity="informational"`` (the default) keeps everything; ``"high"``
    keeps only high/critical findings, etc. This is the triage lever for a
    bounty hunter pointing omen at a whole program scope: with ten detection
    classes spanning informational..critical, surfacing the high-impact leads
    first is the common first pass before drilling into the noise.
    """
    threshold = severity_rank(min_severity)
    if threshold <= 0:
        return findings  # "informational" or unknown -> keep all
    return [f for f in findings if severity_rank(f.severity) >= threshold]


def analyze(
    contract: str,
    input_type: str,
    check: str,
    rpc_url: str | None = None,
    min_confidence: str = "low",
    min_severity: str = "informational",
) -> AnalysisReport:
    """Top-level entry point: load input, run checks, return a report.

    *min_confidence* (POST_V01 Rank 8) suppresses findings below the given
    confidence level (one of ``low``/``medium``/``high``); the default
    ``"low"`` keeps every finding.

    *min_severity* (POST_V01 Rotation 2) suppresses findings below the given
    severity level (one of ``informational``/``low``/``medium``/``high``/
    ``critical``); the default ``"informational"`` keeps every finding. Both
    filters compose: a finding must pass both thresholds to be kept.
    """
    checks = resolve_checks(check)
    src = load_input(contract, input_type, rpc_url)

    if src.input_type in ("sol", "vyper"):
        findings = _analyze_source(src, checks)
    else:  # bytecode or address (both reduce to bytecode analysis)
        findings = _analyze_bytecode(src, checks)

    findings = _filter_by_confidence(findings, min_confidence)
    findings = _filter_by_severity(findings, min_severity)

    return AnalysisReport(
        tool="omen",
        version=__version__,
        input_type=src.input_type,
        origin=src.origin,
        checks=checks,
        findings=findings,
    )
