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
from .detectors import scan_bytecode_opcodes, slither_detector_classes
from .findings import DEFAULT_SEVERITY, Evidence, Finding, Severity
from .solc_env import require_solc
from .sources import SourceInput, load_input


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


def _analyze_source(src: SourceInput, checks: list[str]) -> list[Finding]:
    """Run Slither detectors for the requested categories on a .sol file."""
    require_solc()  # raises SolcUnavailableError with actionable guidance

    from slither import Slither

    slither = Slither(src.sol_path)

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


def _analyze_bytecode(src: SourceInput, checks: list[str]) -> list[Finding]:
    """Run opcode-signature scanning for bytecode / address input.

    For v0.1, opcode-level evidence covers the suicidal class via the
    SELFDESTRUCT opcode. If suicidal is not among the requested checks,
    no bytecode findings are produced (and that's reported honestly).
    """
    assert src.bytecode is not None
    findings: list[Finding] = []
    if "suicidal" not in checks:
        return findings

    hits = scan_bytecode_opcodes(src.bytecode)
    suicidal_hits = [h for h in hits if h["category"] == "suicidal"]
    if suicidal_hits:
        offsets = ", ".join(f"0x{h['offset']:x}" for h in suicidal_hits)
        contract = src.address if src.address else None
        findings.append(
            Finding(
                category="suicidal",
                severity=DEFAULT_SEVERITY["suicidal"],
                title="suicidal contract (selfdestruct opcode present)",
                description=(
                    "The deployed bytecode contains a SELFDESTRUCT opcode at "
                    f"offset(s) {offsets}. If the path reaching it lacks access "
                    "control, anyone can destroy the contract (the MAIAN "
                    "'suicidal' class, e.g. the Parity multisig incident)."
                ),
                detector="omen:bytecode-selfdestruct",
                contract=contract,
                confidence="high",
                evidence=Evidence(opcodes=suicidal_hits),
            )
        )
    return findings


def analyze(
    contract: str,
    input_type: str,
    check: str,
    rpc_url: str | None = None,
) -> AnalysisReport:
    """Top-level entry point: load input, run checks, return a report."""
    checks = resolve_checks(check)
    src = load_input(contract, input_type, rpc_url)

    if src.input_type == "sol":
        findings = _analyze_source(src, checks)
    else:  # bytecode or address (both reduce to bytecode analysis)
        findings = _analyze_bytecode(src, checks)

    return AnalysisReport(
        tool="omen",
        version=__version__,
        input_type=src.input_type,
        origin=src.origin,
        checks=checks,
        findings=findings,
    )
