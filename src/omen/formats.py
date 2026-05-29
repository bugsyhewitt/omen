"""Output formatting for omen: text, JSON, H1-flavored markdown, and SARIF.

JSON is the machine-readable contract. H1-markdown produces a report body
shaped for a HackerOne submission: title, severity, summary, evidence, and
remediation per finding. SARIF (Static Analysis Results Interchange Format)
2.1.0 is the standard consumed by GitHub Advanced Security code scanning,
VSCode, and most CI systems — emitting it lets omen findings flow into the
same tooling ecosystem as Slither's own SARIF output. The text format
(POST_V01 Rotation 2, R2.6) is the compact human-readable terminal view: a
per-severity count summary followed by one line per finding, worst-first — the
"what did omen find, at a glance" read for an analyst running omen interactively
rather than piping it into another tool.
"""

from __future__ import annotations

import json

from . import __version__
from .analyzer import AnalysisReport
from .findings import SEVERITY_ORDER, Finding, Severity, severity_rank


def to_json(report: AnalysisReport, *, indent: int = 2) -> str:
    return json.dumps(report.to_dict(), indent=indent, sort_keys=False)


_REMEDIATION = {
    "prodigal": (
        "Add access control (e.g. an owner check or role guard) to any "
        "function that sends Ether, and validate the destination."
    ),
    "suicidal": (
        "Restrict selfdestruct to an authorized owner, or remove it. "
        "Prefer a pausable/upgradeable pattern over destruction."
    ),
    "greedy": (
        "Add a withdraw path so deposited Ether can be released, or make "
        "the contract non-payable if it is not meant to hold funds."
    ),
    "reentrancy": (
        "Apply checks-effects-interactions: update state before the external "
        "call, or use a reentrancy guard (e.g. OpenZeppelin ReentrancyGuard)."
    ),
    "access-control": (
        "Restrict privileged functions and protected state with an explicit "
        "access guard (e.g. an `onlyOwner` modifier or OpenZeppelin "
        "AccessControl roles), and emit an event whenever ownership or a role "
        "changes so off-chain monitors can detect unauthorized changes."
    ),
    "tx-origin": (
        "Never use `tx.origin` for authorization — it is the original external "
        "account, not the immediate caller, so an attacker contract a victim "
        "interacts with can act on the victim's behalf. Use `msg.sender` "
        "instead (and a role/owner check on top of it)."
    ),
    "delegatecall": (
        "Never `delegatecall` to an address an attacker can control — the "
        "callee executes in this contract's storage and balance context and "
        "can overwrite any state (including the owner) or selfdestruct the "
        "contract. Restrict the target to a fixed, trusted implementation, and "
        "avoid `delegatecall` inside loops where `msg.value` is reused across "
        "iterations."
    ),
    "upgrade": (
        "Protect the upgrade/initialization path of an upgradeable (proxy) "
        "contract. An implementation whose `initialize`/upgrade function is "
        "callable by anyone can be hijacked: an attacker initializes it, "
        "becomes owner, and upgrades the proxy to malicious code. Use "
        "OpenZeppelin's `Initializable` with `_disableInitializers()` in the "
        "implementation constructor, and guard `upgradeTo` with an "
        "owner/role check (`_authorizeUpgrade` in UUPS)."
    ),
    "overflow": (
        "Use Solidity 0.8+ (where arithmetic reverts on overflow/underflow by "
        "default) or OpenZeppelin SafeMath on older compilers. Avoid dividing "
        "before multiplying — it truncates and loses precision; multiply first, "
        "then divide. Remove tautological comparisons (conditions that are "
        "always true or always false), which usually signal a broken bounds or "
        "overflow guard."
    ),
    "weak-randomness": (
        "Never derive randomness from on-chain values an actor can observe or "
        "influence — `block.timestamp`, `blockhash`, `block.number`, and "
        "`block.difficulty`/`prevrandao` are all predictable or "
        "miner/validator-manipulable. Use a verifiable randomness source such "
        "as Chainlink VRF, or a commit-reveal scheme, for any value where the "
        "outcome has economic significance."
    ),
}


def _finding_md(index: int, f: Finding) -> str:
    lines: list[str] = []
    lines.append(f"### {index}. {f.title}")
    lines.append("")
    lines.append(f"- **Category:** {f.category}")
    lines.append(f"- **Severity:** {f.severity.value}")
    lines.append(f"- **Confidence:** {f.confidence}")
    if f.contract:
        lines.append(f"- **Contract:** `{f.contract}`")
    lines.append(f"- **Detector:** `{f.detector}`")
    lines.append("")
    lines.append("**Summary**")
    lines.append("")
    lines.append(f.description or "(no description)")
    lines.append("")

    ev = f.evidence
    if ev.source_mapping or ev.opcodes or ev.trace:
        lines.append("**Evidence**")
        lines.append("")
        for loc in ev.source_mapping:
            lines.append(f"- source: `{loc}`")
        for op in ev.opcodes:
            lines.append(
                f"- opcode: `{op.get('opcode')}` at offset "
                f"`0x{op.get('offset', 0):x}`"
            )
        if ev.calldata:
            lines.append(f"- calldata: `{ev.calldata}`")
        if ev.expected_outcome:
            lines.append(f"- expected outcome: {ev.expected_outcome}")
        for step in ev.trace:
            lines.append(f"- trace: `{step}`")
        lines.append("")

    lines.append("**Remediation**")
    lines.append("")
    lines.append(_REMEDIATION.get(f.category, "Review and remediate the issue."))
    lines.append("")
    return "\n".join(lines)


def to_h1md(report: AnalysisReport) -> str:
    lines: list[str] = []
    lines.append(f"# omen report — {report.origin}")
    lines.append("")
    lines.append(f"- **Tool:** {report.tool} v{report.version}")
    lines.append(f"- **Input type:** {report.input_type}")
    lines.append(f"- **Checks run:** {', '.join(report.checks)}")
    shown = len(report.findings)
    total = report.total_findings if report.total_findings is not None else shown
    if total > shown:
        # --limit (POST_V01 Rotation 2, R2.4) truncated the report; show the
        # honest "top N of M" so the reader knows leads were capped, not absent.
        lines.append(f"- **Findings:** {shown} of {total} (top {shown} shown; --limit)")
    else:
        lines.append(f"- **Findings:** {shown}")
    lines.append("")

    if not report.findings:
        lines.append("No findings for the requested checks.")
        lines.append("")
    else:
        lines.append("## Findings")
        lines.append("")
        for i, f in enumerate(report.findings, start=1):
            lines.append(_finding_md(i, f))

    lines.append("---")
    lines.append("")
    lines.append(
        "_Generated by omen. For authorized security testing only. "
        "omen performs analysis only and never submits transactions._"
    )
    lines.append("")
    return "\n".join(lines)


_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)
_SARIF_VERSION = "2.1.0"
_SARIF_INFO_URI = "https://github.com/bugsyhewitt/omen"

# SARIF defines exactly three result levels (plus "none"). Map omen's H1
# severity taxonomy onto them; the original severity is preserved verbatim in
# each rule's `properties.severity` and in the result's `properties` so no
# information is lost in the projection.
_SEVERITY_TO_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFORMATIONAL: "note",
}

# A security-severity score (0.0–10.0) drives GitHub code-scanning's
# Critical/High/Medium/Low buckets via the `security-severity` rule property.
_SEVERITY_TO_SCORE = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFORMATIONAL: "0.0",
}


def _sarif_level(severity: Severity) -> str:
    return _SEVERITY_TO_SARIF_LEVEL.get(severity, "warning")


def _sarif_rule_id(category: str) -> str:
    return f"omen/{category}"


def _result_locations(f: Finding) -> list[dict]:
    """Build SARIF physicalLocation entries from a finding's source mappings.

    omen source mappings look like ``Contract.sol#12-18``. We split the file
    from the line range so GitHub/VSCode can annotate the exact lines. Bytecode
    findings carry no source location, so they emit no physicalLocation (their
    opcode offsets live in the result properties instead).
    """
    locations: list[dict] = []
    for loc in f.evidence.source_mapping:
        uri = loc
        region: dict | None = None
        if "#" in loc:
            uri, _, span = loc.partition("#")
            start, _, end = span.partition("-")
            try:
                region = {"startLine": int(start)}
                if end:
                    region["endLine"] = int(end)
            except ValueError:
                region = None
        physical: dict = {"artifactLocation": {"uri": uri}}
        if region:
            physical["region"] = region
        locations.append({"physicalLocation": physical})
    return locations


def to_sarif(report: AnalysisReport, *, indent: int = 2) -> str:
    """Render the report as a SARIF 2.1.0 log document.

    Produces a single run with one tool driver (omen) whose `rules` array
    holds one reportingDescriptor per distinct (category) that produced a
    finding, and a `results` array with one result per finding.
    """
    rules_by_id: dict[str, dict] = {}
    results: list[dict] = []

    for f in report.findings:
        rule_id = _sarif_rule_id(f.category)
        if rule_id not in rules_by_id:
            remediation = _REMEDIATION.get(
                f.category, "Review and remediate the issue."
            )
            rules_by_id[rule_id] = {
                "id": rule_id,
                "name": f.category.replace("-", ""),
                "shortDescription": {"text": f"omen {f.category} finding"},
                "fullDescription": {"text": remediation},
                "help": {"text": remediation},
                "defaultConfiguration": {"level": _sarif_level(f.severity)},
                "properties": {
                    "category": f.category,
                    "severity": f.severity.value,
                    "security-severity": _SEVERITY_TO_SCORE.get(
                        f.severity, "5.0"
                    ),
                    "tags": ["security", "smart-contract", f.category],
                },
            }

        result: dict = {
            "ruleId": rule_id,
            "level": _sarif_level(f.severity),
            "message": {"text": f.description or f.title},
            "properties": {
                "category": f.category,
                "severity": f.severity.value,
                "confidence": f.confidence,
                "detector": f.detector,
            },
        }
        if f.contract:
            result["properties"]["contract"] = f.contract
        if f.evidence.opcodes:
            result["properties"]["opcodes"] = f.evidence.opcodes
        locations = _result_locations(f)
        if locations:
            result["locations"] = locations
        results.append(result)

    sarif_doc = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "omen",
                        "version": __version__,
                        "informationUri": _SARIF_INFO_URI,
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif_doc, indent=indent, sort_keys=False)


def _severity_summary(findings: list[Finding]) -> str:
    """Build a worst-first per-severity count line, e.g. ``2 high, 1 medium``.

    Only severities that actually occur are listed, ordered worst-first
    (critical → informational) so the line reads the same direction as the
    default ``--sort severity`` finding order. An empty finding list yields
    ``"none"`` so the summary is never blank.
    """
    counts: dict[Severity, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    # SEVERITY_ORDER is informational..critical (best-first); reverse it so the
    # summary leads with the worst severity, matching the default sort order.
    parts = [
        f"{counts[sev]} {sev.value}"
        for sev in reversed(SEVERITY_ORDER)
        if counts.get(sev)
    ]
    return ", ".join(parts) if parts else "none"


def _finding_line(index: int, f: Finding) -> str:
    """One compact terminal line for a finding: index, severity, category, where.

    Severity is upper-cased and width-padded (the longest severity word is
    ``informational`` at 13 chars) so the category column lines up across rows,
    keeping the worst-first list scannable. The location is the first source
    mapping (source mode) or the first opcode offset (bytecode mode), so the
    analyst sees *where* to look without reading the full JSON/markdown.
    """
    sev = f.severity.value.upper().ljust(13)
    where = ""
    if f.evidence.source_mapping:
        where = f"  {f.evidence.source_mapping[0]}"
    elif f.evidence.opcodes:
        off = f.evidence.opcodes[0].get("offset", 0)
        where = f"  @0x{off:x}"
    elif f.contract:
        where = f"  {f.contract}"
    return f"{index:>2}. {sev} {f.category} [{f.confidence}]{where}"


def to_text(report: AnalysisReport) -> str:
    """Render the report as a compact human-readable terminal view.

    POST_V01 Rotation 2, R2.6. This is the presentation complement to the
    Rotation 2 triage pipeline (filter → sort → cap → gate): once the findings
    that survive are ordered worst-first, an analyst running omen interactively
    wants a glanceable summary, not a JSON blob or a HackerOne markdown report.
    The output is a one-line header (origin + checks), a per-severity count
    summary, and one line per finding in the report's existing order (worst-first
    under the default ``--sort severity``). It honours the same ``--limit``
    truncation accounting as the h1md format ("top N of M shown"), and never
    re-orders or re-filters — it is a pure formatter over ``report.findings``.
    """
    lines: list[str] = []
    lines.append(f"omen {report.version} — {report.origin}")
    lines.append(f"input: {report.input_type}  checks: {', '.join(report.checks)}")

    shown = len(report.findings)
    total = report.total_findings if report.total_findings is not None else shown
    summary = _severity_summary(report.findings)
    if total > shown:
        # --limit (R2.4) truncated the report; report the honest "top N of M".
        lines.append(f"findings: {shown} of {total} (top {shown} shown; --limit)  [{summary}]")
    else:
        lines.append(f"findings: {shown}  [{summary}]")

    if report.findings:
        lines.append("")
        for i, f in enumerate(report.findings, start=1):
            lines.append(_finding_line(i, f))
    else:
        lines.append("")
        lines.append("No findings for the requested checks.")

    return "\n".join(lines)


def render(report: AnalysisReport, fmt: str) -> str:
    if fmt == "text":
        return to_text(report)
    if fmt == "json":
        return to_json(report)
    if fmt == "h1md":
        return to_h1md(report)
    if fmt == "sarif":
        return to_sarif(report)
    raise ValueError(f"unknown output format: {fmt}")
