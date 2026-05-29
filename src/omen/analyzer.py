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
    apply_severity_overrides,
    confidence_rank,
    fail_on_triggered,
    parse_limit,
    parse_severity_overrides,
    severity_rank,
    sort_key,
)
from .solc_env import require_solc
from .sources import InputError, SourceInput, load_input
from .vyper_env import require_vyper


def parse_categories(value: str, *, allow_all: bool) -> list[str]:
    """Parse a category spec into a concrete, deduped, validated list.

    Shared parsing primitive behind both ``--check`` (POST_V01 Rotation 2, R2.7)
    and ``--exclude-check`` (R2.8). A *value* is a single category, optionally the
    keyword ``all`` (only when *allow_all* is set), or a comma-separated list of
    categories. The two flags differ only in whether ``all`` is meaningful:
    ``--check all`` is the obvious "every class", but ``--exclude-check all``
    would scan nothing, so the exclude side forbids it.

    Resolution rules:
      - ``all`` (only if *allow_all*) expands to every category, in ``CATEGORIES``
        order. It may not be combined with other names (``all,reentrancy`` is
        rejected as a mistake — ``all`` already includes everything).
      - A list is split on commas; surrounding whitespace and empty segments
        (e.g. a trailing comma) are ignored.
      - Duplicates are removed while preserving first-seen order.
      - Every name must be a known category; an unknown name raises ``ValueError``
        naming the offender and listing the valid choices.
    """
    flag = "--check" if allow_all else "--exclude-check"
    choices = f"{', '.join(CATEGORIES)}" + (" or 'all'" if allow_all else "")

    raw = (value or "").strip()
    if allow_all and raw == "all":
        return list(CATEGORIES)

    # Split on commas, trim each segment, drop blanks (tolerates trailing/double
    # commas and surrounding whitespace).
    parts = [seg.strip() for seg in raw.split(",")]
    names = [p for p in parts if p]
    if not names:
        raise ValueError(
            f"{flag} requires at least one category; choose from {choices}"
        )

    # 'all' inside a list is ambiguous: it already covers everything, so combining
    # it with explicit names is almost certainly a mistake. Reject it plainly.
    if "all" in names:
        if not allow_all:
            raise ValueError(
                f"{flag} does not accept 'all' (excluding every class would "
                f"scan nothing); list the specific categories to exclude"
            )
        if len(names) == 1:
            return list(CATEGORIES)
        raise ValueError(
            "--check 'all' cannot be combined with other categories; "
            "use 'all' alone or list the specific categories you want"
        )

    resolved: list[str] = []
    for name in names:
        if name not in CATEGORIES:
            raise ValueError(
                f"unknown check {name!r}; choose from {choices}"
            )
        if name not in resolved:  # dedupe, preserve first-seen order
            resolved.append(name)
    return resolved


def resolve_checks(check: str, exclude: str | None = None) -> list[str]:
    """Expand the --check value into a concrete list of categories.

    Accepts (POST_V01 Rotation 2, R2.7) a single category, the keyword ``all``,
    or a comma-separated list of categories (e.g.
    ``access-control,delegatecall,upgrade`` — the proxy/admin attack cluster).
    The comma-list lets a bounty hunter scope a scan to exactly the detection
    surface a given program needs in one run, instead of either accepting the
    noise of ``all`` or running several single-category scans and merging them.

    *exclude* (POST_V01 Rotation 2, R2.8) is the inverse selector: a single
    category or comma-separated list (``all`` is not accepted — excluding every
    class would scan nothing) whose categories are removed from the resolved
    ``--check`` set. It is the natural complement to the R2.7 comma-list: where a
    program's relevant surface is "everything except the two noisy classes",
    ``--check all --exclude-check greedy,prodigal`` expresses it directly instead
    of having to enumerate the other eight. The subtraction preserves the
    ``--check`` order, so the surviving categories run in the same order they
    would have without the exclusion.

    Excluding a category that ``--check`` did not select is a no-op (not an
    error) — ``--check reentrancy --exclude-check suicidal`` simply yields
    ``[reentrancy]`` — so an exclude list can be reused across scans with
    different ``--check`` scopes. Excluding *every* selected category, however,
    leaves nothing to scan, which is a usage error: omen refuses an empty check
    set rather than silently producing an always-empty report.
    """
    resolved = parse_categories(check, allow_all=True)

    if exclude is None or not str(exclude).strip():
        return resolved

    excluded = parse_categories(exclude, allow_all=False)
    excluded_set = set(excluded)
    remaining = [c for c in resolved if c not in excluded_set]
    if not remaining:
        raise ValueError(
            f"--exclude-check {exclude!r} removes every selected category, "
            f"leaving nothing to scan; drop a category from the exclusion or "
            f"widen --check"
        )
    return remaining


@dataclass
class AnalysisReport:
    """The full result of an omen run."""

    tool: str
    version: str
    input_type: str
    origin: str
    checks: list[str]
    findings: list[Finding] = field(default_factory=list)
    # Number of findings that survived filtering/sorting *before* a --limit cap
    # (POST_V01 Rotation 2, R2.4) truncated them for display. When no limit
    # applies this equals len(findings). Defaults to None for in-code callers
    # who build a report directly; to_dict() then reports it as the shown count.
    total_findings: int | None = None
    # Whether the --fail-on severity gate (POST_V01 Rotation 2, R2.5) tripped.
    # Computed over the filtered findings *before* the --limit cap, so a display
    # cap can never hide a finding from the gate. False means "never gate"
    # (the default) or "gate set but nothing reached the threshold"; the CLI
    # maps a True here onto a non-zero exit code for CI use.
    gate_triggered: bool = False

    def to_dict(self) -> dict[str, Any]:
        shown = len(self.findings)
        total = self.total_findings if self.total_findings is not None else shown
        return {
            "tool": self.tool,
            "version": self.version,
            "input_type": self.input_type,
            "origin": self.origin,
            "checks": self.checks,
            # finding_count is the number of findings shown in this report.
            "finding_count": shown,
            # total_findings is how many survived filtering before --limit
            # truncated them; truncated flags whether any were dropped by the
            # cap, so a consumer can tell "10 of 47 shown" from "10 of 10".
            "total_findings": total,
            "truncated": total > shown,
            # gate_triggered records whether the --fail-on CI gate tripped on
            # this report's (pre-cap) findings, so a JSON consumer sees the same
            # signal the process exit code carries.
            "gate_triggered": self.gate_triggered,
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


def _sort_findings(findings: list[Finding], sort: str) -> list[Finding]:
    """Order findings for output (POST_V01 Rotation 2, Rank 3).

    ``sort="severity"`` (the default) returns the findings worst-first:
    highest severity, then highest confidence, with ties preserving the
    original detector-registration order (Python sort is stable). This puts the
    high-impact leads at the top of every report — the order a bounty hunter
    triages a whole-program scan in. ``sort="none"`` preserves the raw
    detector-registration order for callers who want the unmodified stream.
    Pure reordering: it never adds, drops, or mutates a finding, so the
    serialized ``finding_count`` is unaffected.
    """
    if sort == "none":
        return findings
    if sort == "severity":
        return sorted(findings, key=sort_key)
    raise ValueError(f"unknown sort order {sort!r}; choose 'severity' or 'none'")


def _limit_findings(
    findings: list[Finding], limit: int | None
) -> list[Finding]:
    """Cap the report to the first *limit* findings (POST_V01 Rotation 2, R2.4).

    ``limit=None`` (the default) keeps every finding. A positive ``limit``
    returns at most that many findings from the front of the list. This runs
    *after* ``_sort_findings``, so with the default worst-first ordering the
    cap keeps the N highest-impact leads — the "just show me the top N" triage
    move on a whole-program scan that still emits dozens of findings after the
    severity/confidence filters. Unlike the filters, this does change which
    findings appear, so the report records the pre-cap ``total_findings`` and a
    ``truncated`` flag for honest "N of M shown" reporting.
    """
    if limit is None:
        return findings
    return findings[:limit]


def analyze(
    contract: str,
    input_type: str,
    check: str,
    rpc_url: str | None = None,
    min_confidence: str = "low",
    min_severity: str = "informational",
    sort: str = "severity",
    limit: int | str | None = None,
    fail_on: str | None = None,
    exclude_check: str | None = None,
    severity_override: str | None = None,
) -> AnalysisReport:
    """Top-level entry point: load input, run checks, return a report.

    *min_confidence* (POST_V01 Rank 8) suppresses findings below the given
    confidence level (one of ``low``/``medium``/``high``); the default
    ``"low"`` keeps every finding.

    *min_severity* (POST_V01 Rotation 2) suppresses findings below the given
    severity level (one of ``informational``/``low``/``medium``/``high``/
    ``critical``); the default ``"informational"`` keeps every finding. Both
    filters compose: a finding must pass both thresholds to be kept.

    *sort* (POST_V01 Rotation 2, Rank 3) orders the surviving findings:
    ``"severity"`` (the default) returns them worst-first (highest severity,
    then highest confidence), so the high-impact leads lead the report;
    ``"none"`` preserves the raw detector order. Sorting runs after filtering,
    so it never changes which findings appear, only their order.

    *limit* (POST_V01 Rotation 2, R2.4) caps the report to at most that many
    findings; ``None`` (the default) keeps all. The cap runs *after* sorting,
    so with the default worst-first ordering it keeps the N highest-impact
    leads. Because it does change which findings appear, the report records the
    pre-cap ``total_findings`` and a ``truncated`` flag.

    *fail_on* (POST_V01 Rotation 2, R2.5) is the CI exit-code gate. ``None`` /
    ``"never"`` (the default) never trips, so omen exits 0 on a clean run as it
    always has. A severity name (``informational``..``critical``) trips the gate
    — sets ``report.gate_triggered`` — when at least one finding reaches that
    severity, which the CLI maps onto a non-zero exit code so a pipeline step
    fails. The gate is evaluated over the filtered findings *before* the
    ``--limit`` cap, so a display cap can never hide a finding from the gate.

    *exclude_check* (POST_V01 Rotation 2, R2.8) removes one or more categories
    (a single name or comma-separated list; not ``all``) from the resolved
    ``--check`` set — the inverse selector. ``None`` (the default) excludes
    nothing. Excluding a category ``--check`` did not select is a no-op;
    excluding every selected category is a usage error.

    *severity_override* (org-specific risk tuning) is a comma-separated list of
    ``CATEGORY=SEVERITY`` pairs (e.g. ``reentrancy=critical,tx-origin=high``).
    ``None`` (the default) overrides nothing. Each matched finding's severity is
    re-stamped to the configured value *before* the ``--min-severity`` filter,
    ``--sort severity`` ordering, the ``--limit`` cap, and the ``--fail-on`` gate,
    so an override flows through the whole pipeline (it can both surface a class
    that would otherwise be filtered out and trip the CI gate at the pinned
    level). Only severity changes — category/confidence/evidence/detector are
    preserved.
    """
    limit_n = parse_limit(limit)
    checks = resolve_checks(check, exclude_check)
    overrides = parse_severity_overrides(severity_override)
    src = load_input(contract, input_type, rpc_url)

    if src.input_type in ("sol", "vyper"):
        findings = _analyze_source(src, checks)
    else:  # bytecode or address (both reduce to bytecode analysis)
        findings = _analyze_bytecode(src, checks)

    # Re-stamp severities per the override map first, so the filter/sort/gate
    # pipeline below all act on the org-tuned severity rather than the default.
    findings = apply_severity_overrides(findings, overrides)
    findings = _filter_by_confidence(findings, min_confidence)
    findings = _filter_by_severity(findings, min_severity)
    findings = _sort_findings(findings, sort)
    # Record the surviving count before the cap so the report can show "N of M".
    total = len(findings)
    # Evaluate the CI gate over the full filtered set (pre-cap), so --limit
    # cannot hide a gate-tripping finding from the exit code.
    gate = fail_on_triggered(findings, fail_on)
    findings = _limit_findings(findings, limit_n)

    return AnalysisReport(
        tool="omen",
        version=__version__,
        input_type=src.input_type,
        origin=src.origin,
        checks=checks,
        findings=findings,
        total_findings=total,
        gate_triggered=gate,
    )
