"""Output formatting for omen: text, JSON, H1-flavored markdown, SARIF, gha, junit, checkstyle, sonarqube, gitlab-sast.

JSON is the machine-readable contract. H1-markdown produces a report body
shaped for a HackerOne submission: title, severity, summary, evidence, and
remediation per finding. SARIF (Static Analysis Results Interchange Format)
2.1.0 is the standard consumed by GitHub Advanced Security code scanning,
VSCode, and most CI systems — emitting it lets omen findings flow into the
same tooling ecosystem as Slither's own SARIF output. The text format
(POST_V01 Rotation 2, R2.6) is the compact human-readable terminal view: a
per-severity count summary followed by one line per finding, worst-first — the
"what did omen find, at a glance" read for an analyst running omen interactively
rather than piping it into another tool. The gha format (POST_V01 R3.5) emits
GitHub Actions workflow-command annotations (``::error``/``::warning``/
``::notice file=...,line=...::message``), which the Actions runner turns into
inline PR-diff annotations on every repository for free — the no-upload, no-
Advanced-Security complement to the SARIF code-scanning path. The junit format
(POST_V01 R3.6) emits a JUnit XML report — the lingua franca test-result format
that GitHub Actions test reporters, GitLab CI, Jenkins, CircleCI, Azure DevOps,
and TeamCity all ingest natively. Each finding becomes a failing ``<testcase>``
(with a ``<failure>`` carrying the description), grouped under one
``<testsuite>``; it is the platform-agnostic "surface omen findings in the CI
test-results tab and fail the build" lever that works on essentially every CI.
The checkstyle format (POST_V01 R3.7) emits a Checkstyle XML document — the
static-analysis-specific lingua franca consumed natively by GitLab CI's
**Code Quality** widget (which renders the diff-side issue list every MR shows),
Reviewdog, SonarQube, the Jenkins Checkstyle plugin, and most code-review bots.
Where ``junit`` projects findings as *test results*, ``checkstyle`` projects
them as *code-review annotations* keyed on a file/line, which is the shape these
review-side platforms expect for static-analysis output. The sonarqube format
(POST_V01 R3.8) emits a SonarQube `Generic Issue Import Format
<https://docs.sonarqube.org/latest/analyzing-source-code/importing-external-issues/generic-issue-import-format/>`_
JSON document — SonarQube's *own* native external-issues schema, the
SonarQube-native complement to the Checkstyle workaround. Where ``checkstyle``
reaches SonarQube via its generic *Checkstyle* importer (a one-format-fits-all
fallback), ``sonarqube`` targets SonarQube's purpose-built generic issue
importer directly, with native SonarQube severity/type fields, so omen findings
land as first-class external issues in the SonarQube/SonarCloud UI with no
format translation step. The gitlab-sast format (POST_V01 R3.9) emits GitLab's
native [SAST Report v15](https://gitlab.com/gitlab-org/security-products/security-report-schemas)
JSON document — the schema GitLab CI's *Security Dashboard* and the MR
*Vulnerability Report* widget ingest directly via the ``sast`` job artifact.
Where ``checkstyle`` reaches GitLab as a *Code Quality* issue (a diff-side
review comment) and ``sonarqube`` targets the SonarQube ecosystem, ``gitlab-
sast`` targets GitLab's *security* surface: findings become first-class
vulnerabilities in the GitLab vulnerability management UI, with the native
``Critical``/``High``/``Medium``/``Low``/``Info`` severity and the SAST
category that GitLab's merge-request approval rules can gate on. The audience
the existing ``checkstyle`` GitLab path does not cover.
"""

from __future__ import annotations

import json
from xml.sax.saxutils import escape, quoteattr

from . import __version__
from .analyzer import AnalysisReport
from .findings import (
    SEVERITY_ORDER,
    Finding,
    Severity,
    finding_fingerprint,
    severity_rank,
)


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

# The same score table keyed by the severity *string value* (e.g. "critical"),
# for findings loaded from a saved report as dicts (--sarif-merge) where the
# severity is already a string rather than a Severity enum member.
_SEVERITY_TO_SCORE_BY_VALUE = {
    sev.value: score for sev, score in _SEVERITY_TO_SCORE.items()
}


def _sarif_level(severity: Severity) -> str:
    return _SEVERITY_TO_SARIF_LEVEL.get(severity, "warning")


# The level table keyed by the severity *string value* (e.g. "high"), for
# findings loaded as dicts from a saved report (--sarif-merge), whose severity
# is a plain string. Unknown / missing severities fall back to "warning",
# matching the enum path.
_SEVERITY_TO_LEVEL_BY_VALUE = {
    sev.value: level for sev, level in _SEVERITY_TO_SARIF_LEVEL.items()
}


def _sarif_level_by_value(severity_value: str) -> str:
    return _SEVERITY_TO_LEVEL_BY_VALUE.get(
        (severity_value or "").strip().lower(), "warning"
    )


def _sarif_rule_id(category: str) -> str:
    return f"omen/{category}"


def _source_mapping_locations(source_mapping: list[str]) -> list[dict]:
    """Build SARIF physicalLocation entries from omen source mappings.

    omen source mappings look like ``Contract.sol#12-18``. We split the file
    from the line range so GitHub/VSCode can annotate the exact lines. Bytecode
    findings carry no source location, so they emit no physicalLocation (their
    opcode offsets live in the result properties instead).

    Operates on the raw list of mapping strings, so it serves both a live
    ``Finding`` (via ``f.evidence.source_mapping``) and a finding dict loaded
    from a saved report (via ``--sarif-merge``).
    """
    locations: list[dict] = []
    for loc in source_mapping:
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


def _result_locations(f: Finding) -> list[dict]:
    """SARIF physicalLocation entries for a live ``Finding`` (see helper above)."""
    return _source_mapping_locations(list(f.evidence.source_mapping))


def _sarif_rule(category: str, level: str, severity_value: str) -> dict:
    """Build a SARIF reportingDescriptor (rule) for a category.

    Shared by the live-report formatter and the ``--sarif-merge`` consolidator
    so the rule shape is identical regardless of whether the finding came from a
    fresh scan or a saved report. *level* is the SARIF level and *severity_value*
    the omen severity string; both are derived from the finding's severity.
    """
    remediation = _REMEDIATION.get(category, "Review and remediate the issue.")
    return {
        "id": _sarif_rule_id(category),
        "name": category.replace("-", ""),
        "shortDescription": {"text": f"omen {category} finding"},
        "fullDescription": {"text": remediation},
        "help": {"text": remediation},
        "defaultConfiguration": {"level": level},
        "properties": {
            "category": category,
            "severity": severity_value,
            "security-severity": _SEVERITY_TO_SCORE_BY_VALUE.get(
                severity_value, "5.0"
            ),
            "tags": ["security", "smart-contract", category],
        },
    }


def sarif_document(rules: list[dict], results: list[dict], *, indent: int = 2) -> str:
    """Serialize a SARIF 2.1.0 log from prepared *rules* and *results*.

    The single place that fixes omen's SARIF envelope (schema, version, the one
    tool driver). Both ``to_sarif`` (live report) and the ``--sarif-merge``
    consolidator hand it their assembled rule/result arrays so the document shape
    is byte-for-byte consistent across the two entry points.
    """
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
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif_doc, indent=indent, sort_keys=False)


def to_sarif(
    report: AnalysisReport,
    *,
    indent: int = 2,
    baseline: "set[str] | None" = None,
) -> str:
    """Render the report as a SARIF 2.1.0 log document.

    Produces a single run with one tool driver (omen) whose `rules` array
    holds one reportingDescriptor per distinct (category) that produced a
    finding, and a `results` array with one result per finding.

    *baseline* (POST_V01 R3.3, ``--sarif-baseline``) is an optional set of
    finding fingerprints — as produced by ``load_baseline_fingerprints`` from a
    previously-saved omen JSON report. When supplied, every result gains a
    SARIF-native ``baselineState`` field: ``"unchanged"`` for a finding whose
    fingerprint is already in the baseline (a pre-existing, known issue) and
    ``"new"`` for one that is not (introduced since the baseline). This is the
    GitHub-code-scanning-native suppression lever: unlike ``--baseline`` (which
    *drops* known findings from the report entirely), ``--sarif-baseline`` keeps
    every result in the SARIF document and lets the consuming platform (GitHub
    Advanced Security) fold the ``unchanged`` ones into its pre-existing-alert
    view while surfacing the ``new`` ones. ``None`` (the default) omits
    ``baselineState`` entirely, leaving the SARIF output byte-for-byte as before.
    """
    rules_by_id: dict[str, dict] = {}
    results: list[dict] = []

    for f in report.findings:
        rule_id = _sarif_rule_id(f.category)
        if rule_id not in rules_by_id:
            rules_by_id[rule_id] = _sarif_rule(
                f.category, _sarif_level(f.severity), f.severity.value
            )

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
        if baseline is not None:
            # SARIF-native suppression (POST_V01 R3.3): mark each result as a
            # pre-existing ("unchanged") or newly-introduced ("new") finding.
            # GitHub code scanning reads baselineState to fold the unchanged
            # ones into its pre-existing-alert view. The fingerprint is the same
            # category+detector+contract+location identity --baseline uses, so a
            # severity-override re-stamp or a wording drift never flips the state.
            result["baselineState"] = (
                "unchanged" if finding_fingerprint(f) in baseline else "new"
            )
        locations = _result_locations(f)
        if locations:
            result["locations"] = locations
        results.append(result)

    return sarif_document(list(rules_by_id.values()), results, indent=indent)


# GitHub Actions workflow commands have exactly three annotation levels.
# Map omen's five-level severity taxonomy onto them, worst-first: critical/high
# become ``error`` (the red, build-failing annotation), medium becomes
# ``warning``, low/informational become ``notice``. This is the same intent as
# the SARIF level mapping (_SEVERITY_TO_SARIF_LEVEL) but onto the Actions
# command vocabulary; the original severity is preserved verbatim in each
# annotation's title so nothing is lost in the projection.
_SEVERITY_TO_GHA_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "notice",
    Severity.INFORMATIONAL: "notice",
}


def _gha_escape_data(text: str) -> str:
    """Escape the message body of a GitHub Actions workflow command.

    Per the Actions runner's command parser, the data segment (after the ``::``)
    must escape ``%`` (the escape introducer), CR, and LF so a multi-line or
    percent-bearing message stays on one command line. Properties additionally
    escape ``:`` and ``,`` (see ``_gha_escape_prop``).
    """
    return (
        text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    )


def _gha_escape_prop(text: str) -> str:
    """Escape a property *value* of a GitHub Actions workflow command.

    A property value (e.g. ``file=...`` or ``title=...``) sits inside the
    comma-separated, colon-delimited property list, so beyond the data escapes
    it must also escape ``:`` and ``,`` so a path or title containing them does
    not prematurely close the value.
    """
    return (
        _gha_escape_data(text).replace(":", "%3A").replace(",", "%2C")
    )


def _gha_location(f: Finding) -> tuple[str | None, int | None, int | None]:
    """Extract (file, startLine, endLine) for a finding's GHA annotation.

    Reuses omen's ``Contract.sol#12-18`` source-mapping shape (the same split
    the SARIF physicalLocation helper performs): the part before ``#`` is the
    file, the ``start-end`` after it the line range. A bytecode finding (no
    source mapping) yields ``(None, None, None)`` — its annotation is emitted
    without a ``file``/``line`` anchor, which GitHub still surfaces in the
    Actions log (it just isn't pinned to a diff line).
    """
    if not f.evidence.source_mapping:
        return (None, None, None)
    loc = f.evidence.source_mapping[0]
    if "#" not in loc:
        return (loc, None, None)
    uri, _, span = loc.partition("#")
    start_s, _, end_s = span.partition("-")
    try:
        start = int(start_s)
    except ValueError:
        return (uri, None, None)
    try:
        end = int(end_s) if end_s else None
    except ValueError:
        end = None
    return (uri, start, end)


def _gha_line(f: Finding) -> str:
    """One GitHub Actions workflow-command annotation line for a finding.

    Shape: ``::LEVEL file=PATH,line=N,endLine=M,title=TITLE::MESSAGE``. ``file``,
    ``line`` and ``endLine`` are omitted when the finding has no source location
    (bytecode mode). The title carries omen's severity, category and confidence
    so the annotation is self-describing in the PR/Actions UI; the message is the
    finding's description (or title as a fallback). All segments are escaped per
    the Actions command grammar.
    """
    level = _SEVERITY_TO_GHA_LEVEL.get(f.severity, "warning")
    uri, start, end = _gha_location(f)
    props: list[str] = []
    if uri:
        props.append(f"file={_gha_escape_prop(uri)}")
        if start is not None:
            props.append(f"line={start}")
            if end is not None:
                props.append(f"endLine={end}")
    title = f"omen {f.severity.value}: {f.category} [{f.confidence}]"
    props.append(f"title={_gha_escape_prop(title)}")
    message = _gha_escape_data(f.description or f.title)
    return f"::{level} {','.join(props)}::{message}"


def to_gha(report: AnalysisReport) -> str:
    """Render the report as GitHub Actions workflow-command annotations.

    One ``::error``/``::warning``/``::notice`` command per finding, in the
    report's existing worst-first order. Unlike ``--format sarif`` — which
    targets GitHub *Advanced Security* code scanning (a paid feature) and is
    uploaded as a document — these workflow commands are read by the Actions
    *runner* on **every** repository for free: each becomes an inline annotation
    on the PR diff and the workflow run summary, with no upload step. This is the
    pure-formatter complement to the SARIF path for the common "fail the PR and
    annotate the offending lines, in plain GitHub Actions" workflow.

    A pure formatter over ``report.findings`` (like ``to_text``/``to_sarif``): it
    never re-orders or re-filters. An empty report emits a single ``::notice``
    so the step still leaves a visible "omen ran, found nothing" trace in the
    Actions log rather than silent empty output.
    """
    if not report.findings:
        return (
            f"::notice title=omen {_gha_escape_prop(report.origin)}::"
            f"{_gha_escape_data('omen found no findings for the requested checks.')}"
        )
    return "\n".join(_gha_line(f) for f in report.findings)


# JUnit has no severity dimension — a testcase either passed or it failed. omen
# findings are all "the contract has a problem", so every finding is a failure.
# The omen severity is preserved verbatim in the failure ``type`` attribute and
# message so nothing is lost in the projection, mirroring how the SARIF/gha
# formatters keep the original severity alongside the projected level.
def _junit_location(f: Finding) -> str:
    """A short ``where`` suffix for a finding's JUnit testcase name.

    Reuses omen's evidence shape (source mapping first, then opcode offset, then
    contract) so the testcase name pins the finding to a location the same way
    the compact text formatter's finding line does. Returns an empty string for
    a finding with no locatable evidence.
    """
    if f.evidence.source_mapping:
        return f.evidence.source_mapping[0]
    if f.evidence.opcodes:
        return f"@0x{f.evidence.opcodes[0].get('offset', 0):x}"
    if f.contract:
        return f.contract
    return ""


def _junit_testcase(index: int, f: Finding) -> list[str]:
    """The XML lines for one finding rendered as a failing JUnit ``<testcase>``.

    The testcase ``name`` is ``<index>. <category> [<confidence>] <where>`` — the
    same scannable identity the text formatter uses — and its ``classname`` is the
    finding's category so CI test-result UIs that group by class bucket findings
    by vulnerability class. The single ``<failure>`` carries the omen severity in
    its ``type`` and a ``severity: ... | detector: ...`` message header followed
    by the finding's description as the element body, so the full triage context
    survives into the CI test-results tab.
    """
    where = _junit_location(f)
    name = f"{index}. {f.category} [{f.confidence}]"
    if where:
        name = f"{name} {where}"
    classname = f"omen.{f.category}"
    failure_type = f.severity.value
    header = f"severity: {f.severity.value} | detector: {f.detector}"
    if f.contract:
        header = f"{header} | contract: {f.contract}"
    body = f.description or f.title
    failure_message = body.splitlines()[0] if body else f.title
    lines = [
        f"  <testcase name={quoteattr(name)} classname={quoteattr(classname)}>",
        f"    <failure type={quoteattr(failure_type)} "
        f"message={quoteattr(failure_message)}>{escape(header)}\n{escape(body)}"
        f"</failure>",
        "  </testcase>",
    ]
    return lines


def to_junit(report: AnalysisReport) -> str:
    """Render the report as a JUnit XML test-results document.

    POST_V01 R3.6. One ``<testsuite>`` named ``omen`` whose ``tests`` count is the
    number of findings and whose ``failures`` count equals it (every finding is a
    failure — omen only emits findings, never "passes"). Each finding is one
    failing ``<testcase>`` in the report's existing worst-first order; the
    formatter never re-orders or re-filters (a pure formatter over
    ``report.findings`` like ``to_text``/``to_sarif``/``to_gha``).

    Unlike ``--format sarif`` (a GitHub *Advanced Security* upload) and
    ``--format gha`` (GitHub-Actions-only annotations), JUnit XML is the
    platform-agnostic CI test-result format ingested natively by GitHub Actions
    test reporters, GitLab CI, Jenkins, CircleCI, Azure DevOps, and TeamCity — so
    omen findings land in the CI "tests" tab and fail the build on essentially any
    CI system, no upload step or paid feature required.

    A clean report (no findings) emits a valid ``<testsuite>`` with
    ``tests="0" failures="0"`` and a single passing ``<testcase>`` recording that
    omen ran, so the CI test-results tab shows a green "omen" entry rather than an
    empty/absent suite (mirroring how ``to_gha`` emits a single ``::notice`` on an
    empty report). All names, attributes, and bodies are XML-escaped.
    """
    count = len(report.findings)
    suite_name = quoteattr("omen")
    lines: list[str] = ['<?xml version="1.0" encoding="UTF-8"?>']
    if not report.findings:
        lines.append(
            f"<testsuite name={suite_name} tests=\"1\" failures=\"0\" "
            f"errors=\"0\">"
        )
        clean_name = quoteattr(f"omen scan of {report.origin}")
        lines.append(f"  <testcase name={clean_name} classname=\"omen\"/>")
        lines.append("</testsuite>")
        return "\n".join(lines)

    lines.append(
        f"<testsuite name={suite_name} tests=\"{count}\" "
        f"failures=\"{count}\" errors=\"0\">"
    )
    for i, f in enumerate(report.findings, start=1):
        lines.extend(_junit_testcase(i, f))
    lines.append("</testsuite>")
    return "\n".join(lines)


# Checkstyle XML has exactly three severity levels (``error``/``warning``/
# ``info``). Map omen's five-level taxonomy onto them, mirroring the SARIF/gha
# intent: critical/high → ``error`` (the red, blocker level every Checkstyle
# consumer surfaces as a build-failing issue), medium → ``warning`` (the amber
# default), low/informational → ``info`` (the green/note level Reviewdog and the
# Jenkins plugin render but do not block on). The original omen severity is
# preserved verbatim in the ``omen-severity`` attribute on each ``<error>`` so
# nothing is lost in the projection.
_SEVERITY_TO_CHECKSTYLE_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "info",
    Severity.INFORMATIONAL: "info",
}

# Checkstyle XML version most consumers (GitLab Code Quality, Reviewdog,
# Jenkins Checkstyle plugin, SonarQube) accept as the document attribute. The
# value mirrors what slither/eslint-stylish/most static-analysis emitters use.
_CHECKSTYLE_VERSION = "8.0"


def _checkstyle_location(f: Finding) -> tuple[str, int | None, int | None]:
    """Extract (file, startLine, endLine) for a finding's Checkstyle ``<error>``.

    Checkstyle is **file-keyed** (every ``<error>`` lives inside a ``<file>``),
    so a finding with no locatable source must still anchor to *some* file name.
    We reuse omen's evidence shape — the same ``Contract.sol#start-end`` mapping
    the SARIF and gha helpers split — with a graceful fallback chain so a
    bytecode-mode finding (no source mapping) anchors to the contract identifier
    instead of being silently dropped: source mapping first, then contract, then
    ``"<unknown>"`` as a last-resort sentinel so the document stays well-formed.
    """
    if f.evidence.source_mapping:
        loc = f.evidence.source_mapping[0]
        if "#" not in loc:
            return (loc, None, None)
        uri, _, span = loc.partition("#")
        start_s, _, end_s = span.partition("-")
        try:
            start = int(start_s)
        except ValueError:
            return (uri, None, None)
        try:
            end = int(end_s) if end_s else None
        except ValueError:
            end = None
        return (uri, start, end)
    if f.contract:
        return (f.contract, None, None)
    return ("<unknown>", None, None)


def _checkstyle_error(f: Finding) -> str:
    """The XML line for a single finding's Checkstyle ``<error>`` element.

    Carries the projected Checkstyle ``severity`` (error/warning/info), the
    ``line`` (omitted when there is no source mapping — Checkstyle treats a
    missing line as "applies to the file as a whole", which is the right shape
    for a bytecode finding), the finding description as ``message``, the
    detector identity as ``source`` (the standard Checkstyle convention for the
    rule that produced the finding), and the original omen severity verbatim in
    an ``omen-severity`` attribute so the projection is lossless. All attribute
    values are XML-escaped via ``quoteattr`` so a ``<``/``&``/``"`` in a path
    or description cannot break the document.
    """
    level = _SEVERITY_TO_CHECKSTYLE_LEVEL.get(f.severity, "warning")
    _, start, _end = _checkstyle_location(f)
    parts = [f"severity={quoteattr(level)}"]
    if start is not None:
        parts.append(f'line="{start}"')
    message = f.description or f.title
    # Checkstyle messages are single-line per convention; collapse newlines so
    # consumers that render them inline (GitLab Code Quality, Reviewdog) don't
    # break their layout.
    message = message.replace("\n", " ").replace("\r", " ")
    parts.append(f"message={quoteattr(message)}")
    parts.append(f"source={quoteattr(f.detector)}")
    # Preserve the original omen severity (critical/high/medium/low/
    # informational) verbatim so no information is lost when the five-level
    # taxonomy is projected onto Checkstyle's three.
    parts.append(f"omen-severity={quoteattr(f.severity.value)}")
    parts.append(f"omen-category={quoteattr(f.category)}")
    parts.append(f"omen-confidence={quoteattr(f.confidence)}")
    return f"    <error {' '.join(parts)}/>"


def to_checkstyle(report: AnalysisReport) -> str:
    """Render the report as a Checkstyle XML document.

    POST_V01 R3.7. One ``<checkstyle>`` root containing one ``<file>`` per
    distinct location (findings sharing a file are grouped, matching the
    Checkstyle convention every consumer expects), each containing one
    ``<error>`` per finding in the report's existing worst-first order (the
    formatter never re-orders or re-filters — a pure formatter over
    ``report.findings`` like the rest).

    Unlike ``--format junit`` (which projects findings as *test results*, one
    failing testcase per finding under one suite) ``--format checkstyle``
    projects them as **code-review annotations** keyed on a file/line, which is
    the shape GitLab CI's Code Quality widget, Reviewdog, SonarQube, and the
    Jenkins Checkstyle plugin expect. The two are complementary CI-integration
    formats — JUnit is the right pick when you want findings in the *tests* tab
    of any CI; Checkstyle is the right pick when you want them in the *MR/PR
    code-review diff* of the platforms above.

    A clean report (no findings) emits a valid ``<checkstyle>`` document with no
    ``<file>`` children — the well-formed "scan ran, found nothing" shape every
    Checkstyle consumer recognises. All names, attributes, and bodies are
    XML-escaped via ``xml.sax.saxutils.quoteattr``.
    """
    lines: list[str] = ['<?xml version="1.0" encoding="UTF-8"?>']
    lines.append(f'<checkstyle version="{_CHECKSTYLE_VERSION}">')

    # Group findings by file (the location anchor). Preserve first-seen file
    # order so the document order mirrors the report's worst-first finding order
    # — a consumer rendering top-to-bottom sees the worst-affected file first.
    by_file: dict[str, list[Finding]] = {}
    for f in report.findings:
        uri, _, _ = _checkstyle_location(f)
        by_file.setdefault(uri, []).append(f)

    for uri, findings in by_file.items():
        lines.append(f"  <file name={quoteattr(uri)}>")
        for f in findings:
            lines.append(_checkstyle_error(f))
        lines.append("  </file>")

    lines.append("</checkstyle>")
    return "\n".join(lines)


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


# SonarQube `Generic Issue Import Format` (POST_V01 R3.8). SonarQube defines
# exactly five severity levels (BLOCKER/CRITICAL/MAJOR/MINOR/INFO); omen's
# five-level H1 taxonomy maps onto them one-to-one in the natural worst-first
# order. critical -> BLOCKER (the SonarQube "must fix, will block release"
# bucket — the only SonarQube level that natively fails a quality gate by
# default); high -> CRITICAL; medium -> MAJOR (SonarQube's default for most
# external rules); low -> MINOR; informational -> INFO. The original omen
# severity is *not* lossless under this projection — SonarQube exposes only the
# mapped level on its UI/API — so the projected level is what consumers see; the
# mapping is documented and stable. Unlike SARIF/checkstyle/gha, the SonarQube
# generic issue schema has no free-form "extra attributes" slot per issue, so a
# verbatim-severity round-trip is not on the table here; the level mapping is
# the contract.
_SEVERITY_TO_SONARQUBE = {
    Severity.CRITICAL: "BLOCKER",
    Severity.HIGH: "CRITICAL",
    Severity.MEDIUM: "MAJOR",
    Severity.LOW: "MINOR",
    Severity.INFORMATIONAL: "INFO",
}

# Every omen finding is a security weakness in a contract. SonarQube's three
# external-issue ``type`` values are BUG / VULNERABILITY / CODE_SMELL; the right
# bucket for a smart-contract vulnerability is VULNERABILITY across the board
# (it is what SonarQube's own dashboards filter "security issues" on).
_SONARQUBE_TYPE = "VULNERABILITY"

# The engine identifier under which omen's external issues appear in SonarQube's
# UI ("External rules" → engine list). Kept short and stable so a SonarQube
# project's quality-gate rules can refer to it without coupling to a version.
_SONARQUBE_ENGINE_ID = "omen"


def _sonarqube_location(f: Finding) -> "dict | None":
    """Build the SonarQube ``primaryLocation`` entry for a finding.

    SonarQube's generic issue schema *requires* every issue to carry a
    ``primaryLocation`` with at least a ``message`` and a ``filePath``. A
    finding with a source mapping (``Contract.sol#start-end``) supplies the
    file path and a ``textRange`` (a 1-based ``startLine``/``endLine`` pair,
    matching the SARIF helper's parse); a bytecode-mode finding (no source
    mapping) has no file to anchor to and is therefore not representable as a
    SonarQube issue. We return ``None`` in that case and the caller skips the
    finding rather than emit a malformed issue — the honest "this format
    cannot represent that finding" failure mode, parallel to how GitHub
    Actions annotations degrade to a `file`-less command for bytecode but the
    SonarQube schema strictly requires the field.
    """
    if not f.evidence.source_mapping:
        return None
    loc = f.evidence.source_mapping[0]
    file_path = loc
    text_range: dict | None = None
    if "#" in loc:
        file_path, _, span = loc.partition("#")
        start_s, _, end_s = span.partition("-")
        try:
            start = int(start_s)
        except ValueError:
            start = None
        try:
            end = int(end_s) if end_s else None
        except ValueError:
            end = None
        if start is not None:
            text_range = {"startLine": start}
            if end is not None:
                text_range["endLine"] = end
    if not file_path:
        return None
    primary: dict = {
        "message": f.description or f.title,
        "filePath": file_path,
    }
    if text_range:
        primary["textRange"] = text_range
    return primary


def _sonarqube_rule_id(f: Finding) -> str:
    """Stable per-finding rule id (``<category>:<detector>``).

    SonarQube groups external issues by ``ruleId`` for its "Rule" filter and
    its rule-violation counts on the dashboard. We compose the rule id from
    the omen *category* and the underlying *detector*, so two findings of the
    same category produced by different Slither detectors (e.g. ``overflow``
    via ``divide-before-multiply`` vs ``tautology``) still appear under
    distinct rules in the SonarQube UI — the same projection JUnit's
    ``classname`` uses but at the detector level rather than the category
    level, which is the right grain for a SonarQube rule filter. A finding
    with an empty detector falls back to just the category, so the id is
    always non-empty.
    """
    detector = (f.detector or "").strip()
    if detector:
        return f"{f.category}:{detector}"
    return f.category


def to_sonarqube(report: AnalysisReport, *, indent: int = 2) -> str:
    """Render the report as a SonarQube Generic Issue Import Format document.

    POST_V01 R3.8. One ``{"issues": [...]}`` JSON document, one ``issue`` per
    finding in the report's existing worst-first order (the formatter never
    re-orders or re-filters — a pure formatter over ``report.findings`` like
    every other format).

    The output schema matches SonarQube's `Generic Issue Import Format
    <https://docs.sonarqube.org/latest/analyzing-source-code/importing-external-issues/generic-issue-import-format/>`_,
    which SonarQube and SonarCloud ingest natively via
    ``sonar.externalIssuesReportPaths``. Each issue carries:

      - ``engineId``: ``"omen"`` (the engine label SonarQube groups external
        issues under).
      - ``ruleId``: ``<category>:<detector>`` so the SonarQube rule filter
        distinguishes the underlying Slither detector inside an omen category.
      - ``severity``: one of ``BLOCKER``/``CRITICAL``/``MAJOR``/``MINOR``/
        ``INFO`` — omen's five-level taxonomy maps onto SonarQube's five
        one-to-one (critical → BLOCKER, high → CRITICAL, medium → MAJOR,
        low → MINOR, informational → INFO).
      - ``type``: always ``VULNERABILITY`` (every omen finding is a
        security weakness).
      - ``primaryLocation``: ``message`` + ``filePath`` (+ optional
        ``textRange``), the SonarQube-required anchor.

    Unlike ``--format checkstyle`` (which reaches SonarQube via the *generic*
    Checkstyle importer, a one-format-fits-all fallback), ``--format
    sonarqube`` targets SonarQube's *purpose-built* external-issues importer
    directly with native SonarQube severity/type/engineId fields, so omen
    findings appear as first-class SonarQube external issues — the same shape
    the Sonar ecosystem expects for native rule integrations.

    Bytecode-mode findings carry no source mapping (no ``filePath``) and the
    SonarQube schema strictly requires ``primaryLocation.filePath``, so they
    are skipped — they cannot be projected without inventing a fake path. A
    report containing only bytecode-mode findings therefore emits the
    well-formed empty document ``{"issues": []}``, the same shape a clean scan
    produces; the caller can prefer ``--format json``/``sarif`` for full
    coverage of a bytecode scan.
    """
    issues: list[dict] = []
    for f in report.findings:
        primary = _sonarqube_location(f)
        if primary is None:
            # No filePath available (bytecode mode). Skip rather than emit a
            # SonarQube-invalid issue.
            continue
        issues.append(
            {
                "engineId": _SONARQUBE_ENGINE_ID,
                "ruleId": _sonarqube_rule_id(f),
                "severity": _SEVERITY_TO_SONARQUBE.get(f.severity, "MAJOR"),
                "type": _SONARQUBE_TYPE,
                "primaryLocation": primary,
            }
        )
    return json.dumps({"issues": issues}, indent=indent, sort_keys=False)


# --- GitLab SAST Report (POST_V01 R3.9) ----------------------------------
#
# GitLab's SAST report is a JSON document with a fixed top-level shape
# (``version``, ``scan``, ``vulnerabilities``); when a job uploads it as the
# ``reports:sast`` artifact, GitLab ingests every entry as a Vulnerability,
# powers the merge-request *Security* widget, the project *Vulnerability
# Report*, and any merge-request approval rule that gates on severity. The
# schema is versioned (``security-report-schemas`` v15.x at time of writing).
# omen targets v15 — the latest stable major as of 2026 — and pins the version
# string so a consumer can validate it. The two GitLab-facing formats omen now
# offers are complementary: ``--format checkstyle`` reaches GitLab's *Code
# Quality* widget (the diff-side issue list a reviewer sees in the MR), and
# ``--format gitlab-sast`` reaches GitLab's *Security* surface (vulnerability
# management, security dashboard, severity-based MR approval gates) — two
# different GitLab UIs with no overlap, the same way ``sarif`` and ``gha``
# cover two different GitHub UIs.

# omen severity (informational/low/medium/high/critical) -> GitLab SAST
# severity (Info/Low/Medium/High/Critical). GitLab also allows "Unknown",
# which we never emit (every omen finding has a known severity). The mapping
# is one-to-one in the natural worst-first order, matching how `to_sonarqube`
# projects onto SonarQube's five levels — lossless in practice.
_SEVERITY_TO_GITLAB_SAST = {
    Severity.CRITICAL.value: "Critical",
    Severity.HIGH.value: "High",
    Severity.MEDIUM.value: "Medium",
    Severity.LOW.value: "Low",
    Severity.INFORMATIONAL.value: "Info",
}

# GitLab SAST report schema version omen targets. v15 is the latest stable
# major in the security-report-schemas repo as of 2026 and is what current
# GitLab CE/EE releases ingest. Pinning a precise patch version keeps the
# document validatable; bumping the patch is a single-line change here.
_GITLAB_SAST_SCHEMA_VERSION = "15.0.0"

# GitLab SAST schema requires ``scan.start_time``/``scan.end_time`` even when
# they are not meaningful to the consumer (the project dashboard already
# tracks pipeline timing). To keep the formatter pure / byte-stable / testable
# — the rest of omen's formatters take no clock dependency, and a varying
# timestamp would make every report differ — we emit a deterministic epoch
# sentinel. Real wall-clock timing belongs to the CI runner, which already
# stamps the pipeline; the SAST report is a content artifact, not a timing
# record.
_GITLAB_SAST_EPOCH = "1970-01-01T00:00:00"


def _gitlab_sast_location(f: Finding) -> "dict | None":
    """Build the GitLab SAST ``location`` block for a finding.

    GitLab's SAST schema requires every vulnerability to carry a ``location``
    with at least a ``file`` (and recommends ``start_line``/``end_line``).
    Source-mode findings parse the file path and 1-based line range from
    omen's ``Contract.sol#start-end`` mapping (the same shape every other
    location-aware formatter consumes). Bytecode-mode findings have no file
    to anchor to — GitLab has no concept of "an opcode offset is the
    location" — so we return ``None`` and the caller skips the finding, the
    honest "this format cannot represent that finding" failure mode parallel
    to the SonarQube formatter's bytecode handling.
    """
    if not f.evidence.source_mapping:
        return None
    loc = f.evidence.source_mapping[0]
    file_path = loc
    start: int | None = None
    end: int | None = None
    if "#" in loc:
        file_path, _, span = loc.partition("#")
        start_s, _, end_s = span.partition("-")
        try:
            start = int(start_s)
        except ValueError:
            start = None
        try:
            end = int(end_s) if end_s else None
        except ValueError:
            end = None
    if not file_path:
        return None
    location: dict = {"file": file_path}
    if start is not None:
        location["start_line"] = start
        # GitLab's schema treats end_line as optional; we set it only when
        # the mapping carries a real range, so a single-line finding doesn't
        # synthesize a fake end.
        if end is not None:
            location["end_line"] = end
    return location


def _gitlab_sast_identifiers(f: Finding) -> "list[dict]":
    """Build the GitLab SAST ``identifiers`` list for a finding.

    GitLab uses ``identifiers`` for vulnerability deduplication across runs
    and for cross-tool correlation (two scanners reporting the "same" CWE
    show as one vulnerability). The schema requires each identifier to have
    a ``type``, ``name``, and ``value``; ``url`` is optional. omen emits two:

      - ``omen_category`` carrying the omen detection class (e.g.
        ``reentrancy``) — this is the *grouping* identifier, so GitLab's
        Vulnerability Report can filter on omen's category taxonomy.
      - ``omen_detector`` carrying the underlying Slither detector id (e.g.
        ``slither:reentrancy-eth``) — the *precise* identifier, distinguishing
        two findings of the same omen category produced by different
        underlying checks (parallel to how ``sonarqube``'s ``ruleId`` combines
        category + detector).

    A finding with an empty detector emits only the category identifier so
    the list is never empty (GitLab requires at least one identifier).
    """
    identifiers: list[dict] = [
        {
            "type": "omen_category",
            "name": f"omen category: {f.category}",
            "value": f.category,
        }
    ]
    detector = (f.detector or "").strip()
    if detector:
        identifiers.append(
            {
                "type": "omen_detector",
                "name": f"omen detector: {detector}",
                "value": detector,
            }
        )
    return identifiers


def _gitlab_sast_vulnerability_id(f: Finding) -> str:
    """Stable per-finding id for the GitLab SAST ``id`` field.

    GitLab requires each vulnerability to carry an ``id`` that is stable
    across runs (it uses the id to track a vulnerability's lifecycle —
    detected, confirmed, dismissed, resolved). We reuse the same
    fingerprint primitive ``--baseline`` / ``--diff`` / ``--sarif-baseline``
    use (``finding_fingerprint``), so the same finding gets the same id
    across runs, and the id matches the identity GitLab's own
    vulnerability-tracking logic should treat as stable. Returning the raw
    fingerprint string keeps the id human-readable in the JSON (it is a
    ``|``-joined ``category|detector|contract|location`` string), and is
    valid per the SAST schema, which constrains ``id`` only to be a
    non-empty string.
    """
    return finding_fingerprint(f)


def to_gitlab_sast(report: AnalysisReport, *, indent: int = 2) -> str:
    """Render the report as a GitLab SAST Report v15 JSON document.

    POST_V01 R3.9. One JSON document with a fixed top-level shape
    (``version``, ``scan``, ``vulnerabilities``); one entry in
    ``vulnerabilities`` per finding in the report's existing worst-first
    order (the formatter never re-orders or re-filters — a pure formatter
    over ``report.findings`` like every other format).

    The output schema matches GitLab's `SAST Report v15
    <https://gitlab.com/gitlab-org/security-products/security-report-schemas>`_,
    which GitLab CE/EE ingests directly when uploaded as the ``reports:sast``
    job artifact. Each vulnerability carries:

      - ``id``: a stable per-finding fingerprint (the same one
        ``--baseline``/``--diff`` use), so GitLab can track a finding's
        lifecycle across runs.
      - ``category``: always ``"sast"`` (the GitLab artifact bucket; omen is
        a static analyzer for security weaknesses).
      - ``name``/``message``: the finding's title — the short summary
        GitLab's Vulnerability Report shows in the row.
      - ``description``: the finding's description — the longer body shown
        when the row is expanded.
      - ``severity``: one of ``Critical``/``High``/``Medium``/``Low``/``Info``
        — omen's five-level taxonomy maps onto GitLab's five one-to-one
        (informational → ``Info``, otherwise the title-cased name). GitLab's
        merge-request approval rules can gate on this severity.
      - ``scanner``: ``{id: "omen", name: "omen"}`` — the engine label
        GitLab groups external scanners under.
      - ``identifiers``: omen category + detector identifiers, for GitLab's
        deduplication and cross-tool correlation.
      - ``location``: ``file`` (+ optional ``start_line``/``end_line``), the
        GitLab-required anchor.

    Unlike ``--format checkstyle`` (which reaches GitLab via the *Code
    Quality* artifact — a diff-side review-comment widget), ``--format
    gitlab-sast`` targets GitLab's *Security* surface (the Vulnerability
    Report, the security dashboard, severity-based MR approval gates). Two
    different GitLab UIs with no overlap; both are free on every GitLab
    tier.

    Bytecode-mode findings carry no source mapping (no ``file``) and the
    GitLab SAST schema requires ``location.file``, so they are skipped —
    they cannot be projected without inventing a fake path. A report
    containing only bytecode-mode findings therefore emits a well-formed
    empty-vulnerabilities document, the same shape a clean scan produces;
    the caller can prefer ``--format json``/``sarif`` for full coverage of
    a bytecode scan.

    The ``scan`` block's ``start_time``/``end_time`` are emitted as a
    deterministic epoch sentinel (``"1970-01-01T00:00:00"``) rather than a
    wall-clock timestamp, so the report is byte-stable across runs (the
    same property every other omen formatter has) and the formatter takes
    no clock dependency. Real pipeline timing belongs to the CI runner,
    which already stamps it; the SAST report is a content artifact.
    """
    vendor = {"name": "omen"}
    analyzer = {
        "id": "omen",
        "name": "omen",
        "version": __version__,
        "vendor": vendor,
    }
    scanner = {
        "id": "omen",
        "name": "omen",
        "version": __version__,
        "vendor": vendor,
    }
    scanner_short = {"id": "omen", "name": "omen"}

    vulnerabilities: list[dict] = []
    for f in report.findings:
        location = _gitlab_sast_location(f)
        if location is None:
            # No file available (bytecode mode). Skip rather than emit a
            # GitLab-invalid vulnerability.
            continue
        title = f.title or f.category
        vulnerabilities.append(
            {
                "id": _gitlab_sast_vulnerability_id(f),
                "category": "sast",
                "name": title,
                "message": title,
                "description": f.description or title,
                "severity": _SEVERITY_TO_GITLAB_SAST.get(f.severity.value, "Unknown"),
                "scanner": scanner_short,
                "identifiers": _gitlab_sast_identifiers(f),
                "location": location,
            }
        )

    document = {
        "version": _GITLAB_SAST_SCHEMA_VERSION,
        "scan": {
            "analyzer": analyzer,
            "scanner": scanner,
            "type": "sast",
            "start_time": _GITLAB_SAST_EPOCH,
            "end_time": _GITLAB_SAST_EPOCH,
            "status": "success",
        },
        "vulnerabilities": vulnerabilities,
    }
    return json.dumps(document, indent=indent, sort_keys=False)


def render(
    report: AnalysisReport,
    fmt: str,
    *,
    sarif_baseline: "set[str] | None" = None,
) -> str:
    """Render *report* in format *fmt*.

    *sarif_baseline* (POST_V01 R3.3) is only meaningful for ``fmt == "sarif"``:
    a set of finding fingerprints that drives the per-result ``baselineState``
    annotation (``--sarif-baseline``). It is ignored for the other formats —
    ``baselineState`` is a SARIF concept with no analogue in text/json/h1md.
    """
    if fmt == "text":
        return to_text(report)
    if fmt == "json":
        return to_json(report)
    if fmt == "h1md":
        return to_h1md(report)
    if fmt == "sarif":
        return to_sarif(report, baseline=sarif_baseline)
    if fmt == "gha":
        return to_gha(report)
    if fmt == "junit":
        return to_junit(report)
    if fmt == "checkstyle":
        return to_checkstyle(report)
    if fmt == "sonarqube":
        return to_sonarqube(report)
    if fmt == "gitlab-sast":
        return to_gitlab_sast(report)
    raise ValueError(f"unknown output format: {fmt}")
