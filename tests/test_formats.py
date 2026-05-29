"""Output format tests: text, JSON, H1-markdown, and SARIF."""

from __future__ import annotations

import json

from omen.analyzer import AnalysisReport
from omen.findings import Evidence, Finding, Severity
from omen.formats import render, to_gha, to_h1md, to_json, to_sarif, to_text


def _report() -> AnalysisReport:
    return AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="bytecode",
        origin="x.bin",
        checks=["suicidal"],
        findings=[
            Finding(
                category="suicidal",
                severity=Severity.HIGH,
                title="suicidal contract",
                description="selfdestruct present",
                detector="omen:bytecode-selfdestruct",
                contract="0xabc",
                confidence="high",
                evidence=Evidence(opcodes=[{"opcode": "SELFDESTRUCT", "offset": 16}]),
            )
        ],
    )


def test_json_is_valid_and_has_findings():
    text = to_json(_report())
    data = json.loads(text)
    assert data["tool"] == "omen"
    assert data["finding_count"] == 1
    assert data["findings"][0]["category"] == "suicidal"
    assert data["findings"][0]["severity"] == "high"


def test_h1md_contains_sections():
    md = to_h1md(_report())
    assert "# omen report" in md
    assert "suicidal" in md
    assert "Remediation" in md
    assert "Evidence" in md


def test_render_dispatch():
    assert render(_report(), "json").startswith("{")
    assert render(_report(), "h1md").startswith("#")
    assert render(_report(), "sarif").startswith("{")
    assert render(_report(), "text").startswith("omen ")
    assert render(_report(), "gha").startswith("::")


# --- text format (POST_V01 Rotation 2, R2.6) ------------------------------


def test_text_has_header_summary_and_finding_line():
    text = to_text(_report())
    lines = text.splitlines()
    # header line 1: tool/version/origin
    assert lines[0].startswith("omen ")
    assert "x.bin" in lines[0]
    # input/checks line
    assert "input: bytecode" in text
    assert "checks: suicidal" in text
    # summary line with per-severity count
    assert "findings: 1" in text
    assert "1 high" in text
    # finding line: index, upper-cased severity, category, confidence
    finding_line = next(l for l in lines if l.lstrip().startswith("1."))
    assert "HIGH" in finding_line
    assert "suicidal" in finding_line
    assert "[high]" in finding_line  # confidence in brackets


def test_text_bytecode_finding_shows_opcode_offset():
    # _report() is a bytecode finding with an opcode at offset 16 (0x10).
    text = to_text(_report())
    assert "@0x10" in text


def test_text_source_finding_shows_source_location():
    text = to_text(_source_report())
    # source mappings from _source_report(): Vuln.sol#12-18 and Vuln.sol#25
    assert "Vuln.sol#12-18" in text
    assert "Vuln.sol#25" in text


def test_text_summary_is_worst_first_and_counts_each_severity():
    # _source_report() has one high and one medium finding.
    text = to_text(_source_report())
    summary = next(l for l in text.splitlines() if l.startswith("findings:"))
    assert "1 high" in summary
    assert "1 medium" in summary
    # worst-first ordering inside the summary: high appears before medium.
    assert summary.index("1 high") < summary.index("1 medium")


def test_text_finding_lines_are_one_per_finding_in_report_order():
    report = _source_report()
    text = to_text(report)
    numbered = [l for l in text.splitlines() if l.lstrip()[:2] in ("1.", "2.")]
    assert len(numbered) == 2
    # first finding line is the high (access-control), second the medium.
    assert "access-control" in numbered[0]
    assert "tx-origin" in numbered[1]


def test_text_empty_report_says_no_findings():
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="Clean.sol",
        checks=["all"],
        findings=[],
    )
    text = to_text(report)
    assert "findings: 0" in text
    assert "none" in text  # empty summary reads "none"
    assert "No findings" in text


def test_text_reports_limit_truncation_like_h1md():
    # A report where --limit dropped findings: total > shown.
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="Vuln.sol",
        checks=["all"],
        findings=[
            Finding(
                category="suicidal",
                severity=Severity.HIGH,
                title="t",
                description="d",
                detector="slither:suicidal",
                contract="Vuln",
                confidence="high",
                evidence=Evidence(source_mapping=["Vuln.sol#1-2"]),
            )
        ],
        total_findings=5,
    )
    text = to_text(report)
    assert "1 of 5" in text
    assert "--limit" in text


def _source_report() -> AnalysisReport:
    """A source-mode report with a high and a medium finding, both with
    source-mapping locations, to exercise the SARIF location + level mapping."""
    return AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="Vuln.sol",
        checks=["access-control", "tx-origin"],
        findings=[
            Finding(
                category="access-control",
                severity=Severity.HIGH,
                title="access-control contract (protected-vars)",
                description="missing onlyOwner guard",
                detector="slither:protected-vars",
                contract="Vuln",
                confidence="high",
                evidence=Evidence(source_mapping=["Vuln.sol#12-18"]),
            ),
            Finding(
                category="tx-origin",
                severity=Severity.MEDIUM,
                title="tx-origin contract (tx-origin)",
                description="tx.origin used for auth",
                detector="slither:tx-origin",
                contract="Vuln",
                confidence="medium",
                evidence=Evidence(source_mapping=["Vuln.sol#25"]),
            ),
        ],
    )


def test_sarif_is_valid_2_1_0_envelope():
    data = json.loads(to_sarif(_source_report()))
    assert data["version"] == "2.1.0"
    assert "$schema" in data
    assert len(data["runs"]) == 1
    driver = data["runs"][0]["tool"]["driver"]
    assert driver["name"] == "omen"
    assert driver["version"]  # non-empty
    assert isinstance(driver["rules"], list)


def test_sarif_one_result_per_finding():
    data = json.loads(to_sarif(_source_report()))
    results = data["runs"][0]["results"]
    assert len(results) == 2
    rule_ids = {r["ruleId"] for r in results}
    assert rule_ids == {"omen/access-control", "omen/tx-origin"}


def test_sarif_severity_maps_to_level():
    data = json.loads(to_sarif(_source_report()))
    by_rule = {r["ruleId"]: r for r in data["runs"][0]["results"]}
    # high -> error, medium -> warning
    assert by_rule["omen/access-control"]["level"] == "error"
    assert by_rule["omen/tx-origin"]["level"] == "warning"


def test_sarif_results_carry_locations_and_regions():
    data = json.loads(to_sarif(_source_report()))
    ac = next(
        r for r in data["runs"][0]["results"] if r["ruleId"] == "omen/access-control"
    )
    loc = ac["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "Vuln.sol"
    assert loc["region"]["startLine"] == 12
    assert loc["region"]["endLine"] == 18


def test_sarif_rules_dedupe_and_carry_security_severity():
    # Two findings of the SAME category -> one rule in the driver.
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="Vuln.sol",
        checks=["access-control"],
        findings=[
            Finding(
                category="access-control",
                severity=Severity.HIGH,
                title="a",
                description="d",
                detector="slither:protected-vars",
                contract="Vuln",
                confidence="high",
                evidence=Evidence(source_mapping=["Vuln.sol#1-2"]),
            ),
            Finding(
                category="access-control",
                severity=Severity.HIGH,
                title="b",
                description="d2",
                detector="slither:events-access",
                contract="Vuln",
                confidence="high",
                evidence=Evidence(source_mapping=["Vuln.sol#5-6"]),
            ),
        ],
    )
    data = json.loads(to_sarif(report))
    rules = data["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert rules[0]["id"] == "omen/access-control"
    assert rules[0]["properties"]["security-severity"] == "8.0"
    assert len(data["runs"][0]["results"]) == 2


def test_sarif_bytecode_finding_has_no_location_but_keeps_opcodes():
    # The default _report() is a bytecode finding (opcodes, no source mapping).
    data = json.loads(to_sarif(_report()))
    result = data["runs"][0]["results"][0]
    assert "locations" not in result
    assert result["properties"]["opcodes"][0]["opcode"] == "SELFDESTRUCT"
    assert result["properties"]["confidence"] == "high"


def test_sarif_empty_report_is_valid():
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="Clean.sol",
        checks=["all"],
        findings=[],
    )
    data = json.loads(to_sarif(report))
    assert data["runs"][0]["results"] == []
    assert data["runs"][0]["tool"]["driver"]["rules"] == []


# --- gha format: GitHub Actions workflow-command annotations (R3.5) --------


def test_gha_one_command_per_finding_in_report_order():
    # _source_report() has a high then a medium finding, in that order.
    text = to_gha(_source_report())
    lines = text.splitlines()
    assert len(lines) == 2
    # every line is a workflow command
    assert all(line.startswith("::") for line in lines)


def test_gha_severity_maps_to_level():
    # high -> ::error, medium -> ::warning
    lines = to_gha(_source_report()).splitlines()
    assert lines[0].startswith("::error ")
    assert lines[1].startswith("::warning ")


def test_gha_low_and_informational_map_to_notice():
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="Vuln.sol",
        checks=["overflow"],
        findings=[
            Finding(
                category="overflow",
                severity=Severity.LOW,
                title="t",
                description="d",
                detector="slither:divide-before-multiply",
                contract="Vuln",
                confidence="low",
                evidence=Evidence(source_mapping=["Vuln.sol#4-5"]),
            ),
            Finding(
                category="overflow",
                severity=Severity.INFORMATIONAL,
                title="t2",
                description="d2",
                detector="slither:tautology",
                contract="Vuln",
                confidence="low",
                evidence=Evidence(source_mapping=["Vuln.sol#9"]),
            ),
        ],
    )
    lines = to_gha(report).splitlines()
    assert lines[0].startswith("::notice ")
    assert lines[1].startswith("::notice ")


def test_gha_source_finding_carries_file_and_line_range():
    # access-control finding maps to Vuln.sol#12-18.
    line = to_gha(_source_report()).splitlines()[0]
    assert "file=Vuln.sol" in line
    assert "line=12" in line
    assert "endLine=18" in line


def test_gha_single_line_mapping_has_no_endline():
    # tx-origin finding maps to Vuln.sol#25 (no end line).
    line = to_gha(_source_report()).splitlines()[1]
    assert "file=Vuln.sol" in line
    assert "line=25" in line
    assert "endLine=" not in line


def test_gha_title_carries_severity_category_and_confidence():
    line = to_gha(_source_report()).splitlines()[0]
    assert "title=omen high%3A access-control [high]" in line


def test_gha_message_is_after_the_double_colon():
    line = to_gha(_source_report()).splitlines()[0]
    # The data segment follows the final '::' separator.
    _, _, message = line.partition("::")  # strip leading '::'
    _, _, message = message.partition("::")  # split off the data segment
    assert message == "missing onlyOwner guard"


def test_gha_bytecode_finding_has_no_file_anchor():
    # The default _report() is a bytecode finding (opcodes, no source mapping).
    line = to_gha(_report()).splitlines()[0]
    assert line.startswith("::error ")  # high severity
    assert "file=" not in line
    assert "line=" not in line
    # still self-describing via the title
    assert "title=omen high%3A suicidal [high]" in line


def test_gha_escapes_newlines_and_percent_in_message():
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="Vuln.sol",
        checks=["reentrancy"],
        findings=[
            Finding(
                category="reentrancy",
                severity=Severity.HIGH,
                title="t",
                description="line one\nline two 100% sure",
                detector="slither:reentrancy-eth",
                contract="Vuln",
                confidence="high",
                evidence=Evidence(source_mapping=["Vuln.sol#1-2"]),
            )
        ],
    )
    line = to_gha(report).splitlines()[0]
    # newline and percent are escaped so the command stays on one line
    assert "\n" not in line
    assert "%0A" in line
    assert "%25" in line


def test_gha_escapes_colon_and_comma_in_file_property():
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="weird",
        checks=["reentrancy"],
        findings=[
            Finding(
                category="reentrancy",
                severity=Severity.HIGH,
                title="t",
                description="d",
                detector="slither:reentrancy-eth",
                contract="Vuln",
                confidence="high",
                evidence=Evidence(source_mapping=["a,b:c.sol#3"]),
            )
        ],
    )
    line = to_gha(report).splitlines()[0]
    # the comma and colon in the path are escaped so they do not split props
    assert "file=a%2Cb%3Ac.sol" in line
    assert "line=3" in line


def test_gha_empty_report_emits_a_single_notice():
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="Clean.sol",
        checks=["all"],
        findings=[],
    )
    text = to_gha(report)
    lines = text.splitlines()
    assert len(lines) == 1
    assert lines[0].startswith("::notice ")
    assert "Clean.sol" in lines[0]
    assert "no findings" in lines[0]


def test_gha_render_dispatch_matches_to_gha():
    assert render(_source_report(), "gha") == to_gha(_source_report())
