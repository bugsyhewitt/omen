"""Output format tests: text, JSON, H1-markdown, SARIF, gha, junit, checkstyle, sonarqube, gitlab-sast."""

from __future__ import annotations

import json
from xml.etree import ElementTree as ET

from omen.analyzer import AnalysisReport
from omen.findings import Evidence, Finding, Severity
from omen.formats import (
    render,
    to_checkstyle,
    to_gha,
    to_gitlab_sast,
    to_h1md,
    to_json,
    to_junit,
    to_sarif,
    to_sonarqube,
    to_text,
)


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
    assert render(_report(), "junit").lstrip().startswith("<?xml")
    assert render(_report(), "checkstyle").lstrip().startswith("<?xml")
    assert render(_report(), "sonarqube").startswith("{")
    assert render(_report(), "gitlab-sast").startswith("{")


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


# --- junit format: JUnit XML test-results report (R3.6) --------------------


def test_junit_is_well_formed_xml_with_testsuite():
    xml = to_junit(_source_report())
    assert xml.startswith("<?xml")
    root = ET.fromstring(xml)  # parses => well-formed
    assert root.tag == "testsuite"
    assert root.get("name") == "omen"


def test_junit_one_failing_testcase_per_finding():
    # _source_report() has two findings (high + medium).
    root = ET.fromstring(to_junit(_source_report()))
    assert root.get("tests") == "2"
    # every finding is a failure (omen only emits findings, never passes)
    assert root.get("failures") == "2"
    cases = root.findall("testcase")
    assert len(cases) == 2
    # each testcase carries exactly one <failure>
    for case in cases:
        assert len(case.findall("failure")) == 1


def test_junit_testcases_are_in_report_order():
    root = ET.fromstring(to_junit(_source_report()))
    cases = root.findall("testcase")
    # report order: access-control (high) then tx-origin (medium)
    assert "access-control" in cases[0].get("name")
    assert "tx-origin" in cases[1].get("name")


def test_junit_classname_buckets_by_category():
    root = ET.fromstring(to_junit(_source_report()))
    classnames = {c.get("classname") for c in root.findall("testcase")}
    assert classnames == {"omen.access-control", "omen.tx-origin"}


def test_junit_failure_carries_severity_in_type_and_message():
    root = ET.fromstring(to_junit(_source_report()))
    ac = next(
        c for c in root.findall("testcase") if "access-control" in c.get("name")
    )
    failure = ac.find("failure")
    # severity is preserved verbatim in the failure type
    assert failure.get("type") == "high"
    # the failure message is the finding description's first line
    assert failure.get("message") == "missing onlyOwner guard"
    # the body header carries severity + detector for triage context
    assert "severity: high" in failure.text
    assert "slither:protected-vars" in failure.text


def test_junit_testcase_name_carries_location():
    root = ET.fromstring(to_junit(_source_report()))
    ac = next(
        c for c in root.findall("testcase") if "access-control" in c.get("name")
    )
    # source-mode finding pins to its source mapping
    assert "Vuln.sol#12-18" in ac.get("name")


def test_junit_bytecode_finding_uses_opcode_offset_location():
    # The default _report() is a bytecode finding (opcode at offset 16 = 0x10).
    root = ET.fromstring(to_junit(_report()))
    case = root.find("testcase")
    assert "@0x10" in case.get("name")


def test_junit_empty_report_is_a_green_suite():
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="Clean.sol",
        checks=["all"],
        findings=[],
    )
    root = ET.fromstring(to_junit(report))
    assert root.get("failures") == "0"
    # a single passing testcase records that omen ran (no <failure> child)
    cases = root.findall("testcase")
    assert len(cases) == 1
    assert cases[0].find("failure") is None
    assert "Clean.sol" in cases[0].get("name")


def test_junit_escapes_special_xml_chars():
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
                description='use <SafeMath> & "guards" not raw a < b',
                detector="slither:reentrancy-eth",
                contract="Vuln",
                confidence="high",
                evidence=Evidence(source_mapping=["A&B.sol#1-2"]),
            )
        ],
    )
    xml = to_junit(report)
    # raw angle brackets / ampersands from content must not appear unescaped
    assert "<SafeMath>" not in xml
    assert "A&B.sol" not in xml  # the bare ampersand is escaped to &amp;
    # still parses as well-formed XML and round-trips the content
    root = ET.fromstring(xml)
    failure = root.find("testcase").find("failure")
    assert '<SafeMath>' in failure.text
    assert "A&B.sol#1-2" in root.find("testcase").get("name")


def test_junit_render_dispatch_matches_to_junit():
    assert render(_source_report(), "junit") == to_junit(_source_report())


# --- checkstyle format: Checkstyle XML code-review annotations (R3.7) ------


def test_checkstyle_is_well_formed_xml_with_checkstyle_root():
    xml = to_checkstyle(_source_report())
    assert xml.startswith("<?xml")
    root = ET.fromstring(xml)
    assert root.tag == "checkstyle"
    # Version attribute carried so downstream consumers (GitLab Code Quality,
    # Reviewdog, Jenkins, SonarQube) read a recognised document.
    assert root.get("version")


def test_checkstyle_one_error_per_finding_grouped_by_file():
    # _source_report() has two findings, both anchored to Vuln.sol — they
    # should be grouped under a single <file>.
    root = ET.fromstring(to_checkstyle(_source_report()))
    files = root.findall("file")
    assert len(files) == 1
    assert files[0].get("name") == "Vuln.sol"
    errors = files[0].findall("error")
    assert len(errors) == 2


def test_checkstyle_errors_are_in_report_order_within_a_file():
    # report order: access-control (high) then tx-origin (medium).
    root = ET.fromstring(to_checkstyle(_source_report()))
    errors = root.find("file").findall("error")
    # source attribute holds the detector identity; verify order via that.
    assert errors[0].get("source") == "slither:protected-vars"
    assert errors[1].get("source") == "slither:tx-origin"


def test_checkstyle_severity_maps_to_three_levels():
    # high -> error, medium -> warning. (Critical -> error and low/info -> info
    # are exercised by the explicit table-mapping test below.)
    root = ET.fromstring(to_checkstyle(_source_report()))
    errors = root.find("file").findall("error")
    by_source = {e.get("source"): e for e in errors}
    assert by_source["slither:protected-vars"].get("severity") == "error"
    assert by_source["slither:tx-origin"].get("severity") == "warning"


def test_checkstyle_full_severity_mapping_table():
    # Build one finding per omen severity to lock the projection onto
    # Checkstyle's three levels: critical/high -> error, medium -> warning,
    # low/informational -> info.
    findings: list[Finding] = []
    for sev in (
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFORMATIONAL,
    ):
        findings.append(
            Finding(
                category="suicidal",
                severity=sev,
                title=f"t-{sev.value}",
                description=f"d-{sev.value}",
                detector=f"slither:{sev.value}",
                contract="Vuln",
                confidence="high",
                evidence=Evidence(source_mapping=[f"Vuln.sol#{1}-{2}"]),
            )
        )
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="Vuln.sol",
        checks=["suicidal"],
        findings=findings,
    )
    root = ET.fromstring(to_checkstyle(report))
    levels = [e.get("severity") for e in root.find("file").findall("error")]
    assert levels == ["error", "error", "warning", "info", "info"]


def test_checkstyle_preserves_original_severity_verbatim():
    # The five-level omen severity is preserved in the omen-severity attribute
    # so the three-level Checkstyle projection is lossless.
    root = ET.fromstring(to_checkstyle(_source_report()))
    errors = root.find("file").findall("error")
    by_source = {e.get("source"): e for e in errors}
    assert by_source["slither:protected-vars"].get("omen-severity") == "high"
    assert by_source["slither:tx-origin"].get("omen-severity") == "medium"
    # Category and confidence are also preserved on each <error>.
    assert by_source["slither:protected-vars"].get("omen-category") == "access-control"
    assert by_source["slither:protected-vars"].get("omen-confidence") == "high"
    assert by_source["slither:tx-origin"].get("omen-confidence") == "medium"


def test_checkstyle_source_finding_carries_line_and_file():
    root = ET.fromstring(to_checkstyle(_source_report()))
    file_node = root.find("file")
    assert file_node.get("name") == "Vuln.sol"
    errors = file_node.findall("error")
    # access-control source mapping is Vuln.sol#12-18 -> line=12 (Checkstyle
    # has no native endLine attribute; line points to the issue's primary line).
    ac = next(e for e in errors if e.get("source") == "slither:protected-vars")
    assert ac.get("line") == "12"
    tx = next(e for e in errors if e.get("source") == "slither:tx-origin")
    assert tx.get("line") == "25"


def test_checkstyle_carries_message_from_description():
    root = ET.fromstring(to_checkstyle(_source_report()))
    errors = root.find("file").findall("error")
    by_source = {e.get("source"): e for e in errors}
    assert by_source["slither:protected-vars"].get("message") == "missing onlyOwner guard"


def test_checkstyle_bytecode_finding_anchors_to_contract_with_no_line():
    # The default _report() is a bytecode finding (opcodes, no source mapping)
    # whose contract identifier is "0xabc". Checkstyle is file-keyed, so the
    # finding must anchor to *some* file — we use the contract address as the
    # file name and omit the line attribute (a bytecode finding has no line).
    root = ET.fromstring(to_checkstyle(_report()))
    files = root.findall("file")
    assert len(files) == 1
    assert files[0].get("name") == "0xabc"
    error = files[0].find("error")
    # No source mapping => no line attribute.
    assert error.get("line") is None
    # Severity still projects (high -> error).
    assert error.get("severity") == "error"
    # And the original omen severity is still preserved verbatim.
    assert error.get("omen-severity") == "high"


def test_checkstyle_findings_in_different_files_get_separate_file_elements():
    # Two findings, two source files -> two <file> elements, one <error> in each.
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="<project>",
        checks=["all"],
        findings=[
            Finding(
                category="suicidal",
                severity=Severity.HIGH,
                title="t",
                description="d",
                detector="slither:suicidal",
                contract="A",
                confidence="high",
                evidence=Evidence(source_mapping=["A.sol#1-2"]),
            ),
            Finding(
                category="reentrancy",
                severity=Severity.HIGH,
                title="t",
                description="d",
                detector="slither:reentrancy-eth",
                contract="B",
                confidence="high",
                evidence=Evidence(source_mapping=["B.sol#5-6"]),
            ),
        ],
    )
    root = ET.fromstring(to_checkstyle(report))
    file_names = [f.get("name") for f in root.findall("file")]
    assert file_names == ["A.sol", "B.sol"]
    for file_node in root.findall("file"):
        assert len(file_node.findall("error")) == 1


def test_checkstyle_multiple_findings_same_file_share_one_file_element():
    # Same file, two findings -> one <file> with two <error> children (the
    # standard Checkstyle grouping convention every consumer expects).
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
                title="t1",
                description="d1",
                detector="slither:suicidal",
                contract="Vuln",
                confidence="high",
                evidence=Evidence(source_mapping=["Vuln.sol#10-12"]),
            ),
            Finding(
                category="reentrancy",
                severity=Severity.HIGH,
                title="t2",
                description="d2",
                detector="slither:reentrancy-eth",
                contract="Vuln",
                confidence="high",
                evidence=Evidence(source_mapping=["Vuln.sol#30-35"]),
            ),
        ],
    )
    root = ET.fromstring(to_checkstyle(report))
    files = root.findall("file")
    assert len(files) == 1
    assert files[0].get("name") == "Vuln.sol"
    assert len(files[0].findall("error")) == 2


def test_checkstyle_empty_report_is_a_valid_document_with_no_files():
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="Clean.sol",
        checks=["all"],
        findings=[],
    )
    xml = to_checkstyle(report)
    root = ET.fromstring(xml)
    assert root.tag == "checkstyle"
    # No findings -> no <file> children. The document is still well-formed:
    # every Checkstyle consumer reads "scan ran, found nothing" from this shape.
    assert root.findall("file") == []


def test_checkstyle_escapes_special_xml_chars():
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
                description='use <SafeMath> & "guards" not raw a < b',
                detector="slither:reentrancy-eth",
                contract="Vuln",
                confidence="high",
                evidence=Evidence(source_mapping=["A&B.sol#1-2"]),
            )
        ],
    )
    xml = to_checkstyle(report)
    # Raw special chars from the content must not appear unescaped in the doc.
    assert "<SafeMath>" not in xml
    # The bare ampersand must be escaped (no naked "A&B.sol" as an attr value).
    assert 'name="A&B.sol"' not in xml
    # Still parses as well-formed XML and round-trips the content.
    root = ET.fromstring(xml)
    file_node = root.find("file")
    assert file_node.get("name") == "A&B.sol"
    error = file_node.find("error")
    assert "<SafeMath>" in error.get("message")
    assert '"guards"' in error.get("message")


def test_checkstyle_collapses_newlines_in_message():
    # Checkstyle messages are conventionally single-line; a multi-line omen
    # description must not break the attribute layout for consumers that render
    # the message inline (GitLab Code Quality, Reviewdog).
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
                description="line one\nline two\r\nline three",
                detector="slither:reentrancy-eth",
                contract="Vuln",
                confidence="high",
                evidence=Evidence(source_mapping=["Vuln.sol#1-2"]),
            )
        ],
    )
    xml = to_checkstyle(report)
    root = ET.fromstring(xml)
    message = root.find("file").find("error").get("message")
    assert "\n" not in message
    assert "\r" not in message
    assert "line one" in message and "line three" in message


def test_checkstyle_render_dispatch_matches_to_checkstyle():
    assert render(_source_report(), "checkstyle") == to_checkstyle(_source_report())


# --- sonarqube format (POST_V01 R3.8) ------------------------------------


def test_sonarqube_is_valid_json_with_issues_array():
    data = json.loads(to_sonarqube(_source_report()))
    assert isinstance(data, dict)
    assert isinstance(data["issues"], list)
    assert len(data["issues"]) == 2


def test_sonarqube_one_issue_per_finding_in_report_order():
    # _source_report() has access-control (high) then tx-origin (medium).
    issues = json.loads(to_sonarqube(_source_report()))["issues"]
    # rule ids are <category>:<detector>; verify order via ruleId.
    assert issues[0]["ruleId"] == "access-control:slither:protected-vars"
    assert issues[1]["ruleId"] == "tx-origin:slither:tx-origin"


def test_sonarqube_severity_maps_h1_to_sonarqube_five_to_five():
    # critical -> BLOCKER, high -> CRITICAL, medium -> MAJOR,
    # low -> MINOR, informational -> INFO.
    findings: list[Finding] = []
    for sev in (
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFORMATIONAL,
    ):
        findings.append(
            Finding(
                category="suicidal",
                severity=sev,
                title=f"t-{sev.value}",
                description=f"d-{sev.value}",
                detector=f"slither:{sev.value}",
                contract="Vuln",
                confidence="high",
                evidence=Evidence(source_mapping=[f"Vuln.sol#{1}-{2}"]),
            )
        )
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="Vuln.sol",
        checks=["suicidal"],
        findings=findings,
    )
    severities = [i["severity"] for i in json.loads(to_sonarqube(report))["issues"]]
    assert severities == ["BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"]


def test_sonarqube_type_is_vulnerability_for_every_issue():
    # Every omen finding is a smart-contract security weakness -> VULNERABILITY.
    issues = json.loads(to_sonarqube(_source_report()))["issues"]
    assert all(i["type"] == "VULNERABILITY" for i in issues)


def test_sonarqube_engine_id_is_omen():
    issues = json.loads(to_sonarqube(_source_report()))["issues"]
    assert all(i["engineId"] == "omen" for i in issues)


def test_sonarqube_rule_id_combines_category_and_detector():
    # Two findings of the same category but different detectors should get
    # distinct rule ids so SonarQube's rule filter distinguishes them.
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="Vuln.sol",
        checks=["overflow"],
        findings=[
            Finding(
                category="overflow",
                severity=Severity.MEDIUM,
                title="t",
                description="d",
                detector="slither:divide-before-multiply",
                contract="V",
                confidence="high",
                evidence=Evidence(source_mapping=["V.sol#1-2"]),
            ),
            Finding(
                category="overflow",
                severity=Severity.MEDIUM,
                title="t",
                description="d",
                detector="slither:tautology",
                contract="V",
                confidence="high",
                evidence=Evidence(source_mapping=["V.sol#5-6"]),
            ),
        ],
    )
    issues = json.loads(to_sonarqube(report))["issues"]
    rule_ids = {i["ruleId"] for i in issues}
    assert rule_ids == {
        "overflow:slither:divide-before-multiply",
        "overflow:slither:tautology",
    }


def test_sonarqube_rule_id_falls_back_to_category_when_detector_empty():
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="Vuln.sol",
        checks=["suicidal"],
        findings=[
            Finding(
                category="suicidal",
                severity=Severity.HIGH,
                title="t",
                description="d",
                detector="",
                contract="V",
                confidence="high",
                evidence=Evidence(source_mapping=["V.sol#1-2"]),
            ),
        ],
    )
    issues = json.loads(to_sonarqube(report))["issues"]
    assert issues[0]["ruleId"] == "suicidal"


def test_sonarqube_primary_location_carries_file_path_and_text_range():
    # access-control source mapping in _source_report() is Vuln.sol#12-18.
    issues = json.loads(to_sonarqube(_source_report()))["issues"]
    ac = next(i for i in issues if i["ruleId"].startswith("access-control:"))
    primary = ac["primaryLocation"]
    assert primary["filePath"] == "Vuln.sol"
    assert primary["textRange"] == {"startLine": 12, "endLine": 18}
    assert primary["message"] == "missing onlyOwner guard"


def test_sonarqube_single_line_mapping_has_no_end_line():
    # tx-origin source mapping is Vuln.sol#25 — a single-line location, so the
    # textRange should carry only startLine (no endLine).
    issues = json.loads(to_sonarqube(_source_report()))["issues"]
    tx = next(i for i in issues if i["ruleId"].startswith("tx-origin:"))
    text_range = tx["primaryLocation"]["textRange"]
    assert text_range == {"startLine": 25}


def test_sonarqube_bytecode_finding_is_skipped():
    # SonarQube's generic issue schema strictly requires primaryLocation.filePath.
    # _report() is a bytecode finding (opcodes, no source mapping), so it cannot
    # be represented and must be skipped rather than emit a SonarQube-invalid issue.
    data = json.loads(to_sonarqube(_report()))
    assert data == {"issues": []}


def test_sonarqube_mixed_source_and_bytecode_skips_only_bytecode():
    # A report containing both source-mode and bytecode-mode findings should
    # emit issues for the source ones and silently skip the bytecode ones.
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="<project>",
        checks=["all"],
        findings=[
            Finding(  # bytecode finding (no source mapping) -> skipped
                category="suicidal",
                severity=Severity.HIGH,
                title="t",
                description="d",
                detector="omen:bytecode-selfdestruct",
                contract="0xabc",
                confidence="high",
                evidence=Evidence(opcodes=[{"opcode": "SELFDESTRUCT", "offset": 16}]),
            ),
            Finding(  # source finding -> kept
                category="reentrancy",
                severity=Severity.HIGH,
                title="t",
                description="d",
                detector="slither:reentrancy-eth",
                contract="V",
                confidence="high",
                evidence=Evidence(source_mapping=["V.sol#5-6"]),
            ),
        ],
    )
    issues = json.loads(to_sonarqube(report))["issues"]
    assert len(issues) == 1
    assert issues[0]["ruleId"] == "reentrancy:slither:reentrancy-eth"


def test_sonarqube_empty_report_is_valid_empty_document():
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="Clean.sol",
        checks=["all"],
        findings=[],
    )
    data = json.loads(to_sonarqube(report))
    assert data == {"issues": []}


def test_sonarqube_message_falls_back_to_title_when_description_empty():
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="V.sol",
        checks=["suicidal"],
        findings=[
            Finding(
                category="suicidal",
                severity=Severity.HIGH,
                title="title-fallback",
                description="",
                detector="slither:suicidal",
                contract="V",
                confidence="high",
                evidence=Evidence(source_mapping=["V.sol#1-2"]),
            ),
        ],
    )
    issues = json.loads(to_sonarqube(report))["issues"]
    assert issues[0]["primaryLocation"]["message"] == "title-fallback"


def test_sonarqube_source_mapping_without_hash_uses_path_only():
    # A source mapping that is just a bare path with no #range -> filePath
    # set, no textRange (the SonarQube schema allows it).
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="V.sol",
        checks=["suicidal"],
        findings=[
            Finding(
                category="suicidal",
                severity=Severity.HIGH,
                title="t",
                description="d",
                detector="slither:suicidal",
                contract="V",
                confidence="high",
                evidence=Evidence(source_mapping=["V.sol"]),
            ),
        ],
    )
    issues = json.loads(to_sonarqube(report))["issues"]
    primary = issues[0]["primaryLocation"]
    assert primary["filePath"] == "V.sol"
    assert "textRange" not in primary


def test_sonarqube_issue_schema_keys_are_exactly_the_required_set():
    # SonarQube ingests engineId/ruleId/severity/type/primaryLocation; no
    # extra unknown fields should leak through (the schema is strict).
    issues = json.loads(to_sonarqube(_source_report()))["issues"]
    expected = {"engineId", "ruleId", "severity", "type", "primaryLocation"}
    for issue in issues:
        assert set(issue.keys()) == expected


def test_sonarqube_render_dispatch_matches_to_sonarqube():
    assert render(_source_report(), "sonarqube") == to_sonarqube(_source_report())


# --- gitlab-sast format (POST_V01 R3.9) ----------------------------------


def test_gitlab_sast_is_valid_json_with_top_level_shape():
    data = json.loads(to_gitlab_sast(_source_report()))
    assert isinstance(data, dict)
    # Three required top-level keys per GitLab SAST schema v15.
    assert "version" in data
    assert "scan" in data
    assert "vulnerabilities" in data
    assert isinstance(data["vulnerabilities"], list)


def test_gitlab_sast_schema_version_is_v15():
    data = json.loads(to_gitlab_sast(_source_report()))
    # Pinned major: GitLab's security-report-schemas v15 is the current stable.
    assert data["version"].startswith("15.")


def test_gitlab_sast_scan_block_carries_required_fields():
    data = json.loads(to_gitlab_sast(_source_report()))
    scan = data["scan"]
    # Per GitLab SAST schema v15: analyzer, scanner, type, start_time,
    # end_time, status are all required on the scan object.
    for key in ("analyzer", "scanner", "type", "start_time", "end_time", "status"):
        assert key in scan, f"scan missing {key}"
    assert scan["type"] == "sast"
    assert scan["status"] == "success"
    # Both analyzer and scanner identify omen, with a vendor block.
    assert scan["analyzer"]["id"] == "omen"
    assert scan["analyzer"]["name"] == "omen"
    assert scan["analyzer"]["vendor"] == {"name": "omen"}
    assert scan["scanner"]["id"] == "omen"
    assert scan["scanner"]["vendor"] == {"name": "omen"}


def test_gitlab_sast_timestamps_are_deterministic_epoch_sentinel():
    # The formatter is pure (no clock dependency); two calls produce
    # byte-identical output, and the timestamps are the documented sentinel.
    a = to_gitlab_sast(_source_report())
    b = to_gitlab_sast(_source_report())
    assert a == b
    scan = json.loads(a)["scan"]
    assert scan["start_time"] == "1970-01-01T00:00:00"
    assert scan["end_time"] == "1970-01-01T00:00:00"


def test_gitlab_sast_one_vulnerability_per_finding_in_report_order():
    # _source_report() has access-control (high) then tx-origin (medium).
    vulns = json.loads(to_gitlab_sast(_source_report()))["vulnerabilities"]
    assert len(vulns) == 2
    # Order matches report.findings (the formatter never re-orders).
    assert vulns[0]["name"] == "access-control contract (protected-vars)"
    assert vulns[1]["name"] == "tx-origin contract (tx-origin)"


def test_gitlab_sast_severity_maps_h1_to_gitlab_five_to_five():
    # critical -> Critical, high -> High, medium -> Medium,
    # low -> Low, informational -> Info.
    findings: list[Finding] = []
    for sev in (
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFORMATIONAL,
    ):
        findings.append(
            Finding(
                category="suicidal",
                severity=sev,
                title=f"t-{sev.value}",
                description=f"d-{sev.value}",
                detector=f"slither:{sev.value}",
                contract="Vuln",
                confidence="high",
                evidence=Evidence(source_mapping=["Vuln.sol#1-2"]),
            )
        )
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="Vuln.sol",
        checks=["suicidal"],
        findings=findings,
    )
    severities = [
        v["severity"] for v in json.loads(to_gitlab_sast(report))["vulnerabilities"]
    ]
    assert severities == ["Critical", "High", "Medium", "Low", "Info"]


def test_gitlab_sast_category_is_sast_for_every_vulnerability():
    vulns = json.loads(to_gitlab_sast(_source_report()))["vulnerabilities"]
    assert all(v["category"] == "sast" for v in vulns)


def test_gitlab_sast_scanner_short_block_on_each_vulnerability():
    vulns = json.loads(to_gitlab_sast(_source_report()))["vulnerabilities"]
    for v in vulns:
        assert v["scanner"] == {"id": "omen", "name": "omen"}


def test_gitlab_sast_identifiers_carry_category_and_detector():
    vulns = json.loads(to_gitlab_sast(_source_report()))["vulnerabilities"]
    ac = next(v for v in vulns if v["identifiers"][0]["value"] == "access-control")
    types = {i["type"] for i in ac["identifiers"]}
    assert types == {"omen_category", "omen_detector"}
    by_type = {i["type"]: i for i in ac["identifiers"]}
    assert by_type["omen_category"]["value"] == "access-control"
    assert by_type["omen_detector"]["value"] == "slither:protected-vars"


def test_gitlab_sast_identifiers_fall_back_to_category_only_when_detector_empty():
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="V.sol",
        checks=["suicidal"],
        findings=[
            Finding(
                category="suicidal",
                severity=Severity.HIGH,
                title="t",
                description="d",
                detector="",
                contract="V",
                confidence="high",
                evidence=Evidence(source_mapping=["V.sol#1-2"]),
            ),
        ],
    )
    vulns = json.loads(to_gitlab_sast(report))["vulnerabilities"]
    # At least one identifier is required by the schema; omen drops the
    # detector entry when the detector is empty rather than emit an empty
    # value.
    assert len(vulns[0]["identifiers"]) == 1
    assert vulns[0]["identifiers"][0]["type"] == "omen_category"
    assert vulns[0]["identifiers"][0]["value"] == "suicidal"


def test_gitlab_sast_location_carries_file_and_line_range():
    # access-control source mapping in _source_report() is Vuln.sol#12-18.
    vulns = json.loads(to_gitlab_sast(_source_report()))["vulnerabilities"]
    ac = next(v for v in vulns if v["identifiers"][0]["value"] == "access-control")
    location = ac["location"]
    assert location["file"] == "Vuln.sol"
    assert location["start_line"] == 12
    assert location["end_line"] == 18


def test_gitlab_sast_single_line_mapping_has_no_end_line():
    # tx-origin source mapping is Vuln.sol#25 (single line, no -end).
    vulns = json.loads(to_gitlab_sast(_source_report()))["vulnerabilities"]
    tx = next(v for v in vulns if v["identifiers"][0]["value"] == "tx-origin")
    location = tx["location"]
    assert location["file"] == "Vuln.sol"
    assert location["start_line"] == 25
    assert "end_line" not in location


def test_gitlab_sast_bytecode_finding_is_skipped():
    # The GitLab SAST schema strictly requires location.file. A bytecode
    # finding (no source mapping) cannot be projected and must be skipped
    # rather than emit a GitLab-invalid vulnerability.
    data = json.loads(to_gitlab_sast(_report()))
    assert data["vulnerabilities"] == []
    # The scan block is still valid (clean-document shape).
    assert data["scan"]["type"] == "sast"


def test_gitlab_sast_mixed_source_and_bytecode_skips_only_bytecode():
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="<project>",
        checks=["all"],
        findings=[
            Finding(  # bytecode finding -> skipped
                category="suicidal",
                severity=Severity.HIGH,
                title="t",
                description="d",
                detector="omen:bytecode-selfdestruct",
                contract="0xabc",
                confidence="high",
                evidence=Evidence(opcodes=[{"opcode": "SELFDESTRUCT", "offset": 16}]),
            ),
            Finding(  # source finding -> kept
                category="reentrancy",
                severity=Severity.HIGH,
                title="t",
                description="d",
                detector="slither:reentrancy-eth",
                contract="V",
                confidence="high",
                evidence=Evidence(source_mapping=["V.sol#5-6"]),
            ),
        ],
    )
    vulns = json.loads(to_gitlab_sast(report))["vulnerabilities"]
    assert len(vulns) == 1
    assert vulns[0]["identifiers"][0]["value"] == "reentrancy"


def test_gitlab_sast_empty_report_is_valid_empty_document():
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="Clean.sol",
        checks=["all"],
        findings=[],
    )
    data = json.loads(to_gitlab_sast(report))
    assert data["vulnerabilities"] == []
    assert data["version"].startswith("15.")
    assert data["scan"]["type"] == "sast"


def test_gitlab_sast_vulnerability_id_is_stable_per_finding():
    # The id must be stable across two runs of the same input — GitLab uses
    # it for vulnerability lifecycle tracking. We reuse the same fingerprint
    # primitive --baseline/--diff/--sarif-baseline use, so identity is
    # uniform across the omen feature surface.
    from omen.findings import finding_fingerprint

    a = json.loads(to_gitlab_sast(_source_report()))["vulnerabilities"]
    b = json.loads(to_gitlab_sast(_source_report()))["vulnerabilities"]
    assert [v["id"] for v in a] == [v["id"] for v in b]
    # And the id is the fingerprint string itself.
    source = _source_report()
    assert a[0]["id"] == finding_fingerprint(source.findings[0])
    assert a[1]["id"] == finding_fingerprint(source.findings[1])


def test_gitlab_sast_message_and_name_use_title_description_uses_description():
    # The 'name'/'message' fields surface in GitLab's row summary; the
    # 'description' is the expanded body. omen's title -> name/message;
    # omen's description -> description.
    vulns = json.loads(to_gitlab_sast(_source_report()))["vulnerabilities"]
    ac = next(v for v in vulns if v["identifiers"][0]["value"] == "access-control")
    assert ac["name"] == "access-control contract (protected-vars)"
    assert ac["message"] == ac["name"]
    assert ac["description"] == "missing onlyOwner guard"


def test_gitlab_sast_description_falls_back_to_title_when_empty():
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="V.sol",
        checks=["suicidal"],
        findings=[
            Finding(
                category="suicidal",
                severity=Severity.HIGH,
                title="title-fallback",
                description="",
                detector="slither:suicidal",
                contract="V",
                confidence="high",
                evidence=Evidence(source_mapping=["V.sol#1-2"]),
            ),
        ],
    )
    vulns = json.loads(to_gitlab_sast(report))["vulnerabilities"]
    assert vulns[0]["description"] == "title-fallback"


def test_gitlab_sast_render_dispatch_matches_to_gitlab_sast():
    assert render(_source_report(), "gitlab-sast") == to_gitlab_sast(_source_report())
