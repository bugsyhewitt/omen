"""Output format tests: text, JSON, H1-markdown, SARIF, gha, junit, checkstyle, sonarqube, gitlab-sast."""

from __future__ import annotations

import json
from xml.etree import ElementTree as ET

from omen.analyzer import AnalysisReport
from omen.findings import Evidence, Finding, Severity
from omen.formats import (
    render,
    to_azure_devops,
    to_bitbucket_code_insights,
    to_checkstyle,
    to_gha,
    to_gitlab_sast,
    to_h1md,
    to_json,
    to_junit,
    to_opsgenie,
    to_sarif,
    to_sonarqube,
    to_teams_webhook,
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
    assert render(_report(), "bitbucket-code-insights").startswith("{")
    assert render(_report(), "azure-devops").startswith("##vso[")
    assert render(_report(), "teams-webhook").startswith("{")
    assert render(_report(), "opsgenie").startswith("{")


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
# --- bitbucket-code-insights format (POST_V01 R3.9) -----------------------


def test_bitbucket_is_valid_json_with_report_and_annotations():
    data = json.loads(to_bitbucket_code_insights(_source_report()))
    assert isinstance(data, dict)
    assert isinstance(data["report"], dict)
    assert isinstance(data["annotations"], list)
    assert len(data["annotations"]) == 2


def test_bitbucket_report_block_carries_required_fields():
    report_block = json.loads(to_bitbucket_code_insights(_source_report()))["report"]
    # The Bitbucket Code Insights /reports endpoint requires title and reporter,
    # and renders report_type + result as filters/badges on the PR UI.
    assert report_block["title"] == "omen security scan"
    assert report_block["reporter"] == "omen"
    assert report_block["report_type"] == "SECURITY"
    assert report_block["result"] == "FAILED"
    assert "details" in report_block and report_block["details"]


def test_bitbucket_empty_report_result_is_passed():
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="Clean.sol",
        checks=["all"],
        findings=[],
    )
    data = json.loads(to_bitbucket_code_insights(report))
    assert data["report"]["result"] == "PASSED"
    assert data["annotations"] == []


def test_bitbucket_report_data_carries_per_severity_counts():
    # _source_report() has access-control (high) and tx-origin (medium).
    data = json.loads(to_bitbucket_code_insights(_source_report()))["report"]["data"]
    # data is a list of {title, type, value} entries — one per H1 severity.
    by_title = {row["title"]: row["value"] for row in data}
    assert by_title["high"] == 1
    assert by_title["medium"] == 1
    assert by_title["critical"] == 0
    assert by_title["low"] == 0
    assert by_title["informational"] == 0
    assert all(row["type"] == "NUMBER" for row in data)


def test_bitbucket_one_annotation_per_finding_in_report_order():
    anns = json.loads(to_bitbucket_code_insights(_source_report()))["annotations"]
    # _source_report() emits high then medium; both should be present in order.
    assert anns[0]["severity"] == "HIGH"
    assert anns[1]["severity"] == "MEDIUM"


def test_bitbucket_severity_maps_h1_to_bitbucket_four_levels():
    # critical -> CRITICAL, high -> HIGH, medium -> MEDIUM, low -> LOW,
    # informational -> LOW (folds into the lowest Bitbucket level).
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
        a["severity"]
        for a in json.loads(to_bitbucket_code_insights(report))["annotations"]
    ]
    assert severities == ["CRITICAL", "HIGH", "MEDIUM", "LOW", "LOW"]


def test_bitbucket_annotation_type_is_vulnerability_for_every_annotation():
    anns = json.loads(to_bitbucket_code_insights(_source_report()))["annotations"]
    assert all(a["annotation_type"] == "VULNERABILITY" for a in anns)


def test_bitbucket_source_finding_carries_path_and_line():
    # access-control source mapping in _source_report() is Vuln.sol#12-18,
    # so the annotation must carry path=Vuln.sol and line=12 (start line).
    anns = json.loads(to_bitbucket_code_insights(_source_report()))["annotations"]
    ac = next(a for a in anns if a["severity"] == "HIGH")
    assert ac["path"] == "Vuln.sol"
    assert ac["line"] == 12


def test_bitbucket_single_line_mapping_carries_that_line():
    # tx-origin source mapping is Vuln.sol#25 — single-line location, the
    # annotation's line should be exactly 25.
    anns = json.loads(to_bitbucket_code_insights(_source_report()))["annotations"]
    tx = next(a for a in anns if a["severity"] == "MEDIUM")
    assert tx["path"] == "Vuln.sol"
    assert tx["line"] == 25


def test_bitbucket_bytecode_finding_has_no_path_or_line():
    # Bytecode finding (no source_mapping) -> Bitbucket cannot anchor it to
    # a PR-diff line, but the annotation is still emitted as a report-level
    # entry so the finding is visible in the Code Insights tab.
    anns = json.loads(to_bitbucket_code_insights(_report()))["annotations"]
    assert len(anns) == 1
    assert "path" not in anns[0]
    assert "line" not in anns[0]
    # But the annotation_type, severity, and summary must still be present.
    assert anns[0]["annotation_type"] == "VULNERABILITY"
    assert anns[0]["severity"] == "HIGH"
    assert anns[0]["summary"]


def test_bitbucket_external_id_is_stable_across_runs():
    # Two renders of the same report must produce identical external_ids per
    # annotation (the Code Insights API uses external_id for upsert).
    a1 = json.loads(to_bitbucket_code_insights(_source_report()))["annotations"]
    a2 = json.loads(to_bitbucket_code_insights(_source_report()))["annotations"]
    ids1 = [a["external_id"] for a in a1]
    ids2 = [a["external_id"] for a in a2]
    assert ids1 == ids2
    # All external_ids should be unique within a single report.
    assert len(set(ids1)) == len(ids1)
    # And they should be prefixed with "omen-" for grouping in the Bitbucket UI.
    assert all(eid.startswith("omen-") for eid in ids1)


def test_bitbucket_summary_preserves_original_h1_severity_verbatim():
    # The annotation's projected severity is Bitbucket's four-level vocabulary,
    # but the summary line must carry omen's original H1 severity verbatim so
    # the reviewer still sees informational vs low (both project to LOW).
    findings = [
        Finding(
            category="suicidal",
            severity=Severity.INFORMATIONAL,
            title="info",
            description="info-finding",
            detector="slither:suicidal",
            contract="V",
            confidence="medium",
            evidence=Evidence(source_mapping=["V.sol#1-2"]),
        ),
        Finding(
            category="suicidal",
            severity=Severity.LOW,
            title="low",
            description="low-finding",
            detector="slither:suicidal",
            contract="V",
            confidence="high",
            evidence=Evidence(source_mapping=["V.sol#3-4"]),
        ),
    ]
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="V.sol",
        checks=["suicidal"],
        findings=findings,
    )
    anns = json.loads(to_bitbucket_code_insights(report))["annotations"]
    # Both project to LOW but their summaries must disambiguate.
    assert all(a["severity"] == "LOW" for a in anns)
    assert "informational" in anns[0]["summary"]
    assert "low" in anns[1]["summary"] and "informational" not in anns[1]["summary"]


def test_bitbucket_summary_falls_back_to_title_when_description_empty():
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
    anns = json.loads(to_bitbucket_code_insights(report))["annotations"]
    assert "title-fallback" in anns[0]["summary"]


def test_bitbucket_source_mapping_without_hash_emits_no_line_anchor():
    # A source mapping that is just a bare path (no #range) lacks a line
    # number — Bitbucket requires BOTH path and line for an inline anchor,
    # so it falls back to the report-level annotation form.
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
    anns = json.loads(to_bitbucket_code_insights(report))["annotations"]
    assert "path" not in anns[0]
    assert "line" not in anns[0]


def test_bitbucket_details_reports_limit_truncation_like_h1md():
    # When --limit truncated the report, the details line must convey "N of M".
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
                evidence=Evidence(source_mapping=["V.sol#1-2"]),
            ),
        ],
        total_findings=10,
    )
    details = json.loads(to_bitbucket_code_insights(report))["report"]["details"]
    assert "1 of 10" in details
    assert "--limit" in details


def test_bitbucket_annotation_schema_keys_are_within_expected_set():
    anns = json.loads(to_bitbucket_code_insights(_source_report()))["annotations"]
    allowed = {
        "external_id",
        "annotation_type",
        "summary",
        "severity",
        "path",
        "line",
    }
    for a in anns:
        assert set(a.keys()).issubset(allowed)
        # Required keys (always present) regardless of source/bytecode mode.
        assert {"external_id", "annotation_type", "summary", "severity"}.issubset(a.keys())


def test_bitbucket_render_dispatch_matches_to_bitbucket_code_insights():
    assert render(_source_report(), "bitbucket-code-insights") == to_bitbucket_code_insights(
        _source_report()
    )


# --- azure-devops format (POST_V01 R3.10) ---------------------------------


def test_azdo_one_command_per_finding_in_report_order():
    out = to_azure_devops(_source_report())
    lines = out.splitlines()
    assert len(lines) == 2
    for line in lines:
        assert line.startswith("##vso[task.logissue ")
    # High access-control finding first (worst-first); medium tx-origin second.
    assert "code=access-control" in lines[0]
    assert "code=tx-origin" in lines[1]


def test_azdo_severity_maps_to_two_levels():
    # critical/high -> error; medium/low/informational -> warning.
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="V.sol",
        checks=["x"],
        findings=[
            Finding(
                category="c",
                severity=sev,
                title="t",
                description="d",
                detector="x",
                contract="V",
                confidence="high",
                evidence=Evidence(source_mapping=["V.sol#1"]),
            )
            for sev in (
                Severity.CRITICAL,
                Severity.HIGH,
                Severity.MEDIUM,
                Severity.LOW,
                Severity.INFORMATIONAL,
            )
        ],
    )
    lines = to_azure_devops(report).splitlines()
    assert "type=error" in lines[0]  # critical
    assert "type=error" in lines[1]  # high
    assert "type=warning" in lines[2]  # medium
    assert "type=warning" in lines[3]  # low
    assert "type=warning" in lines[4]  # informational


def test_azdo_source_finding_carries_sourcepath_and_linenumber():
    line = to_azure_devops(_source_report()).splitlines()[0]
    assert "sourcepath=Vuln.sol" in line
    assert "linenumber=12" in line


def test_azdo_single_line_mapping_carries_that_line():
    # tx-origin finding in _source_report uses Vuln.sol#25 (single line, no end).
    line = to_azure_devops(_source_report()).splitlines()[1]
    assert "sourcepath=Vuln.sol" in line
    assert "linenumber=25" in line


def test_azdo_bytecode_finding_has_no_source_anchor():
    line = to_azure_devops(_report()).splitlines()[0]
    assert line.startswith("##vso[task.logissue ")
    assert "sourcepath=" not in line
    assert "linenumber=" not in line
    # The category code is still carried so the annotation is identifiable.
    assert "code=suicidal" in line


def test_azdo_message_preserves_h1_severity_and_confidence_verbatim():
    # The message body (everything after the command-closing ``]``) carries
    # the original H1 severity, category and confidence verbatim. The literal
    # ``]`` characters in the ``[sev/cat/conf]`` summary tag are AzDO-escaped
    # to ``%5D`` so they don't terminate the command early; the human-readable
    # severity/category strings remain intact.
    out = to_azure_devops(_source_report())
    high_line, med_line = out.splitlines()
    high_msg = high_line.split("]", 1)[1]
    med_msg = med_line.split("]", 1)[1]
    assert "[high/access-control/high%5D" in high_msg
    assert "[medium/tx-origin/medium%5D" in med_msg
    assert "missing onlyOwner guard" in high_msg
    assert "tx.origin used for auth" in med_msg


def test_azdo_escapes_special_chars_in_message_and_props():
    # A finding whose description contains a ``;`` and a ``]`` and a ``%``
    # plus a multi-line body; AzDO's logging-command parser would otherwise
    # truncate the command at the first ``;`` or ``]``.
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="path;with]chars.sol",
        checks=["c"],
        findings=[
            Finding(
                category="c",
                severity=Severity.HIGH,
                title="t",
                description="a;b]c%d\nmore",
                detector="x",
                contract="V",
                confidence="high",
                evidence=Evidence(source_mapping=["path;with]chars.sol#7"]),
            )
        ],
    )
    line = to_azure_devops(report)
    # No raw ``;`` may appear inside an escaped value (only between props).
    # No raw ``]`` may appear before the command-closing bracket.
    sourcepath_prop = [p for p in line.split("]", 1)[0].split(";") if p.startswith("sourcepath=")][0]
    assert "%3B" in sourcepath_prop
    assert "%5D" in sourcepath_prop
    # Message body escapes too: ``;`` -> %3B, ``]`` -> %5D, LF -> %0A, ``%`` -> %AZP25.
    msg = line.split("]", 1)[1]
    assert "%3B" in msg
    assert "%5D" in msg
    assert "%0A" in msg
    assert "%AZP25" in msg


def test_azdo_empty_report_emits_a_single_debug_line():
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="V.sol",
        checks=["c"],
        findings=[],
    )
    out = to_azure_devops(report)
    assert out.startswith("##[debug]")
    assert "found no findings" in out
    assert "\n" not in out


def test_azdo_render_dispatch_matches_to_azure_devops():
    assert render(_source_report(), "azure-devops") == to_azure_devops(_source_report())


def test_azdo_source_mapping_without_hash_emits_no_linenumber():
    # A source mapping that omits the ``#line`` portion still carries the
    # file path (sourcepath) but no linenumber — the annotation appears on
    # the Files tab, just not pinned to a line.
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="V.sol",
        checks=["c"],
        findings=[
            Finding(
                category="c",
                severity=Severity.HIGH,
                title="t",
                description="d",
                detector="x",
                contract="V",
                confidence="high",
                evidence=Evidence(source_mapping=["V.sol"]),
            )
        ],
    )
    line = to_azure_devops(report)
    assert "sourcepath=V.sol" in line
    assert "linenumber=" not in line


# --- teams-webhook format (POST_V01 R3.11) --------------------------------


def test_teams_envelope_is_messagecard():
    data = json.loads(to_teams_webhook(_source_report()))
    assert data["@type"] == "MessageCard"
    assert data["@context"] == "https://schema.org/extensions"
    assert data["title"] == "omen security scan"
    assert "themeColor" in data
    assert "sections" in data and isinstance(data["sections"], list)


def test_teams_one_section_per_finding_in_report_order():
    data = json.loads(to_teams_webhook(_source_report()))
    sections = data["sections"]
    assert len(sections) == 2
    # worst-first: high access-control then medium tx-origin
    assert "access-control" in sections[0]["activityTitle"]
    assert "tx-origin" in sections[1]["activityTitle"]
    assert sections[0]["activityTitle"].startswith("**#1.")
    assert sections[1]["activityTitle"].startswith("**#2.")


def test_teams_facts_carry_per_finding_metadata():
    data = json.loads(to_teams_webhook(_source_report()))
    facts = {fact["name"]: fact["value"] for fact in data["sections"][0]["facts"]}
    assert facts["Severity"] == "high"
    assert facts["Category"] == "access-control"
    assert facts["Confidence"] == "high"
    assert facts["Contract"] == "Vuln"
    assert facts["Detector"] == "slither:protected-vars"
    assert facts["Location"] == "Vuln.sol:12"


def test_teams_section_body_carries_description():
    data = json.loads(to_teams_webhook(_source_report()))
    assert data["sections"][0]["text"] == "missing onlyOwner guard"
    assert data["sections"][1]["text"] == "tx.origin used for auth"


def test_teams_theme_color_reflects_worst_severity():
    # _source_report has a high finding worst-first, so themeColor is the
    # high color (D13438), not the medium color.
    data = json.loads(to_teams_webhook(_source_report()))
    assert data["themeColor"] == "D13438"


def test_teams_theme_color_critical_overrides_high():
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="V.sol",
        checks=["c"],
        findings=[
            Finding(
                category="c",
                severity=Severity.CRITICAL,
                title="t",
                description="d",
                detector="x",
                contract="V",
                confidence="high",
                evidence=Evidence(source_mapping=["V.sol#1"]),
            ),
            Finding(
                category="c",
                severity=Severity.HIGH,
                title="t",
                description="d",
                detector="x",
                contract="V",
                confidence="high",
                evidence=Evidence(source_mapping=["V.sol#2"]),
            ),
        ],
    )
    data = json.loads(to_teams_webhook(report))
    assert data["themeColor"] == "A6192E"


def test_teams_empty_report_uses_green_theme_color_and_emits_no_sections():
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="V.sol",
        checks=["c"],
        findings=[],
    )
    data = json.loads(to_teams_webhook(report))
    assert data["themeColor"] == "107C10"
    assert data["sections"] == []
    assert "no findings" in data["text"]
    assert data["summary"] == "omen security scan: 0 findings"


def test_teams_summary_text_carries_scan_metadata_and_severity_breakdown():
    data = json.loads(to_teams_webhook(_source_report()))
    text = data["text"]
    assert "omen 0.1.0" in text
    assert "Vuln.sol" in text
    assert "(sol)" in text
    assert "2 findings" in text
    assert "high=1" in text
    assert "medium=1" in text


def test_teams_notification_summary_carries_finding_count():
    data = json.loads(to_teams_webhook(_source_report()))
    assert data["summary"] == "omen security scan: 2 findings"


def test_teams_bytecode_finding_omits_location_fact():
    data = json.loads(to_teams_webhook(_report()))
    facts = {fact["name"]: fact["value"] for fact in data["sections"][0]["facts"]}
    assert "Location" not in facts
    # but still carries severity/category/contract/detector
    assert facts["Severity"] == "high"
    assert facts["Category"] == "suicidal"
    assert facts["Contract"] == "0xabc"


def test_teams_location_is_file_colon_line_for_ranged_mapping():
    # _source_report's first finding uses Vuln.sol#12-18 — only the start
    # line is reported (Teams facts list has no concept of a line range).
    data = json.loads(to_teams_webhook(_source_report()))
    facts = {fact["name"]: fact["value"] for fact in data["sections"][0]["facts"]}
    assert facts["Location"] == "Vuln.sol:12"


def test_teams_location_uses_file_only_when_mapping_has_no_hash():
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="V.sol",
        checks=["c"],
        findings=[
            Finding(
                category="c",
                severity=Severity.HIGH,
                title="t",
                description="d",
                detector="x",
                contract="V",
                confidence="high",
                evidence=Evidence(source_mapping=["V.sol"]),
            )
        ],
    )
    data = json.loads(to_teams_webhook(report))
    facts = {fact["name"]: fact["value"] for fact in data["sections"][0]["facts"]}
    assert facts["Location"] == "V.sol"


def test_teams_render_dispatch_matches_to_teams_webhook():
    assert render(_source_report(), "teams-webhook") == to_teams_webhook(_source_report())


def test_teams_payload_is_valid_json_object():
    text = to_teams_webhook(_source_report())
    data = json.loads(text)
    assert isinstance(data, dict)
    # The MessageCard schema requires these top-level fields on Incoming
    # Webhook payloads; if any goes missing the Teams connector rejects the
    # POST with a 400 (the failure mode this regression test guards).
    for required in ("@type", "@context", "summary", "themeColor", "title", "text", "sections"):
        assert required in data


def test_teams_section_without_description_omits_text_field():
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="V.sol",
        checks=["c"],
        findings=[
            Finding(
                category="c",
                severity=Severity.HIGH,
                title="t",
                description="",
                detector="x",
                contract="V",
                confidence="high",
                evidence=Evidence(source_mapping=["V.sol#1"]),
            )
        ],
    )
    data = json.loads(to_teams_webhook(report))
    section = data["sections"][0]
    assert "text" not in section
    # activityTitle still carries the index/severity/category/title tag
    assert "[high/c]" in section["activityTitle"]


# --- opsgenie format (POST_V01 R3.12) ----------------------------------------


def test_opsgenie_envelope_has_required_keys():
    data = json.loads(to_opsgenie(_source_report()))
    assert "message" in data
    assert "alias" in data
    assert "description" in data
    assert "priority" in data
    assert "tags" in data and isinstance(data["tags"], list)
    assert "details" in data and isinstance(data["details"], dict)


def test_opsgenie_priority_reflects_worst_severity():
    # _source_report has high as worst → P2
    data = json.loads(to_opsgenie(_source_report()))
    assert data["priority"] == "P2"


def test_opsgenie_priority_critical_is_p1():
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="V.sol",
        checks=["c"],
        findings=[
            Finding(
                category="c",
                severity=Severity.CRITICAL,
                title="t",
                description="d",
                detector="x",
                contract="V",
                confidence="high",
                evidence=Evidence(source_mapping=["V.sol#1"]),
            ),
        ],
    )
    data = json.loads(to_opsgenie(report))
    assert data["priority"] == "P1"


def test_opsgenie_priority_mapping_all_levels():
    for severity, expected in [
        (Severity.CRITICAL, "P1"),
        (Severity.HIGH, "P2"),
        (Severity.MEDIUM, "P3"),
        (Severity.LOW, "P4"),
        (Severity.INFORMATIONAL, "P5"),
    ]:
        report = AnalysisReport(
            tool="omen",
            version="0.1.0",
            input_type="sol",
            origin="V.sol",
            checks=["c"],
            findings=[
                Finding(
                    category="c",
                    severity=severity,
                    title="t",
                    description="d",
                    detector="x",
                    contract="V",
                    confidence="high",
                    evidence=Evidence(source_mapping=["V.sol#1"]),
                ),
            ],
        )
        data = json.loads(to_opsgenie(report))
        assert data["priority"] == expected, f"severity {severity} → {data['priority']} != {expected}"


def test_opsgenie_message_carries_finding_count():
    data = json.loads(to_opsgenie(_source_report()))
    assert "2 findings" in data["message"]


def test_opsgenie_message_singular_for_one_finding():
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="V.sol",
        checks=["c"],
        findings=[
            Finding(
                category="c",
                severity=Severity.HIGH,
                title="t",
                description="d",
                detector="x",
                contract="V",
                confidence="high",
                evidence=Evidence(source_mapping=["V.sol#1"]),
            ),
        ],
    )
    data = json.loads(to_opsgenie(report))
    assert "1 finding" in data["message"]
    assert "findings" not in data["message"]


def test_opsgenie_message_capped_at_130_chars():
    # message must never exceed 130 chars (Opsgenie API hard limit)
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="V" * 200,
        checks=["c"],
        findings=[],
    )
    data = json.loads(to_opsgenie(report))
    assert len(data["message"]) <= 130


def test_opsgenie_alias_encodes_origin_and_input_type():
    data = json.loads(to_opsgenie(_source_report()))
    assert "Vuln.sol" in data["alias"]
    assert "sol" in data["alias"]


def test_opsgenie_tags_include_finding_categories():
    data = json.loads(to_opsgenie(_source_report()))
    tags = data["tags"]
    assert "omen:access-control" in tags
    assert "omen:tx-origin" in tags


def test_opsgenie_description_contains_each_finding():
    data = json.loads(to_opsgenie(_source_report()))
    desc = data["description"]
    assert "access-control" in desc
    assert "tx-origin" in desc
    assert "#1." in desc
    assert "#2." in desc


def test_opsgenie_description_contains_finding_metadata():
    data = json.loads(to_opsgenie(_source_report()))
    desc = data["description"]
    # severity, category, confidence, contract, detector, location all present
    assert "high" in desc
    assert "Vuln" in desc
    assert "slither:protected-vars" in desc


def test_opsgenie_details_carry_scan_metadata():
    data = json.loads(to_opsgenie(_source_report()))
    details = data["details"]
    assert details["tool"] == "omen"
    assert details["origin"] == "Vuln.sol"
    assert details["input_type"] == "sol"
    assert details["finding_count"] == "2"


def test_opsgenie_empty_report_no_findings_message():
    report = AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="sol",
        origin="V.sol",
        checks=["c"],
        findings=[],
    )
    data = json.loads(to_opsgenie(report))
    assert "no findings" in data["message"]
    assert data["priority"] == "P5"
    assert data["tags"] == ["omen:clean"]
    assert "No findings" in data["description"]


def test_opsgenie_render_dispatch_matches_to_opsgenie():
    assert render(_source_report(), "opsgenie") == to_opsgenie(_source_report())
