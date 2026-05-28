"""Output format tests: JSON, H1-markdown, and SARIF."""

from __future__ import annotations

import json

from omen.analyzer import AnalysisReport
from omen.findings import Evidence, Finding, Severity
from omen.formats import render, to_h1md, to_json, to_sarif


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
