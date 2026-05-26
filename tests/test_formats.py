"""Output format tests: JSON and H1-markdown."""

from __future__ import annotations

import json

from omen.analyzer import AnalysisReport
from omen.findings import Evidence, Finding, Severity
from omen.formats import render, to_h1md, to_json


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
