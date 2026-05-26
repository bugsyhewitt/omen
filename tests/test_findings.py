"""Unit tests for the findings data model."""

from __future__ import annotations

from omen.findings import DEFAULT_SEVERITY, Evidence, Finding, Severity


def test_severity_values():
    assert Severity.HIGH.value == "high"
    assert Severity.MEDIUM.value == "medium"


def test_default_severity_covers_all_categories():
    for cat in ("prodigal", "suicidal", "greedy", "reentrancy"):
        assert cat in DEFAULT_SEVERITY
        assert isinstance(DEFAULT_SEVERITY[cat], Severity)


def test_finding_to_dict_roundtrip():
    f = Finding(
        category="suicidal",
        severity=Severity.HIGH,
        title="t",
        description="d",
        detector="slither:suicidal",
        contract="C",
        confidence="high",
        evidence=Evidence(source_mapping=["x.sol#1-3"]),
    )
    d = f.to_dict()
    assert d["category"] == "suicidal"
    assert d["severity"] == "high"
    assert d["detector"] == "slither:suicidal"
    assert d["evidence"]["source_mapping"] == ["x.sol#1-3"]
