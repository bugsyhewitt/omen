"""Source-mode detection tests for the access-control and tx-origin classes.

These two classes (POST_V01 Rank 2) extend omen beyond the four MAIAN classes.
access-control maps onto Slither `protected-vars` + `events-access`; tx-origin
maps onto Slither `tx-origin`. Each test proves the class fires on a
deliberately-vulnerable fixture with the right category and severity, and that
a clean contract produces no findings for either class.

Source-mode tests require a `solc` on PATH; they skip cleanly if it is absent.
"""

from __future__ import annotations

from omen.analyzer import analyze
from omen.findings import DEFAULT_SEVERITY, Severity

from conftest import requires_solc


def _categories(report) -> set[str]:
    return {f.category for f in report.findings}


@requires_solc
def test_access_control_source_finds_finding(fixtures_dir):
    report = analyze(
        contract=str(fixtures_dir / "vulnerable-access-control.sol"),
        input_type="sol",
        check="access-control",
    )
    assert "access-control" in _categories(report)
    f = next(f for f in report.findings if f.category == "access-control")
    # Severity must be populated; access-control defaults to high.
    assert f.severity is not None and f.severity.value
    assert f.severity == DEFAULT_SEVERITY["access-control"] == Severity.HIGH
    # The finding must carry an underlying slither detector id.
    assert f.detector.startswith("slither:")


@requires_solc
def test_tx_origin_source_finds_finding(fixtures_dir):
    report = analyze(
        contract=str(fixtures_dir / "vulnerable-tx-origin.sol"),
        input_type="sol",
        check="tx-origin",
    )
    assert "tx-origin" in _categories(report)
    f = next(f for f in report.findings if f.category == "tx-origin")
    assert f.severity == DEFAULT_SEVERITY["tx-origin"] == Severity.MEDIUM
    assert f.detector == "slither:tx-origin"


@requires_solc
def test_access_control_clean_contract_has_no_finding(fixtures_dir):
    report = analyze(
        contract=str(fixtures_dir / "clean-access-control.sol"),
        input_type="sol",
        check="access-control",
    )
    assert "access-control" not in _categories(report)
    assert len(report.findings) == 0


@requires_solc
def test_tx_origin_clean_contract_has_no_finding(fixtures_dir):
    report = analyze(
        contract=str(fixtures_dir / "clean-access-control.sol"),
        input_type="sol",
        check="tx-origin",
    )
    assert "tx-origin" not in _categories(report)
    assert len(report.findings) == 0


@requires_solc
def test_check_all_surfaces_tx_origin(fixtures_dir):
    # Running --check all on the tx-origin fixture must still surface tx-origin.
    report = analyze(
        contract=str(fixtures_dir / "vulnerable-tx-origin.sol"),
        input_type="sol",
        check="all",
    )
    assert "tx-origin" in _categories(report)


@requires_solc
def test_check_all_surfaces_access_control(fixtures_dir):
    report = analyze(
        contract=str(fixtures_dir / "vulnerable-access-control.sol"),
        input_type="sol",
        check="all",
    )
    assert "access-control" in _categories(report)
