"""Source-mode detection tests for the delegatecall and upgrade classes.

These two classes (POST_V01 Rank 4) extend omen to the proxy/upgrade bug
cluster. delegatecall maps onto Slither `controlled-delegatecall` +
`delegatecall-loop`; upgrade maps onto Slither `unprotected-upgrade`. Each test
proves the class fires on a deliberately-vulnerable fixture with the right
category and severity, and that a clean contract produces no findings for
either class.

Source-mode tests require a `solc` on PATH; they skip cleanly if it is absent.
"""

from __future__ import annotations

from omen.analyzer import analyze
from omen.findings import DEFAULT_SEVERITY, Severity

from conftest import requires_solc


def _categories(report) -> set[str]:
    return {f.category for f in report.findings}


@requires_solc
def test_delegatecall_source_finds_finding(fixtures_dir):
    report = analyze(
        contract=str(fixtures_dir / "vulnerable-delegatecall.sol"),
        input_type="sol",
        check="delegatecall",
    )
    assert "delegatecall" in _categories(report)
    f = next(f for f in report.findings if f.category == "delegatecall")
    assert f.severity == DEFAULT_SEVERITY["delegatecall"] == Severity.HIGH
    assert f.detector.startswith("slither:")


@requires_solc
def test_upgrade_source_finds_finding(fixtures_dir):
    report = analyze(
        contract=str(fixtures_dir / "vulnerable-upgrade.sol"),
        input_type="sol",
        check="upgrade",
    )
    assert "upgrade" in _categories(report)
    f = next(f for f in report.findings if f.category == "upgrade")
    assert f.severity == DEFAULT_SEVERITY["upgrade"] == Severity.HIGH
    assert f.detector == "slither:unprotected-upgrade"


@requires_solc
def test_delegatecall_clean_contract_has_no_finding(fixtures_dir):
    report = analyze(
        contract=str(fixtures_dir / "clean-delegatecall.sol"),
        input_type="sol",
        check="delegatecall",
    )
    assert "delegatecall" not in _categories(report)


@requires_solc
def test_upgrade_clean_contract_has_no_finding(fixtures_dir):
    report = analyze(
        contract=str(fixtures_dir / "clean-delegatecall.sol"),
        input_type="sol",
        check="upgrade",
    )
    assert "upgrade" not in _categories(report)


@requires_solc
def test_check_all_surfaces_delegatecall(fixtures_dir):
    report = analyze(
        contract=str(fixtures_dir / "vulnerable-delegatecall.sol"),
        input_type="sol",
        check="all",
    )
    assert "delegatecall" in _categories(report)


@requires_solc
def test_check_all_surfaces_upgrade(fixtures_dir):
    report = analyze(
        contract=str(fixtures_dir / "vulnerable-upgrade.sol"),
        input_type="sol",
        check="all",
    )
    assert "upgrade" in _categories(report)
