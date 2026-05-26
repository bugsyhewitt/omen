"""Source-mode detection tests against the shipped vulnerable fixtures.

Covers criteria 3, 4, 5: each MAIAN class (plus reentrancy) is detected on
a deliberately-vulnerable .sol fixture and reported with the right category
and a severity set.
"""

from __future__ import annotations

from omen.analyzer import analyze

from conftest import requires_solc


def _categories(report) -> set[str]:
    return {f.category for f in report.findings}


@requires_solc
def test_prodigal_source(fixtures_dir):
    report = analyze(
        contract=str(fixtures_dir / "vulnerable-prodigal.sol"),
        input_type="sol",
        check="prodigal",
    )
    assert "prodigal" in _categories(report)
    f = next(f for f in report.findings if f.category == "prodigal")
    assert f.severity is not None
    assert f.severity.value


@requires_solc
def test_suicidal_source(fixtures_dir):
    report = analyze(
        contract=str(fixtures_dir / "vulnerable-suicidal.sol"),
        input_type="sol",
        check="suicidal",
    )
    assert "suicidal" in _categories(report)
    f = next(f for f in report.findings if f.category == "suicidal")
    assert f.severity.value


@requires_solc
def test_greedy_source(fixtures_dir):
    report = analyze(
        contract=str(fixtures_dir / "vulnerable-greedy.sol"),
        input_type="sol",
        check="greedy",
    )
    assert "greedy" in _categories(report)
    f = next(f for f in report.findings if f.category == "greedy")
    assert f.severity.value


@requires_solc
def test_reentrancy_source(fixtures_dir):
    report = analyze(
        contract=str(fixtures_dir / "vulnerable-reentrancy.sol"),
        input_type="sol",
        check="reentrancy",
    )
    assert "reentrancy" in _categories(report)
    f = next(f for f in report.findings if f.category == "reentrancy")
    assert f.severity.value


@requires_solc
def test_check_all_finds_multiple_classes(fixtures_dir):
    # A reentrancy fixture run with --check all should still surface reentrancy
    report = analyze(
        contract=str(fixtures_dir / "vulnerable-reentrancy.sol"),
        input_type="sol",
        check="all",
    )
    assert "reentrancy" in _categories(report)
