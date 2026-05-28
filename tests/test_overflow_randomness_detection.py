"""Source-mode detection tests for the overflow and weak-randomness classes.

These two classes (POST_V01 Rank 7) extend omen to the medium-severity
arithmetic-precision and weak-PRNG cluster. overflow maps onto Slither
`divide-before-multiply` + `tautology`; weak-randomness maps onto Slither
`weak-prng`. Each test proves the class fires on a deliberately-vulnerable
fixture with the right category, and that a clean contract produces no findings
for either class.

Source-mode tests require a `solc` on PATH; they skip cleanly if it is absent.
"""

from __future__ import annotations

from omen.analyzer import analyze

from conftest import requires_solc


def _categories(report) -> set[str]:
    return {f.category for f in report.findings}


@requires_solc
def test_overflow_source_finds_finding(fixtures_dir):
    report = analyze(
        contract=str(fixtures_dir / "vulnerable-overflow.sol"),
        input_type="sol",
        check="overflow",
    )
    assert "overflow" in _categories(report)
    f = next(f for f in report.findings if f.category == "overflow")
    assert f.detector == "slither:divide-before-multiply"


@requires_solc
def test_weak_randomness_source_finds_finding(fixtures_dir):
    report = analyze(
        contract=str(fixtures_dir / "vulnerable-weak-randomness.sol"),
        input_type="sol",
        check="weak-randomness",
    )
    assert "weak-randomness" in _categories(report)
    f = next(f for f in report.findings if f.category == "weak-randomness")
    assert f.detector == "slither:weak-prng"


@requires_solc
def test_overflow_clean_contract_has_no_finding(fixtures_dir):
    report = analyze(
        contract=str(fixtures_dir / "clean-overflow.sol"),
        input_type="sol",
        check="overflow",
    )
    assert "overflow" not in _categories(report)


@requires_solc
def test_weak_randomness_clean_contract_has_no_finding(fixtures_dir):
    report = analyze(
        contract=str(fixtures_dir / "clean-overflow.sol"),
        input_type="sol",
        check="weak-randomness",
    )
    assert "weak-randomness" not in _categories(report)


@requires_solc
def test_check_all_surfaces_overflow(fixtures_dir):
    report = analyze(
        contract=str(fixtures_dir / "vulnerable-overflow.sol"),
        input_type="sol",
        check="all",
    )
    assert "overflow" in _categories(report)


@requires_solc
def test_check_all_surfaces_weak_randomness(fixtures_dir):
    report = analyze(
        contract=str(fixtures_dir / "vulnerable-weak-randomness.sol"),
        input_type="sol",
        check="all",
    )
    assert "weak-randomness" in _categories(report)
