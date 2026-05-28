"""Wiring tests for the overflow and weak-randomness classes (POST_V01 Rank 7).

These assert the two new medium-severity completeness classes are plumbed
through every layer omen exposes — CATEGORIES, the detector mapping, default
severity, the CLI --check choices, the help text, and the remediation table —
without requiring solc/slither to run. They are the fast guard against a
half-wired category, mirroring the R2/R5 wiring tests.
"""

from __future__ import annotations

from omen import CATEGORIES
from omen.cli import build_parser
from omen.detectors import CATEGORY_TO_SLITHER, VYPER_SUPPORTED_CATEGORIES
from omen.findings import DEFAULT_SEVERITY, Severity
from omen.formats import _REMEDIATION

NEW_CATEGORIES = ("overflow", "weak-randomness")


def test_new_categories_registered():
    for cat in NEW_CATEGORIES:
        assert cat in CATEGORIES


def test_detector_mapping_has_new_categories():
    # Mapping correction (R8): the roadmap's "integer-overflow" ARGUMENT does
    # not exist in slither 0.11.x; overflow maps onto the real arithmetic
    # detectors divide-before-multiply + tautology. weak-randomness maps onto
    # weak-prng exactly as the roadmap named it.
    assert CATEGORY_TO_SLITHER["overflow"] == [
        "divide-before-multiply",
        "tautology",
    ]
    assert CATEGORY_TO_SLITHER["weak-randomness"] == ["weak-prng"]
    # The phantom name must NOT be present.
    assert "integer-overflow" not in CATEGORY_TO_SLITHER["overflow"]


def test_default_severity_new_categories():
    assert DEFAULT_SEVERITY["overflow"] == Severity.MEDIUM
    assert DEFAULT_SEVERITY["weak-randomness"] == Severity.MEDIUM


def test_cli_check_choices_include_new_categories():
    parser = build_parser()
    check_action = next(a for a in parser._actions if a.dest == "check")
    for cat in NEW_CATEGORIES:
        assert cat in check_action.choices


def test_remediation_text_present_for_new_categories():
    for cat in NEW_CATEGORIES:
        assert cat in _REMEDIATION
        assert _REMEDIATION[cat].strip()


def test_help_text_lists_new_categories():
    text = build_parser().format_help()
    for cat in NEW_CATEGORIES:
        assert cat in text


def test_new_categories_not_supported_for_vyper():
    # overflow and weak-randomness are Solidity-only concepts in omen's Vyper
    # subset (R7 only covers reentrancy + prodigal for Vyper); they must stay
    # out of VYPER_SUPPORTED_CATEGORIES.
    for cat in NEW_CATEGORIES:
        assert cat not in VYPER_SUPPORTED_CATEGORIES
