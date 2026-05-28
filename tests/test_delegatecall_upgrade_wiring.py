"""Wiring tests for the delegatecall and upgrade classes (POST_V01 Rank 4).

These assert the two new proxy/upgrade classes are plumbed through every layer
omen exposes — CATEGORIES, the detector mapping, default severity, the CLI
--check choices, and the remediation table — without requiring solc/slither to
run. They are the fast guard against a half-wired category.
"""

from __future__ import annotations

from omen import CATEGORIES
from omen.cli import build_parser
from omen.detectors import CATEGORY_TO_SLITHER
from omen.findings import DEFAULT_SEVERITY, Severity
from omen.formats import _REMEDIATION

NEW_CATEGORIES = ("delegatecall", "upgrade")


def test_new_categories_registered():
    for cat in NEW_CATEGORIES:
        assert cat in CATEGORIES


def test_detector_mapping_has_new_categories():
    # Mapping correction (R5): the roadmap's "dangerous-delegatecall" ARGUMENT
    # does not exist in slither 0.11.x; controlled-delegatecall is the real
    # detector. delegatecall-loop is paired with it; upgrade -> unprotected-upgrade.
    assert CATEGORY_TO_SLITHER["delegatecall"] == [
        "controlled-delegatecall",
        "delegatecall-loop",
    ]
    assert CATEGORY_TO_SLITHER["upgrade"] == ["unprotected-upgrade"]
    # The phantom name must NOT be present.
    assert "dangerous-delegatecall" not in CATEGORY_TO_SLITHER["delegatecall"]


def test_default_severity_new_categories():
    assert DEFAULT_SEVERITY["delegatecall"] == Severity.HIGH
    assert DEFAULT_SEVERITY["upgrade"] == Severity.HIGH


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
