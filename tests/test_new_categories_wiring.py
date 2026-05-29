"""Wiring tests for the access-control and tx-origin classes (POST_V01 Rank 2).

These assert the new classes are plumbed through every layer omen exposes —
CATEGORIES, the detector mapping, default severity, the CLI --check choices,
and the remediation table — without requiring solc/slither to run. They are
the fast guard against a half-wired category.
"""

from __future__ import annotations

from omen import CATEGORIES
from omen.analyzer import resolve_checks
from omen.cli import build_parser
from omen.detectors import CATEGORY_TO_SLITHER
from omen.findings import DEFAULT_SEVERITY, Severity
from omen.formats import _REMEDIATION

NEW_CATEGORIES = ("access-control", "tx-origin")


def test_new_categories_registered():
    for cat in NEW_CATEGORIES:
        assert cat in CATEGORIES


def test_detector_mapping_has_new_categories():
    assert CATEGORY_TO_SLITHER["access-control"] == ["protected-vars", "events-access"]
    assert CATEGORY_TO_SLITHER["tx-origin"] == ["tx-origin"]


def test_default_severity_new_categories():
    assert DEFAULT_SEVERITY["access-control"] == Severity.HIGH
    assert DEFAULT_SEVERITY["tx-origin"] == Severity.MEDIUM


def test_cli_check_accepts_new_categories():
    # R2.7 moved --check validation from argparse `choices` to resolve_checks
    # (so it can accept a comma-separated list); the CLI accepting a category
    # now means resolve_checks resolving it.
    for cat in NEW_CATEGORIES:
        assert resolve_checks(cat) == [cat]


def test_remediation_text_present_for_new_categories():
    for cat in NEW_CATEGORIES:
        assert cat in _REMEDIATION
        assert _REMEDIATION[cat].strip()


def test_help_text_lists_new_categories():
    text = build_parser().format_help()
    for cat in NEW_CATEGORIES:
        assert cat in text
