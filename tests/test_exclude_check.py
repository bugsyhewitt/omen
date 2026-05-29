"""Tests for the --exclude-check inverse category selector (POST_V01 Rotation 2, R2.8).

R2.7 added comma-separated `--check` lists (scope a scan *to* a set of classes).
R2.8 adds the inverse, `--exclude-check`: remove one or more classes *from* the
resolved `--check` set. The motivating case pairs it with the default
`--check all` to express "every class except these" without enumerating the
other eight — e.g. `--check all --exclude-check greedy,prodigal` to drop the two
noisiest bytecode heuristics from a whole-surface scan.

These tests cover the shared parse_categories primitive, the resolve_checks
subtraction logic (no-op exclusion, order preservation, empty-set rejection),
the CLI surface (help text + argparse acceptance + exit-2 on bad values), and
bytecode-mode end-to-end subprocess runs that need no compiler.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from omen import CATEGORIES
from omen.analyzer import parse_categories, resolve_checks
from omen.cli import build_parser

FIXTURES = Path(__file__).parent / "fixtures"


# --- parse_categories: the shared primitive ---------------------------------


def test_parse_single_category_either_mode():
    assert parse_categories("reentrancy", allow_all=True) == ["reentrancy"]
    assert parse_categories("reentrancy", allow_all=False) == ["reentrancy"]


def test_parse_list_preserves_order_and_dedupes():
    assert parse_categories("upgrade,access-control,upgrade", allow_all=False) == [
        "upgrade",
        "access-control",
    ]


def test_parse_tolerates_whitespace_and_trailing_commas():
    assert parse_categories(" greedy , prodigal ,", allow_all=False) == [
        "greedy",
        "prodigal",
    ]


def test_parse_all_expands_only_when_allowed():
    assert parse_categories("all", allow_all=True) == list(CATEGORIES)
    with pytest.raises(ValueError) as exc:
        parse_categories("all", allow_all=False)
    assert "all" in str(exc.value).lower()


def test_parse_all_in_exclude_list_rejected():
    # 'all' anywhere in an exclude list is rejected (excluding everything scans
    # nothing) and the error explains why.
    with pytest.raises(ValueError) as exc:
        parse_categories("greedy,all", allow_all=False)
    assert "all" in str(exc.value).lower()


def test_parse_unknown_member_names_offender():
    with pytest.raises(ValueError) as exc:
        parse_categories("greedy,bogus", allow_all=False)
    assert "bogus" in str(exc.value)


def test_parse_empty_rejected_for_both_modes():
    with pytest.raises(ValueError):
        parse_categories("", allow_all=False)
    with pytest.raises(ValueError):
        parse_categories(",,,", allow_all=True)


# --- resolve_checks: the subtraction (the R2.8 feature) ---------------------


def test_resolve_no_exclude_is_unchanged():
    # No exclude (None or empty) leaves --check resolution exactly as R2.7.
    assert resolve_checks("all") == list(CATEGORIES)
    assert resolve_checks("all", None) == list(CATEGORIES)
    assert resolve_checks("all", "") == list(CATEGORIES)
    assert resolve_checks("all", "   ") == list(CATEGORIES)


def test_resolve_exclude_one_from_all():
    expected = [c for c in CATEGORIES if c != "greedy"]
    assert resolve_checks("all", "greedy") == expected


def test_resolve_exclude_list_from_all():
    drop = {"greedy", "prodigal"}
    expected = [c for c in CATEGORIES if c not in drop]
    assert resolve_checks("all", "greedy,prodigal") == expected


def test_resolve_exclude_preserves_check_order():
    # The surviving categories keep the --check order, not the exclude order.
    result = resolve_checks("reentrancy,suicidal,greedy", "suicidal")
    assert result == ["reentrancy", "greedy"]


def test_resolve_exclude_unselected_is_noop():
    # Excluding a class --check never selected just yields the --check set.
    assert resolve_checks("reentrancy", "suicidal") == ["reentrancy"]
    assert resolve_checks("reentrancy,greedy", "suicidal,upgrade") == [
        "reentrancy",
        "greedy",
    ]


def test_resolve_exclude_every_selected_category_raises():
    # Excluding everything --check selected leaves nothing to scan -> error.
    with pytest.raises(ValueError) as exc:
        resolve_checks("reentrancy,suicidal", "suicidal,reentrancy")
    assert "nothing to scan" in str(exc.value).lower()


def test_resolve_exclude_all_categories_from_all_raises():
    spec = ",".join(CATEGORIES)
    with pytest.raises(ValueError):
        resolve_checks("all", spec)


def test_resolve_exclude_rejects_all_keyword():
    with pytest.raises(ValueError):
        resolve_checks("all", "all")


def test_resolve_exclude_unknown_member_raises_naming_offender():
    with pytest.raises(ValueError) as exc:
        resolve_checks("all", "greedy,bogus")
    assert "bogus" in str(exc.value)


# --- CLI surface ------------------------------------------------------------


def test_help_documents_exclude_check():
    text = build_parser().format_help()
    assert "--exclude-check" in text
    collapsed = " ".join(text.split()).replace("- ", "-").lower()
    assert "inverse selector" in collapsed


def test_parser_accepts_exclude_check_value():
    parser = build_parser()
    args = parser.parse_args(
        [
            "--contract",
            "x.sol",
            "--input-type",
            "sol",
            "--exclude-check",
            "greedy,prodigal",
        ]
    )
    assert args.exclude_check == "greedy,prodigal"


def test_exclude_check_defaults_to_none():
    parser = build_parser()
    args = parser.parse_args(["--contract", "x.sol", "--input-type", "sol"])
    assert args.exclude_check is None


def test_cli_rejects_unknown_exclude_member_with_exit_2():
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "omen.cli",
            "--contract",
            str(FIXTURES / "compiled.bin"),
            "--input-type",
            "bytecode",
            "--exclude-check",
            "greedy,bogus",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2
    assert "bogus" in proc.stderr


def test_cli_rejects_exclude_all_with_exit_2():
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "omen.cli",
            "--contract",
            str(FIXTURES / "compiled.bin"),
            "--input-type",
            "bytecode",
            "--exclude-check",
            "all",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2


def test_cli_rejects_excluding_every_selected_with_exit_2():
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "omen.cli",
            "--contract",
            str(FIXTURES / "compiled.bin"),
            "--input-type",
            "bytecode",
            "--check",
            "reentrancy,suicidal",
            "--exclude-check",
            "reentrancy,suicidal",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2


# --- End-to-end: --exclude-check scopes the scan (bytecode mode, no compiler) ---


def test_exclude_check_removes_class_end_to_end():
    """On a fixture that hits both reentrancy and suicidal, excluding suicidal
    must leave only reentrancy in the report, and `checks` echoes the surviving
    set."""
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "omen.cli",
            "--contract",
            str(FIXTURES / "mixed-confidence.bin"),
            "--input-type",
            "bytecode",
            "--check",
            "all",
            "--exclude-check",
            "suicidal",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    # suicidal was removed from the resolved check set...
    assert "suicidal" not in report["checks"]
    # ...so no suicidal finding can appear.
    found = {f["category"] for f in report["findings"]}
    assert "suicidal" not in found


def test_exclude_check_noop_keeps_findings_end_to_end():
    """Excluding a class the fixture does not even hit (and --check still covers)
    is a no-op: the reentrancy finding still surfaces."""
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "omen.cli",
            "--contract",
            str(FIXTURES / "mixed-confidence.bin"),
            "--input-type",
            "bytecode",
            "--check",
            "all",
            "--exclude-check",
            "upgrade",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    assert "upgrade" not in report["checks"]
    found = {f["category"] for f in report["findings"]}
    assert "reentrancy" in found
