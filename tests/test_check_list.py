"""Tests for comma-separated --check category lists (POST_V01 Rotation 2, R2.7).

`--check` historically accepted a single category or the keyword `all`. R2.7
extends it to accept a comma-separated list of categories — the input-side
complement to the Rotation 2 output triage pipeline: a bounty hunter can now
scope a single scan to exactly the detection surface a program needs (e.g.
`access-control,delegatecall,upgrade` — the proxy/admin attack cluster) instead
of accepting the noise of `all` or running and merging several scans.

These tests cover the pure resolve_checks primitive (the parsing/validation/
dedupe logic), the CLI surface (help text + argparse no longer rejecting a
list), and a bytecode-mode end-to-end subprocess run that needs no compiler.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from omen import CATEGORIES
from omen.analyzer import resolve_checks
from omen.cli import build_parser

FIXTURES = Path(__file__).parent / "fixtures"


# --- resolve_checks: backward-compatible single / all behaviour -------------


def test_resolve_all_unchanged():
    # 'all' still expands to every category, in CATEGORIES order.
    assert resolve_checks("all") == list(CATEGORIES)


def test_resolve_single_category_unchanged():
    assert resolve_checks("reentrancy") == ["reentrancy"]


def test_resolve_single_category_with_whitespace():
    # Surrounding whitespace is tolerated.
    assert resolve_checks("  suicidal  ") == ["suicidal"]


def test_resolve_unknown_single_raises():
    with pytest.raises(ValueError) as exc:
        resolve_checks("not-a-real-check")
    assert "not-a-real-check" in str(exc.value)
    # The error names the valid choices.
    assert "reentrancy" in str(exc.value)


# --- resolve_checks: comma-separated list (the R2.7 feature) ----------------


def test_resolve_two_categories():
    assert resolve_checks("reentrancy,suicidal") == ["reentrancy", "suicidal"]


def test_resolve_three_categories_proxy_admin_cluster():
    # The motivating use case: scope a scan to the proxy/admin attack surface.
    assert resolve_checks("access-control,delegatecall,upgrade") == [
        "access-control",
        "delegatecall",
        "upgrade",
    ]


def test_resolve_preserves_user_order():
    # The order the user lists classes in is the order they resolve in.
    assert resolve_checks("upgrade,access-control") == ["upgrade", "access-control"]


def test_resolve_dedupes_preserving_first_seen_order():
    assert resolve_checks("reentrancy,suicidal,reentrancy") == [
        "reentrancy",
        "suicidal",
    ]


def test_resolve_tolerates_whitespace_around_list_items():
    assert resolve_checks(" reentrancy , suicidal ") == ["reentrancy", "suicidal"]


def test_resolve_tolerates_trailing_and_double_commas():
    # Empty segments from a trailing/double comma are dropped, not errored.
    assert resolve_checks("reentrancy,,suicidal,") == ["reentrancy", "suicidal"]


def test_resolve_list_with_unknown_member_raises_naming_offender():
    with pytest.raises(ValueError) as exc:
        resolve_checks("reentrancy,bogus,suicidal")
    assert "bogus" in str(exc.value)


def test_resolve_empty_string_raises():
    with pytest.raises(ValueError):
        resolve_checks("")


def test_resolve_only_commas_raises():
    with pytest.raises(ValueError):
        resolve_checks(",,,")


def test_resolve_all_alone_in_a_list_expands():
    # A degenerate one-element list of just 'all' still expands to everything.
    assert resolve_checks("all,") == list(CATEGORIES)
    assert resolve_checks(" all ") == list(CATEGORIES)


def test_resolve_all_combined_with_others_rejected():
    # 'all' already covers everything; combining it with explicit names is a
    # mistake, so it is rejected rather than silently treated as 'all'.
    with pytest.raises(ValueError) as exc:
        resolve_checks("all,reentrancy")
    assert "all" in str(exc.value).lower()


def test_resolve_every_category_individually_is_valid():
    # Every advertised category resolves as a single-element list.
    for cat in CATEGORIES:
        assert resolve_checks(cat) == [cat]


def test_resolve_full_list_of_all_categories():
    # Listing every category explicitly resolves to the full set in that order.
    spec = ",".join(CATEGORIES)
    assert resolve_checks(spec) == list(CATEGORIES)


# --- CLI surface ------------------------------------------------------------


def test_help_documents_check_list_syntax():
    text = build_parser().format_help()
    # The metavar advertises the comma-list syntax.
    assert "CATEGORY[,CATEGORY...]" in text
    # The help documents that a comma-separated list is accepted. (argparse
    # may hard-wrap the literal example across a line — even inside a hyphenated
    # word — so assert on the descriptive phrasing rather than the exact
    # example string.)
    # argparse hard-wraps long help, sometimes mid-hyphenated-word ("comma-\n
    # separated" -> "comma- separated"); undo that artifact before matching.
    collapsed = " ".join(text.split()).replace("- ", "-").lower()
    assert "comma-separated list" in collapsed
    assert "'all'" in collapsed


def test_parser_accepts_comma_list_without_argparse_rejection():
    # argparse `choices` previously rejected a comma list at parse time; the
    # parser must now accept the raw string and defer validation to resolve_checks.
    parser = build_parser()
    args = parser.parse_args(
        ["--contract", "x.sol", "--input-type", "sol", "--check", "reentrancy,suicidal"]
    )
    assert args.check == "reentrancy,suicidal"


def test_cli_rejects_unknown_check_member_with_exit_2():
    # A bad category in a list is an input/usage error -> exit code 2.
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
            "suicidal,bogus",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2
    assert "bogus" in proc.stderr


def test_cli_rejects_all_combined_with_others_with_exit_2():
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
            "all,suicidal",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2


# --- End-to-end: a comma-list scopes the scan (bytecode mode, no compiler) ---


def test_check_list_scopes_scan_end_to_end():
    """A two-category --check on a fixture that hits both classes returns both,
    and the report's `checks` field records exactly the requested list."""
    import json

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
            "reentrancy,suicidal",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    # The report echoes exactly the resolved check list (order preserved).
    assert report["checks"] == ["reentrancy", "suicidal"]
    found = {f["category"] for f in report["findings"]}
    assert found == {"reentrancy", "suicidal"}


def test_check_list_excludes_unrequested_classes_end_to_end():
    """Asking for only `reentrancy` on the same fixture must NOT surface the
    suicidal finding the fixture also contains — the list scopes the surface."""
    import json

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
            "reentrancy",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    found = {f["category"] for f in report["findings"]}
    assert "suicidal" not in found
    assert found <= {"reentrancy"}
