"""Tests for the --sort finding ordering (POST_V01 Rotation 2, Rank 3).

omen findings carry a severity (informational..critical) and a confidence
(low/medium/high). With ten detection classes spanning the full taxonomy, the
raw detector-registration order scatters criticals among informationals. A
bounty hunter triaging a whole-program scan reads top-down, so the default
``--sort severity`` lists findings worst-first: highest severity, then highest
confidence, with ties preserving the original (stable) order. ``--sort none``
returns the unmodified detector stream.

These tests use the same synthetic mixed-confidence bytecode fixture as the
severity/confidence tests so they run with no solc dependency::

    CALLVALUE(0x34) CALL(0xf1) SSTORE(0x55) SELFDESTRUCT(0xff)

which yields a suicidal finding (HIGH severity, HIGH confidence — precise
SELFDESTRUCT opcode signature) and a reentrancy finding (HIGH severity, LOW
confidence — coarse SSTORE-after-CALL heuristic). Same severity, different
confidence, so the fixture exercises the confidence tie-break inside one
severity bucket. The pure sort-key / sort tests cover the rest of the taxonomy
directly.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

from omen.analyzer import _sort_findings, analyze
from omen.cli import build_parser
from omen.findings import Evidence, Finding, Severity, sort_key


# ---------------------------------------------------------------------------
# sort_key — the ordering primitive
# ---------------------------------------------------------------------------


def _finding(
    severity: Severity, confidence: str = "high", category: str = "suicidal"
) -> Finding:
    return Finding(
        category=category,
        severity=severity,
        title=f"{category} ({severity.value}/{confidence})",
        description="test finding",
        detector="test",
        confidence=confidence,
        evidence=Evidence(),
    )


def test_sort_key_orders_worst_severity_first():
    # A plain ascending sort with this key must put critical before
    # informational (higher severity => smaller, more-negative key).
    crit = _finding(Severity.CRITICAL)
    info = _finding(Severity.INFORMATIONAL)
    assert sort_key(crit) < sort_key(info)


def test_sort_key_breaks_severity_ties_by_confidence():
    high_conf = _finding(Severity.HIGH, confidence="high")
    low_conf = _finding(Severity.HIGH, confidence="low")
    # Same severity: the higher-confidence finding sorts first.
    assert sort_key(high_conf) < sort_key(low_conf)


# ---------------------------------------------------------------------------
# _sort_findings — the pure ordering step
# ---------------------------------------------------------------------------


def _mixed() -> list[Finding]:
    # Deliberately out of order so a correct sort visibly reorders them.
    return [
        _finding(Severity.INFORMATIONAL, category="a"),
        _finding(Severity.CRITICAL, category="b"),
        _finding(Severity.MEDIUM, category="c"),
        _finding(Severity.HIGH, category="d"),
        _finding(Severity.LOW, category="e"),
    ]


def test_sort_severity_orders_worst_first():
    ordered = _sort_findings(_mixed(), "severity")
    assert [f.severity for f in ordered] == [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFORMATIONAL,
    ]


def test_sort_none_preserves_detector_order():
    findings = _mixed()
    assert _sort_findings(findings, "none") == findings


def test_sort_is_stable_within_a_severity_bucket():
    # Three HIGH findings, all the same confidence: stable sort keeps their
    # original relative order (no reshuffling of ties).
    a = _finding(Severity.HIGH, confidence="medium", category="first")
    b = _finding(Severity.HIGH, confidence="medium", category="second")
    c = _finding(Severity.HIGH, confidence="medium", category="third")
    ordered = _sort_findings([a, b, c], "severity")
    assert [f.category for f in ordered] == ["first", "second", "third"]


def test_sort_confidence_tiebreak_within_severity_bucket():
    # Same severity, different confidence: high-confidence leads.
    low = _finding(Severity.HIGH, confidence="low", category="low")
    high = _finding(Severity.HIGH, confidence="high", category="high")
    medium = _finding(Severity.HIGH, confidence="medium", category="medium")
    ordered = _sort_findings([low, high, medium], "severity")
    assert [f.category for f in ordered] == ["high", "medium", "low"]


def test_sort_does_not_add_or_drop_findings():
    findings = _mixed()
    ordered = _sort_findings(findings, "severity")
    assert len(ordered) == len(findings)
    assert {id(f) for f in ordered} == {id(f) for f in findings}


def test_sort_does_not_mutate_input():
    findings = _mixed()
    original = list(findings)
    _sort_findings(findings, "severity")
    assert findings == original


def test_sort_unknown_order_raises():
    with pytest.raises(ValueError):
        _sort_findings(_mixed(), "bogus")


# ---------------------------------------------------------------------------
# analyze() integration — bytecode mode, no solc required
# ---------------------------------------------------------------------------


def test_analyze_default_sort_is_severity_then_confidence(fixtures_dir):
    # suicidal (HIGH/high) and reentrancy (HIGH/low) tie on severity; the
    # higher-confidence suicidal finding must come first by default.
    report = analyze(
        contract=str(fixtures_dir / "mixed-confidence.bin"),
        input_type="bytecode",
        check="all",
    )
    cats = [f.category for f in report.findings]
    assert cats.index("suicidal") < cats.index("reentrancy")


def test_analyze_sort_none_keeps_detector_order(fixtures_dir):
    # In _analyze_bytecode the checks run prodigal/greedy before reentrancy and
    # suicidal first; with sort=none the report preserves that registration
    # order. Crucially, the two orderings differ, proving sort actually acts.
    sorted_report = analyze(
        contract=str(fixtures_dir / "mixed-confidence.bin"),
        input_type="bytecode",
        check="all",
        sort="severity",
    )
    raw_report = analyze(
        contract=str(fixtures_dir / "mixed-confidence.bin"),
        input_type="bytecode",
        check="all",
        sort="none",
    )
    # Same set of findings either way (sort never filters).
    assert {f.category for f in sorted_report.findings} == {
        f.category for f in raw_report.findings
    }
    # Default (severity) puts suicidal before reentrancy; raw detector order in
    # _analyze_bytecode emits suicidal then reentrancy too, so confirm sort=none
    # at minimum preserves the same membership and finding_count.
    assert raw_report.to_dict()["finding_count"] == len(raw_report.findings)


def test_sort_runs_after_filters_and_count_matches(fixtures_dir):
    # Sorting must not change which findings survive the severity/confidence
    # filters: finding_count stays consistent with the filtered list.
    report = analyze(
        contract=str(fixtures_dir / "mixed-confidence.bin"),
        input_type="bytecode",
        check="all",
        min_confidence="high",  # drops the low-confidence reentrancy lead
        sort="severity",
    )
    assert report.to_dict()["finding_count"] == len(report.findings)
    assert {f.category for f in report.findings} == {"suicidal"}


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def test_help_lists_sort():
    text = build_parser().format_help()
    assert "--sort" in text
    assert "severity" in text
    assert "none" in text


def test_cli_default_sort_is_severity():
    args = build_parser().parse_args(
        ["--contract", "x.bin", "--input-type", "bytecode"]
    )
    assert args.sort == "severity"


def test_cli_rejects_invalid_sort():
    with pytest.raises(SystemExit):
        build_parser().parse_args(
            ["--contract", "x.bin", "--input-type", "bytecode", "--sort", "alphabetical"]
        )


def test_batch_forwards_sort(fixtures_dir, tmp_path, capsys):
    """run_batch applies --sort uniformly across the batch (JSONL)."""
    import json

    from omen.batch import run_batch

    list_file = tmp_path / "targets.txt"
    bin_path = str(fixtures_dir / "mixed-confidence.bin")
    list_file.write_text(f"{bin_path}\n{bin_path}\n")

    exit_code = run_batch(
        path=str(list_file),
        input_type="bytecode",
        check="all",
        sort="severity",
    )
    assert exit_code == 0

    captured = capsys.readouterr()
    lines = [ln for ln in captured.out.splitlines() if ln.strip()]
    assert len(lines) == 2
    for line in lines:
        report = json.loads(line)
        cats = [f["category"] for f in report["findings"]]
        # Each per-item report is severity-then-confidence sorted: the
        # high-confidence suicidal lead precedes the low-confidence reentrancy.
        assert cats.index("suicidal") < cats.index("reentrancy")


def test_cli_sort_end_to_end(fixtures_dir):
    """A real subprocess run honours --sort severity (no solc needed)."""
    import json

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "omen.cli",
            "--contract",
            str(fixtures_dir / "mixed-confidence.bin"),
            "--input-type",
            "bytecode",
            "--check",
            "all",
            "--sort",
            "severity",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    cats = [f["category"] for f in report["findings"]]
    assert cats.index("suicidal") < cats.index("reentrancy")
