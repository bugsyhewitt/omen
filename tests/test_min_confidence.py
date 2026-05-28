"""Tests for the --min-confidence filter (POST_V01 Rank 8).

omen findings carry a confidence (low/medium/high). Slither emits its own
confidence; omen's bytecode/address heuristics (POST_V01 Rank 1) default to
"low". --min-confidence lets a bounty hunter suppress findings below a chosen
threshold — the common case when triaging large batches where the
low-confidence opcode heuristics dominate the output.

These tests use a synthetic mixed-confidence bytecode fixture so they run with
no solc dependency:

    CALLVALUE(0x34) CALL(0xf1) SSTORE(0x55) SELFDESTRUCT(0xff)

which yields one HIGH-confidence finding (suicidal — the SELFDESTRUCT opcode)
and one LOW-confidence finding (reentrancy — an SSTORE after a CALL).
"""

from __future__ import annotations

import subprocess
import sys

import pytest

from omen.analyzer import _filter_by_confidence, analyze
from omen.cli import build_parser
from omen.findings import (
    CONFIDENCE_ORDER,
    Evidence,
    Finding,
    Severity,
    confidence_rank,
)


# ---------------------------------------------------------------------------
# confidence_rank — the ordering primitive
# ---------------------------------------------------------------------------


def test_confidence_order_is_low_to_high():
    assert CONFIDENCE_ORDER == ("low", "medium", "high")


def test_confidence_rank_orders_levels():
    assert confidence_rank("low") < confidence_rank("medium") < confidence_rank("high")


def test_confidence_rank_is_case_and_whitespace_insensitive():
    assert confidence_rank("  HIGH ") == confidence_rank("high")
    assert confidence_rank("Medium") == confidence_rank("medium")


def test_confidence_rank_unknown_is_lowest():
    # Unknown / empty confidence ranks below "medium" so a stricter threshold
    # never silently keeps it.
    assert confidence_rank("bogus") == 0
    assert confidence_rank("") == 0
    assert confidence_rank(None) == 0  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _filter_by_confidence — the pure filter
# ---------------------------------------------------------------------------


def _finding(confidence: str, category: str = "suicidal") -> Finding:
    return Finding(
        category=category,
        severity=Severity.HIGH,
        title=f"{category} ({confidence})",
        description="test finding",
        detector="test",
        confidence=confidence,
        evidence=Evidence(),
    )


def test_filter_low_keeps_everything():
    findings = [_finding("low"), _finding("medium"), _finding("high")]
    assert _filter_by_confidence(findings, "low") == findings


def test_filter_medium_drops_low():
    findings = [_finding("low"), _finding("medium"), _finding("high")]
    kept = _filter_by_confidence(findings, "medium")
    assert [f.confidence for f in kept] == ["medium", "high"]


def test_filter_high_keeps_only_high():
    findings = [_finding("low"), _finding("medium"), _finding("high")]
    kept = _filter_by_confidence(findings, "high")
    assert [f.confidence for f in kept] == ["high"]


def test_filter_unknown_threshold_keeps_everything():
    # An unrecognized threshold ranks as 0 ("low"), so nothing is dropped.
    findings = [_finding("low"), _finding("high")]
    assert _filter_by_confidence(findings, "bogus") == findings


def test_filter_does_not_mutate_input():
    findings = [_finding("low"), _finding("high")]
    original = list(findings)
    _filter_by_confidence(findings, "high")
    assert findings == original


# ---------------------------------------------------------------------------
# analyze() integration — bytecode mode, no solc required
# ---------------------------------------------------------------------------


def test_default_min_confidence_keeps_all(fixtures_dir):
    report = analyze(
        contract=str(fixtures_dir / "mixed-confidence.bin"),
        input_type="bytecode",
        check="all",
    )
    cats = {f.category for f in report.findings}
    # Both the high-confidence suicidal and the low-confidence reentrancy lead.
    assert "suicidal" in cats
    assert "reentrancy" in cats


def test_min_confidence_medium_drops_low_findings(fixtures_dir):
    report = analyze(
        contract=str(fixtures_dir / "mixed-confidence.bin"),
        input_type="bytecode",
        check="all",
        min_confidence="medium",
    )
    cats = {f.category for f in report.findings}
    assert "suicidal" in cats  # high-confidence survives
    assert "reentrancy" not in cats  # low-confidence heuristic suppressed
    assert all(confidence_rank(f.confidence) >= confidence_rank("medium") for f in report.findings)


def test_min_confidence_high_keeps_only_high(fixtures_dir):
    report = analyze(
        contract=str(fixtures_dir / "mixed-confidence.bin"),
        input_type="bytecode",
        check="all",
        min_confidence="high",
    )
    assert report.findings  # the suicidal finding is high-confidence
    assert all(f.confidence == "high" for f in report.findings)
    assert report.to_dict()["finding_count"] == len(report.findings)


def test_min_confidence_filter_reflected_in_finding_count(fixtures_dir):
    """finding_count in the serialized report tracks the filtered list."""
    full = analyze(
        contract=str(fixtures_dir / "mixed-confidence.bin"),
        input_type="bytecode",
        check="all",
        min_confidence="low",
    )
    filtered = analyze(
        contract=str(fixtures_dir / "mixed-confidence.bin"),
        input_type="bytecode",
        check="all",
        min_confidence="high",
    )
    assert filtered.to_dict()["finding_count"] < full.to_dict()["finding_count"]


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def test_help_lists_min_confidence():
    text = build_parser().format_help()
    assert "--min-confidence" in text
    for choice in ("low", "medium", "high"):
        assert choice in text


def test_cli_default_min_confidence_is_low():
    args = build_parser().parse_args(
        ["--contract", "x.bin", "--input-type", "bytecode"]
    )
    assert args.min_confidence == "low"


def test_cli_rejects_invalid_min_confidence():
    with pytest.raises(SystemExit):
        build_parser().parse_args(
            ["--contract", "x.bin", "--input-type", "bytecode", "--min-confidence", "extreme"]
        )


def test_batch_forwards_min_confidence(fixtures_dir, tmp_path, capsys):
    """run_batch applies --min-confidence uniformly across the batch (JSONL)."""
    import json

    from omen.batch import run_batch

    # A list file pointing at the mixed-confidence fixture twice.
    list_file = tmp_path / "targets.txt"
    bin_path = str(fixtures_dir / "mixed-confidence.bin")
    list_file.write_text(f"{bin_path}\n{bin_path}\n")

    exit_code = run_batch(
        path=str(list_file),
        input_type="bytecode",
        check="all",
        min_confidence="high",
    )
    assert exit_code == 0

    captured = capsys.readouterr()
    lines = [ln for ln in captured.out.splitlines() if ln.strip()]
    assert len(lines) == 2
    for line in lines:
        report = json.loads(line)
        assert all(f["confidence"] == "high" for f in report["findings"])


def test_cli_min_confidence_end_to_end(fixtures_dir):
    """A real subprocess run honours --min-confidence high (no solc needed)."""
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
            "--min-confidence",
            "high",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    assert report["finding_count"] == len(report["findings"])
    assert all(f["confidence"] == "high" for f in report["findings"])
