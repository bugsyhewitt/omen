"""Tests for the --min-severity filter (POST_V01 Rotation 2).

omen findings carry a severity (informational..critical). With ten detection
classes spanning the full taxonomy, a bounty hunter triaging a whole program
scope wants to surface only the high-impact leads first. --min-severity is the
severity-axis sibling of --min-confidence: a finding must pass both thresholds
to survive.

These tests use the same synthetic mixed-confidence bytecode fixture as the
confidence tests so they run with no solc dependency:

    CALLVALUE(0x34) CALL(0xf1) SSTORE(0x55) SELFDESTRUCT(0xff)

which yields one HIGH-severity finding (suicidal — the SELFDESTRUCT opcode)
and one HIGH-severity finding (reentrancy — an SSTORE after a CALL). Both are
HIGH severity by their category defaults, so the fixture exercises the
"high threshold keeps both, critical threshold drops both" boundaries. The pure
filter / rank tests cover the rest of the taxonomy directly.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

from omen.analyzer import _filter_by_severity, analyze
from omen.cli import build_parser
from omen.findings import (
    SEVERITY_ORDER,
    Evidence,
    Finding,
    Severity,
    severity_rank,
)


# ---------------------------------------------------------------------------
# severity_rank — the ordering primitive
# ---------------------------------------------------------------------------


def test_severity_order_is_informational_to_critical():
    assert SEVERITY_ORDER == (
        Severity.INFORMATIONAL,
        Severity.LOW,
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
    )


def test_severity_rank_orders_levels():
    assert (
        severity_rank(Severity.INFORMATIONAL)
        < severity_rank(Severity.LOW)
        < severity_rank(Severity.MEDIUM)
        < severity_rank(Severity.HIGH)
        < severity_rank(Severity.CRITICAL)
    )


def test_severity_rank_accepts_enum_and_string():
    assert severity_rank(Severity.HIGH) == severity_rank("high")
    assert severity_rank(Severity.CRITICAL) == severity_rank("critical")


def test_severity_rank_is_case_and_whitespace_insensitive():
    assert severity_rank("  HIGH ") == severity_rank("high")
    assert severity_rank("Medium") == severity_rank("medium")


def test_severity_rank_unknown_is_lowest():
    # Unknown / empty severity ranks below "low" so a stricter threshold never
    # silently keeps it.
    assert severity_rank("bogus") == 0
    assert severity_rank("") == 0
    assert severity_rank(None) == 0  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _filter_by_severity — the pure filter
# ---------------------------------------------------------------------------


def _finding(severity: Severity, category: str = "suicidal") -> Finding:
    return Finding(
        category=category,
        severity=severity,
        title=f"{category} ({severity.value})",
        description="test finding",
        detector="test",
        confidence="high",
        evidence=Evidence(),
    )


def _all_severities() -> list[Finding]:
    return [
        _finding(Severity.INFORMATIONAL),
        _finding(Severity.LOW),
        _finding(Severity.MEDIUM),
        _finding(Severity.HIGH),
        _finding(Severity.CRITICAL),
    ]


def test_filter_informational_keeps_everything():
    findings = _all_severities()
    assert _filter_by_severity(findings, "informational") == findings


def test_filter_medium_drops_below_medium():
    kept = _filter_by_severity(_all_severities(), "medium")
    assert [f.severity for f in kept] == [
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
    ]


def test_filter_high_keeps_high_and_critical():
    kept = _filter_by_severity(_all_severities(), "high")
    assert [f.severity for f in kept] == [Severity.HIGH, Severity.CRITICAL]


def test_filter_critical_keeps_only_critical():
    kept = _filter_by_severity(_all_severities(), "critical")
    assert [f.severity for f in kept] == [Severity.CRITICAL]


def test_filter_unknown_threshold_keeps_everything():
    findings = _all_severities()
    assert _filter_by_severity(findings, "bogus") == findings


def test_filter_does_not_mutate_input():
    findings = _all_severities()
    original = list(findings)
    _filter_by_severity(findings, "critical")
    assert findings == original


# ---------------------------------------------------------------------------
# analyze() integration — bytecode mode, no solc required
# ---------------------------------------------------------------------------


def test_default_min_severity_keeps_all(fixtures_dir):
    report = analyze(
        contract=str(fixtures_dir / "mixed-confidence.bin"),
        input_type="bytecode",
        check="all",
    )
    cats = {f.category for f in report.findings}
    assert "suicidal" in cats
    assert "reentrancy" in cats


def test_min_severity_high_keeps_high_findings(fixtures_dir):
    # Both fixture findings (suicidal, reentrancy) default to HIGH severity, so
    # a "high" threshold keeps them.
    report = analyze(
        contract=str(fixtures_dir / "mixed-confidence.bin"),
        input_type="bytecode",
        check="all",
        min_severity="high",
    )
    cats = {f.category for f in report.findings}
    assert "suicidal" in cats
    assert "reentrancy" in cats
    assert all(severity_rank(f.severity) >= severity_rank("high") for f in report.findings)


def test_min_severity_critical_drops_all_high(fixtures_dir):
    # Neither fixture finding is CRITICAL, so a "critical" threshold drops both.
    report = analyze(
        contract=str(fixtures_dir / "mixed-confidence.bin"),
        input_type="bytecode",
        check="all",
        min_severity="critical",
    )
    assert report.findings == []
    assert report.to_dict()["finding_count"] == 0


def test_min_severity_composes_with_min_confidence(fixtures_dir):
    """A finding must pass BOTH thresholds. The reentrancy lead is HIGH
    severity but LOW confidence; the suicidal lead is HIGH/HIGH. Asking for
    high severity AND high confidence keeps only suicidal."""
    report = analyze(
        contract=str(fixtures_dir / "mixed-confidence.bin"),
        input_type="bytecode",
        check="all",
        min_confidence="high",
        min_severity="high",
    )
    cats = {f.category for f in report.findings}
    assert cats == {"suicidal"}


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def test_help_lists_min_severity():
    text = build_parser().format_help()
    assert "--min-severity" in text
    for choice in ("informational", "low", "medium", "high", "critical"):
        assert choice in text


def test_cli_default_min_severity_is_informational():
    args = build_parser().parse_args(
        ["--contract", "x.bin", "--input-type", "bytecode"]
    )
    assert args.min_severity == "informational"


def test_cli_rejects_invalid_min_severity():
    with pytest.raises(SystemExit):
        build_parser().parse_args(
            ["--contract", "x.bin", "--input-type", "bytecode", "--min-severity", "fatal"]
        )


def test_batch_forwards_min_severity(fixtures_dir, tmp_path, capsys):
    """run_batch applies --min-severity uniformly across the batch (JSONL)."""
    import json

    from omen.batch import run_batch

    list_file = tmp_path / "targets.txt"
    bin_path = str(fixtures_dir / "mixed-confidence.bin")
    list_file.write_text(f"{bin_path}\n{bin_path}\n")

    exit_code = run_batch(
        path=str(list_file),
        input_type="bytecode",
        check="all",
        min_severity="critical",
    )
    assert exit_code == 0

    captured = capsys.readouterr()
    lines = [ln for ln in captured.out.splitlines() if ln.strip()]
    assert len(lines) == 2
    for line in lines:
        report = json.loads(line)
        # Nothing in the fixture is critical, so every per-item report is empty.
        assert report["findings"] == []
        assert report["finding_count"] == 0


def test_cli_min_severity_end_to_end(fixtures_dir):
    """A real subprocess run honours --min-severity high (no solc needed)."""
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
            "--min-severity",
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
    assert all(f["severity"] in ("high", "critical") for f in report["findings"])
