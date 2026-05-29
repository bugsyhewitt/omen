"""Tests for --severity-override (per-category severity, org-specific risk tuning).

omen ships a built-in DEFAULT_SEVERITY per detection class and, in source mode,
maps Slither's per-finding impact onto severity. An org with its own risk model
may rank a class differently — e.g. treat any reentrancy lead as critical, or
demote the noisy bytecode greedy heuristic to informational. --severity-override
is the lever: a comma-separated CATEGORY=SEVERITY list that re-stamps matched
findings' severity *before* the --min-severity filter, --sort ordering, the
--limit cap, and the --fail-on gate, so the override flows through the whole
pipeline.

These tests use the synthetic mixed-confidence bytecode fixture (no solc needed):

    CALLVALUE(0x34) CALL(0xf1) SSTORE(0x55) SELFDESTRUCT(0xff)

which yields a HIGH-severity suicidal finding (high confidence) and a
HIGH-severity reentrancy finding (low confidence). The pure parser/apply tests
cover the rest of the taxonomy directly.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from omen.analyzer import analyze
from omen.cli import build_parser
from omen.findings import (
    Evidence,
    Finding,
    Severity,
    apply_severity_overrides,
    parse_severity_overrides,
    severity_rank,
)


# ---------------------------------------------------------------------------
# parse_severity_overrides — the pure parser
# ---------------------------------------------------------------------------


def test_parse_none_and_blank_yield_empty_map():
    assert parse_severity_overrides(None) == {}
    assert parse_severity_overrides("") == {}
    assert parse_severity_overrides("   ") == {}


def test_parse_single_pair():
    assert parse_severity_overrides("reentrancy=critical") == {
        "reentrancy": Severity.CRITICAL
    }


def test_parse_multiple_pairs():
    assert parse_severity_overrides("reentrancy=critical,tx-origin=high") == {
        "reentrancy": Severity.CRITICAL,
        "tx-origin": Severity.HIGH,
    }


def test_parse_is_whitespace_and_case_insensitive_on_severity():
    assert parse_severity_overrides("  reentrancy = CRITICAL ") == {
        "reentrancy": Severity.CRITICAL
    }
    assert parse_severity_overrides("greedy=Low") == {"greedy": Severity.LOW}


def test_parse_tolerates_trailing_and_double_commas():
    assert parse_severity_overrides("greedy=low,,suicidal=critical,") == {
        "greedy": Severity.LOW,
        "suicidal": Severity.CRITICAL,
    }


def test_parse_last_write_wins_for_repeated_category():
    assert parse_severity_overrides("greedy=low,greedy=critical") == {
        "greedy": Severity.CRITICAL
    }


def test_parse_rejects_missing_equals():
    with pytest.raises(ValueError, match="CATEGORY=SEVERITY"):
        parse_severity_overrides("reentrancy")


def test_parse_rejects_empty_side():
    with pytest.raises(ValueError, match="CATEGORY=SEVERITY"):
        parse_severity_overrides("=critical")
    with pytest.raises(ValueError, match="CATEGORY=SEVERITY"):
        parse_severity_overrides("reentrancy=")


def test_parse_rejects_unknown_category():
    with pytest.raises(ValueError, match="unknown category 'bogus'"):
        parse_severity_overrides("bogus=high")


def test_parse_rejects_unknown_severity():
    with pytest.raises(ValueError, match="unknown severity 'fatal'"):
        parse_severity_overrides("reentrancy=fatal")


# ---------------------------------------------------------------------------
# apply_severity_overrides — the pure mutator
# ---------------------------------------------------------------------------


def _finding(category: str, severity: Severity) -> Finding:
    return Finding(
        category=category,
        severity=severity,
        title=f"{category} ({severity.value})",
        description="test finding",
        detector="test",
        confidence="high",
        evidence=Evidence(),
    )


def test_apply_empty_map_is_noop():
    findings = [_finding("reentrancy", Severity.HIGH)]
    assert apply_severity_overrides(findings, {}) == findings
    assert findings[0].severity == Severity.HIGH


def test_apply_overrides_matching_category_only():
    findings = [
        _finding("reentrancy", Severity.HIGH),
        _finding("greedy", Severity.MEDIUM),
    ]
    apply_severity_overrides(findings, {"reentrancy": Severity.CRITICAL})
    assert findings[0].severity == Severity.CRITICAL  # overridden
    assert findings[1].severity == Severity.MEDIUM  # untouched


def test_apply_can_pin_severity_down():
    findings = [_finding("greedy", Severity.MEDIUM)]
    apply_severity_overrides(findings, {"greedy": Severity.INFORMATIONAL})
    assert findings[0].severity == Severity.INFORMATIONAL


def test_apply_preserves_other_fields():
    findings = [_finding("tx-origin", Severity.MEDIUM)]
    original = findings[0]
    apply_severity_overrides(findings, {"tx-origin": Severity.HIGH})
    assert original.category == "tx-origin"
    assert original.confidence == "high"
    assert original.detector == "test"
    assert original.severity == Severity.HIGH


# ---------------------------------------------------------------------------
# analyze() integration — bytecode mode, no solc required
# ---------------------------------------------------------------------------


def test_override_restamps_finding_severity(fixtures_dir):
    report = analyze(
        contract=str(fixtures_dir / "mixed-confidence.bin"),
        input_type="bytecode",
        check="all",
        severity_override="suicidal=critical",
    )
    suicidal = [f for f in report.findings if f.category == "suicidal"]
    assert suicidal, "fixture should yield a suicidal finding"
    assert all(f.severity == Severity.CRITICAL for f in suicidal)
    # reentrancy is untouched — still its HIGH default.
    reentrancy = [f for f in report.findings if f.category == "reentrancy"]
    assert reentrancy and all(f.severity == Severity.HIGH for f in reentrancy)


def test_override_composes_with_min_severity(fixtures_dir):
    """Pinning reentrancy DOWN to informational lets --min-severity high drop it
    while the suicidal HIGH finding survives — proof the override runs before
    the filter."""
    report = analyze(
        contract=str(fixtures_dir / "mixed-confidence.bin"),
        input_type="bytecode",
        check="all",
        severity_override="reentrancy=informational",
        min_severity="high",
    )
    cats = {f.category for f in report.findings}
    assert "reentrancy" not in cats
    assert "suicidal" in cats


def test_override_composes_with_fail_on_gate(fixtures_dir):
    """Pinning suicidal UP to critical trips a --fail-on critical gate that the
    default HIGH severity would not."""
    # Baseline: nothing is critical, so a critical gate does not trip.
    base = analyze(
        contract=str(fixtures_dir / "mixed-confidence.bin"),
        input_type="bytecode",
        check="all",
        fail_on="critical",
    )
    assert base.gate_triggered is False

    gated = analyze(
        contract=str(fixtures_dir / "mixed-confidence.bin"),
        input_type="bytecode",
        check="all",
        severity_override="suicidal=critical",
        fail_on="critical",
    )
    assert gated.gate_triggered is True


def test_override_affects_sort_order(fixtures_dir):
    """With default worst-first sort, pinning reentrancy to critical floats it
    above the suicidal HIGH finding."""
    report = analyze(
        contract=str(fixtures_dir / "mixed-confidence.bin"),
        input_type="bytecode",
        check="all",
        severity_override="reentrancy=critical",
        sort="severity",
    )
    # First finding should now be the critical reentrancy one.
    assert report.findings[0].category == "reentrancy"
    assert report.findings[0].severity == Severity.CRITICAL


def test_no_override_keeps_defaults(fixtures_dir):
    report = analyze(
        contract=str(fixtures_dir / "mixed-confidence.bin"),
        input_type="bytecode",
        check="all",
    )
    for f in report.findings:
        if f.category == "suicidal":
            assert f.severity == Severity.HIGH


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def test_help_lists_severity_override():
    text = build_parser().format_help()
    assert "--severity-override" in text
    assert "CATEGORY=SEVERITY" in text


def test_cli_default_severity_override_is_none():
    args = build_parser().parse_args(
        ["--contract", "x.bin", "--input-type", "bytecode"]
    )
    assert args.severity_override is None


def test_cli_accepts_severity_override_value():
    args = build_parser().parse_args(
        [
            "--contract",
            "x.bin",
            "--input-type",
            "bytecode",
            "--severity-override",
            "reentrancy=critical",
        ]
    )
    assert args.severity_override == "reentrancy=critical"


def test_cli_rejects_unknown_category(fixtures_dir):
    """A bad --severity-override is a usage error (exit 2), not a crash."""
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "omen.cli",
            "--contract",
            str(fixtures_dir / "mixed-confidence.bin"),
            "--input-type",
            "bytecode",
            "--severity-override",
            "bogus=high",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2
    assert "unknown category" in proc.stderr


def test_cli_rejects_unknown_severity(fixtures_dir):
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "omen.cli",
            "--contract",
            str(fixtures_dir / "mixed-confidence.bin"),
            "--input-type",
            "bytecode",
            "--severity-override",
            "reentrancy=fatal",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2
    assert "unknown severity" in proc.stderr


def test_cli_severity_override_end_to_end(fixtures_dir):
    """A real subprocess run honours --severity-override (no solc needed)."""
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
            "--severity-override",
            "suicidal=critical",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    suicidal = [f for f in report["findings"] if f["category"] == "suicidal"]
    assert suicidal and all(f["severity"] == "critical" for f in suicidal)


# ---------------------------------------------------------------------------
# Batch + config integration
# ---------------------------------------------------------------------------


def test_batch_forwards_severity_override(fixtures_dir, tmp_path, capsys):
    """run_batch applies --severity-override uniformly across the batch."""
    from omen.batch import run_batch

    list_file = tmp_path / "targets.txt"
    bin_path = str(fixtures_dir / "mixed-confidence.bin")
    list_file.write_text(f"{bin_path}\n{bin_path}\n")

    exit_code = run_batch(
        path=str(list_file),
        input_type="bytecode",
        check="all",
        severity_override="suicidal=critical",
    )
    assert exit_code == 0

    captured = capsys.readouterr()
    lines = [ln for ln in captured.out.splitlines() if ln.strip()]
    assert len(lines) == 2
    for line in lines:
        report = json.loads(line)
        suicidal = [f for f in report["findings"] if f["category"] == "suicidal"]
        assert suicidal and all(f["severity"] == "critical" for f in suicidal)


def test_config_file_can_set_severity_override(fixtures_dir, tmp_path):
    """An omen.toml may carry severity_override; the CLI applies it."""
    from omen.config import load_config

    cfg = tmp_path / "omen.toml"
    cfg.write_text('[omen]\nseverity_override = "suicidal=critical"\n')
    loaded = load_config(str(cfg))
    assert loaded["severity_override"] == "suicidal=critical"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "omen.cli",
            "--config",
            str(cfg),
            "--contract",
            str(fixtures_dir / "mixed-confidence.bin"),
            "--input-type",
            "bytecode",
            "--check",
            "all",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    suicidal = [f for f in report["findings"] if f["category"] == "suicidal"]
    assert suicidal and all(f["severity"] == "critical" for f in suicidal)


def test_cli_flag_overrides_config_severity_override(fixtures_dir, tmp_path):
    """An explicit --severity-override on the CLI beats the config-file value."""
    cfg = tmp_path / "omen.toml"
    cfg.write_text('[omen]\nseverity_override = "suicidal=low"\n')

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "omen.cli",
            "--config",
            str(cfg),
            "--contract",
            str(fixtures_dir / "mixed-confidence.bin"),
            "--input-type",
            "bytecode",
            "--check",
            "all",
            "--severity-override",
            "suicidal=critical",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    suicidal = [f for f in report["findings"] if f["category"] == "suicidal"]
    assert suicidal and all(f["severity"] == "critical" for f in suicidal)
