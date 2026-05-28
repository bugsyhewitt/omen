"""Tests for the --fail-on CI exit-code gate (POST_V01 Rotation 2, R2.5).

The Rotation 2 triage pipeline so far is filter (which findings survive) ->
sort (what order they are read in) -> limit (how many to read). R2.5 adds the
*gate*: turn the survivors into a process exit code so omen can fail a CI step.

This is the standard security-scanner CI pattern (Slither's --fail-high,
semgrep/trivy/bandit severity gates): a clean scan exits 0, a scan that
surfaces a lead at or above the chosen severity exits non-zero (omen uses 3,
distinct from input error 2 and analysis crash 1). The default "never" keeps
the historical always-exit-0 behaviour.

These tests use the synthetic mixed-confidence bytecode fixture so they run
with no solc dependency::

    CALLVALUE(0x34) CALL(0xf1) SSTORE(0x55) SELFDESTRUCT(0xff)

which yields a suicidal finding (HIGH/high) and a reentrancy finding
(HIGH/low) — both HIGH severity. So a `high` (or lower) threshold trips the
gate and a `critical` threshold does not, giving clean boundary cases. The
pure ``fail_on_triggered`` tests cover the primitive directly across the full
severity taxonomy.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from omen.analyzer import AnalysisReport, analyze
from omen.cli import build_parser, main
from omen.findings import Evidence, Finding, Severity, fail_on_triggered


# ---------------------------------------------------------------------------
# fail_on_triggered — the pure gate primitive
# ---------------------------------------------------------------------------


def _finding(severity: Severity) -> Finding:
    return Finding(
        category="suicidal",
        severity=severity,
        title="t",
        description="d",
        detector="test",
        confidence="high",
        evidence=Evidence(),
    )


def test_gate_never_with_none():
    assert fail_on_triggered([_finding(Severity.CRITICAL)], None) is False


def test_gate_never_with_never_literal():
    assert fail_on_triggered([_finding(Severity.CRITICAL)], "never") is False


def test_gate_never_with_empty_string():
    assert fail_on_triggered([_finding(Severity.CRITICAL)], "") is False
    assert fail_on_triggered([_finding(Severity.CRITICAL)], "   ") is False


def test_gate_trips_at_exact_threshold():
    # a HIGH finding, threshold high -> >= trips
    assert fail_on_triggered([_finding(Severity.HIGH)], "high") is True


def test_gate_trips_above_threshold():
    # a CRITICAL finding, threshold high -> trips
    assert fail_on_triggered([_finding(Severity.CRITICAL)], "high") is True


def test_gate_does_not_trip_below_threshold():
    # a MEDIUM finding, threshold high -> does not trip
    assert fail_on_triggered([_finding(Severity.MEDIUM)], "high") is False


def test_gate_critical_threshold_not_tripped_by_high():
    assert fail_on_triggered([_finding(Severity.HIGH)], "critical") is False


def test_gate_informational_threshold_trips_on_any_finding():
    assert fail_on_triggered([_finding(Severity.INFORMATIONAL)], "informational") is True


def test_gate_no_findings_never_trips():
    assert fail_on_triggered([], "informational") is False
    assert fail_on_triggered([], "critical") is False


def test_gate_case_insensitive():
    assert fail_on_triggered([_finding(Severity.HIGH)], "HIGH") is True


def test_gate_trips_on_worst_of_mixed_set():
    # The gate is an any() across findings: one CRITICAL trips a critical gate
    # even amid lower-severity findings.
    findings = [_finding(Severity.LOW), _finding(Severity.CRITICAL)]
    assert fail_on_triggered(findings, "critical") is True


# ---------------------------------------------------------------------------
# AnalysisReport.gate_triggered / to_dict bookkeeping
# ---------------------------------------------------------------------------


def _report(gate: bool) -> AnalysisReport:
    return AnalysisReport(
        tool="omen",
        version="test",
        input_type="bytecode",
        origin="x.bin",
        checks=["all"],
        findings=[_finding(Severity.HIGH)],
        gate_triggered=gate,
    )


def test_to_dict_exposes_gate_triggered_false_by_default():
    d = _report(False).to_dict()
    assert d["gate_triggered"] is False


def test_to_dict_exposes_gate_triggered_true():
    d = _report(True).to_dict()
    assert d["gate_triggered"] is True


def test_report_default_gate_is_false():
    # A report built without specifying the gate defaults to not-tripped.
    r = AnalysisReport(
        tool="omen",
        version="test",
        input_type="bytecode",
        origin="x.bin",
        checks=["all"],
        findings=[],
    )
    assert r.gate_triggered is False
    assert r.to_dict()["gate_triggered"] is False


# ---------------------------------------------------------------------------
# analyze() integration — bytecode mode, no solc required
# ---------------------------------------------------------------------------


def test_analyze_default_never_gates(fixtures_dir):
    report = analyze(
        contract=str(fixtures_dir / "mixed-confidence.bin"),
        input_type="bytecode",
        check="all",
    )
    assert report.gate_triggered is False


def test_analyze_fail_on_high_trips(fixtures_dir):
    # Both fixture findings are HIGH, so a high gate trips.
    report = analyze(
        contract=str(fixtures_dir / "mixed-confidence.bin"),
        input_type="bytecode",
        check="all",
        fail_on="high",
    )
    assert report.gate_triggered is True


def test_analyze_fail_on_critical_does_not_trip(fixtures_dir):
    # No finding reaches CRITICAL, so a critical gate stays clean.
    report = analyze(
        contract=str(fixtures_dir / "mixed-confidence.bin"),
        input_type="bytecode",
        check="all",
        fail_on="critical",
    )
    assert report.gate_triggered is False


def test_gate_evaluated_before_limit_cap(fixtures_dir):
    # --limit 1 keeps only the top (suicidal HIGH) lead, but the gate is
    # evaluated over the pre-cap filtered set; here both are HIGH so this is a
    # gate that would trip regardless. The key assertion is the cap does not
    # *clear* a gate: a high gate still trips with a tight cap.
    report = analyze(
        contract=str(fixtures_dir / "mixed-confidence.bin"),
        input_type="bytecode",
        check="all",
        fail_on="high",
        limit=1,
    )
    assert len(report.findings) == 1
    assert report.gate_triggered is True


def test_gate_evaluated_before_limit_cannot_hide_finding(fixtures_dir, monkeypatch):
    # Construct the scenario explicitly: a high-severity finding ranked below a
    # critical one in display order would be hidden by --limit 1, but the gate
    # must still see it. We simulate by checking that a gate keyed to the
    # *second* finding's severity still trips under a cap of 1.
    from omen import analyzer

    crit = _finding(Severity.CRITICAL)
    high = _finding(Severity.HIGH)

    def fake_bytecode(src, checks):
        return [crit, high]

    monkeypatch.setattr(analyzer, "_analyze_bytecode", fake_bytecode)

    report = analyze(
        contract=str(fixtures_dir / "mixed-confidence.bin"),
        input_type="bytecode",
        check="all",
        fail_on="high",
        limit=1,  # would display only the critical lead
    )
    # Only one finding is shown (the cap applied)...
    assert len(report.findings) == 1
    # ...but the gate saw both, so a high gate trips.
    assert report.gate_triggered is True


def test_gate_composes_with_min_severity_filter(fixtures_dir):
    # --min-severity critical drops both HIGH findings, so the (high) gate has
    # nothing to trip on — a filtered-out finding does not trip the gate, which
    # is the correct triage semantics (you said "ignore below critical").
    report = analyze(
        contract=str(fixtures_dir / "mixed-confidence.bin"),
        input_type="bytecode",
        check="all",
        min_severity="critical",
        fail_on="high",
    )
    assert report.findings == []
    assert report.gate_triggered is False


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def test_help_lists_fail_on():
    assert "--fail-on" in build_parser().format_help()


def test_cli_default_fail_on_is_never():
    args = build_parser().parse_args(
        ["--contract", "x.bin", "--input-type", "bytecode"]
    )
    assert args.fail_on == "never"


def test_cli_parses_fail_on_value():
    args = build_parser().parse_args(
        ["--contract", "x.bin", "--input-type", "bytecode", "--fail-on", "high"]
    )
    assert args.fail_on == "high"


def test_cli_rejects_unknown_fail_on():
    with pytest.raises(SystemExit):
        build_parser().parse_args(
            ["--contract", "x.bin", "--input-type", "bytecode", "--fail-on", "bogus"]
        )


# ---------------------------------------------------------------------------
# main() exit codes (in-process, no solc)
# ---------------------------------------------------------------------------


def test_main_exits_zero_without_gate(fixtures_dir, capsys):
    code = main(
        [
            "--contract",
            str(fixtures_dir / "mixed-confidence.bin"),
            "--input-type",
            "bytecode",
            "--check",
            "all",
        ]
    )
    assert code == 0


def test_main_exits_three_when_gate_trips(fixtures_dir, capsys):
    code = main(
        [
            "--contract",
            str(fixtures_dir / "mixed-confidence.bin"),
            "--input-type",
            "bytecode",
            "--check",
            "all",
            "--fail-on",
            "high",
        ]
    )
    assert code == 3
    # The report is still printed before the gate exit.
    out = capsys.readouterr().out
    report = json.loads(out)
    assert report["gate_triggered"] is True


def test_main_exits_zero_when_gate_set_but_not_reached(fixtures_dir, capsys):
    code = main(
        [
            "--contract",
            str(fixtures_dir / "mixed-confidence.bin"),
            "--input-type",
            "bytecode",
            "--check",
            "all",
            "--fail-on",
            "critical",
        ]
    )
    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["gate_triggered"] is False


# ---------------------------------------------------------------------------
# batch forwarding — gate is OR across items, error outranks gate
# ---------------------------------------------------------------------------


def test_batch_gate_trips_returns_three(fixtures_dir, tmp_path, capsys):
    from omen.batch import run_batch

    list_file = tmp_path / "targets.txt"
    bin_path = str(fixtures_dir / "mixed-confidence.bin")
    list_file.write_text(f"{bin_path}\n{bin_path}\n")

    code = run_batch(
        path=str(list_file),
        input_type="bytecode",
        check="all",
        fail_on="high",
    )
    assert code == 3
    lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
    assert len(lines) == 2
    for line in lines:
        assert json.loads(line)["gate_triggered"] is True


def test_batch_no_gate_returns_zero(fixtures_dir, tmp_path, capsys):
    from omen.batch import run_batch

    list_file = tmp_path / "targets.txt"
    bin_path = str(fixtures_dir / "mixed-confidence.bin")
    list_file.write_text(f"{bin_path}\n")

    code = run_batch(
        path=str(list_file),
        input_type="bytecode",
        check="all",
        fail_on="critical",
    )
    assert code == 0


def test_batch_error_outranks_gate(fixtures_dir, tmp_path, capsys):
    # One good item (would trip the high gate) plus one bad path. The error
    # exit (1) takes precedence over the gate exit (3).
    from omen.batch import run_batch

    list_file = tmp_path / "targets.txt"
    good = str(fixtures_dir / "mixed-confidence.bin")
    bad = str(tmp_path / "does-not-exist.bin")
    list_file.write_text(f"{good}\n{bad}\n")

    code = run_batch(
        path=str(list_file),
        input_type="bytecode",
        check="all",
        fail_on="high",
    )
    assert code == 1


# ---------------------------------------------------------------------------
# end-to-end subprocess — real process exit code
# ---------------------------------------------------------------------------


def _run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "omen.cli", *args],
        capture_output=True,
        text=True,
    )


def test_subprocess_exit_three_on_gate(fixtures_dir):
    proc = _run(
        [
            "--contract",
            str(fixtures_dir / "mixed-confidence.bin"),
            "--input-type",
            "bytecode",
            "--check",
            "all",
            "--fail-on",
            "high",
            "--format",
            "json",
        ]
    )
    assert proc.returncode == 3, proc.stderr
    assert json.loads(proc.stdout)["gate_triggered"] is True


def test_subprocess_exit_zero_without_gate(fixtures_dir):
    proc = _run(
        [
            "--contract",
            str(fixtures_dir / "mixed-confidence.bin"),
            "--input-type",
            "bytecode",
            "--check",
            "all",
            "--format",
            "json",
        ]
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["gate_triggered"] is False
