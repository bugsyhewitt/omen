"""Tests for the --batch-summary aggregate roll-up (POST_V01 Rotation 2, R2.12).

Every prior Rotation 2 lever (--sort, --limit, --fail-on, --ignore) operates
*per contract*; none gives an aggregate read across a whole-program --batch
scan. --batch-summary closes that gap: after the JSONL stream it prints a
roll-up to **stderr** (so the stdout JSONL stays machine-clean for jq) with the
contract/error/finding totals, a worst-first per-severity total line, and the
worst-affected contracts.

Covered:
- summarize_batch primitive: counts, severity roll-up (worst-first, only-present),
  with-findings tally, total_findings (pre-limit) preference, worst-affected
  ordering + cap, gate line, error count, empty batch, singular/plural noun.
- run_batch integration: summary emitted to stderr (not stdout), off by default,
  stdout JSONL unchanged when on, composes with --output-file, error count
  reflected, no retained reports when off.
- CLI surface: --batch-summary in help, store_true default False, parses.
- config: batch-summary accepted as a bool key, non-bool rejected.
- subprocess end-to-end: real bytecode batch with --batch-summary writes the
  roll-up to stderr and leaves stdout as pure JSONL.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from omen.batch import run_batch, summarize_batch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _report_dict(
    origin: str,
    findings: list[dict] | None = None,
    *,
    total_findings: int | None = None,
    gate_triggered: bool = False,
) -> dict:
    """Build a per-contract report dict shaped like AnalysisReport.to_dict()."""
    findings = findings or []
    shown = len(findings)
    total = total_findings if total_findings is not None else shown
    return {
        "tool": "omen",
        "version": "0.1.0",
        "input_type": "sol",
        "origin": origin,
        "checks": ["all"],
        "finding_count": shown,
        "total_findings": total,
        "truncated": total > shown,
        "gate_triggered": gate_triggered,
        "findings": findings,
    }


def _finding(severity: str) -> dict:
    return {
        "category": "suicidal",
        "severity": severity,
        "title": "x",
        "description": "y",
        "detector": "slither:suicidal",
        "contract": None,
        "confidence": "high",
        "evidence": {"source_mapping": [], "opcodes": []},
    }


def _make_mock_report(origin: str, findings: list[dict], gate: bool = False) -> MagicMock:
    rep = MagicMock()
    rep.gate_triggered = gate
    rep.to_dict.return_value = _report_dict(origin, findings, gate_triggered=gate)
    return rep


# ---------------------------------------------------------------------------
# summarize_batch — the pure aggregation primitive
# ---------------------------------------------------------------------------


def test_summary_header_counts() -> None:
    reports = [
        _report_dict("a.sol", [_finding("high")]),
        _report_dict("b.sol", []),
        _report_dict("c.sol", [_finding("low"), _finding("medium")]),
    ]
    out = summarize_batch(reports, errors=1)
    assert "omen batch summary" in out
    # 3 scanned, 2 with findings (a + c), 1 errored
    assert "3 scanned, 2 with findings, 1 errored" in out


def test_summary_severity_rollup_worst_first() -> None:
    reports = [
        _report_dict("a.sol", [_finding("medium"), _finding("high")]),
        _report_dict("b.sol", [_finding("high"), _finding("critical")]),
    ]
    out = summarize_batch(reports, errors=0)
    # 4 total: 1 critical, 2 high, 1 medium — worst-first.
    assert "findings: 4 total" in out
    line = next(ln for ln in out.splitlines() if ln.startswith("findings:"))
    assert "1 critical, 2 high, 1 medium" in line


def test_summary_only_present_severities() -> None:
    reports = [_report_dict("a.sol", [_finding("low")])]
    out = summarize_batch(reports, errors=0)
    line = next(ln for ln in out.splitlines() if ln.startswith("findings:"))
    # No 'critical'/'high'/'medium'/'informational' words when absent.
    assert "1 low" in line
    assert "high" not in line and "medium" not in line


def test_summary_no_findings_says_none() -> None:
    reports = [_report_dict("a.sol", []), _report_dict("b.sol", [])]
    out = summarize_batch(reports, errors=0)
    assert "findings: 0 total  [none]" in out
    # No "top affected" block when nothing was found.
    assert "top affected" not in out


def test_summary_prefers_total_findings_over_shown() -> None:
    # A --limit cap shows 1 finding but total_findings records 5 pre-cap; the
    # roll-up must reflect the true scope total, not the truncated display count.
    reports = [_report_dict("a.sol", [_finding("high")], total_findings=5)]
    out = summarize_batch(reports, errors=0)
    assert "findings: 5 total" in out
    assert "1 with findings" in out


def test_summary_top_affected_ordering_and_cap() -> None:
    reports = [
        _report_dict("one.sol", [_finding("low")]),
        _report_dict("six.sol", [_finding("low")] * 6),
        _report_dict("three.sol", [_finding("low")] * 3),
        _report_dict("zero.sol", []),
        _report_dict("two.sol", [_finding("low")] * 2),
        _report_dict("four.sol", [_finding("low")] * 4),
        _report_dict("five.sol", [_finding("low")] * 5),
    ]
    out = summarize_batch(reports, errors=0)
    lines = out.splitlines()
    idx = lines.index("top affected:")
    block = lines[idx + 1 : idx + 6]  # capped at five
    assert len(block) == 5
    # Most findings first: six, five, four, three, two — zero excluded.
    assert "six.sol" in block[0] and "6 findings" in block[0]
    assert "five.sol" in block[1]
    assert "four.sol" in block[2]
    assert "three.sol" in block[3]
    assert "two.sol" in block[4]
    assert "zero.sol" not in out  # contracts with no findings never listed
    assert "one.sol" not in out  # capped out (6th place)


def test_summary_singular_plural_noun() -> None:
    out = summarize_batch([_report_dict("a.sol", [_finding("high")])], errors=0)
    assert "1 finding  a.sol" in out  # singular
    out2 = summarize_batch([_report_dict("b.sol", [_finding("high")] * 2)], errors=0)
    assert "2 findings  b.sol" in out2  # plural


def test_summary_gate_line() -> None:
    reports = [_report_dict("a.sol", [_finding("high")], gate_triggered=True)]
    out = summarize_batch(reports, errors=0)
    assert "--fail-on gate: TRIPPED" in out
    # No gate line when nothing tripped.
    clean = summarize_batch([_report_dict("a.sol", [_finding("high")])], errors=0)
    assert "gate" not in clean


def test_summary_empty_batch() -> None:
    out = summarize_batch([], errors=0)
    assert "0 scanned, 0 with findings, 0 errored" in out
    assert "findings: 0 total  [none]" in out


def test_summary_missing_total_findings_falls_back_to_shown() -> None:
    # Older / mocked dicts may lack total_findings; fall back to len(findings).
    rep = {
        "origin": "legacy.sol",
        "findings": [_finding("high"), _finding("low")],
        "gate_triggered": False,
    }
    out = summarize_batch([rep], errors=0)
    assert "findings: 2 total" in out
    assert "1 with findings" in out


# ---------------------------------------------------------------------------
# run_batch integration
# ---------------------------------------------------------------------------


def test_run_batch_summary_to_stderr_not_stdout(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    (tmp_path / "a.sol").write_text("// a")
    (tmp_path / "b.sol").write_text("// b")
    reports = [
        _make_mock_report("a.sol", [_finding("high")]),
        _make_mock_report("b.sol", []),
    ]
    with patch("omen.batch.analyze", side_effect=reports):
        code = run_batch(str(tmp_path), "sol", "all", batch_summary=True)

    captured = capsys.readouterr()
    # stdout is pure JSONL — two lines, both valid JSON, no summary text.
    out_lines = [ln for ln in captured.out.splitlines() if ln.strip()]
    assert len(out_lines) == 2
    for ln in out_lines:
        json.loads(ln)
    assert "omen batch summary" not in captured.out
    # the roll-up is on stderr
    assert "omen batch summary" in captured.err
    assert "2 scanned, 1 with findings, 0 errored" in captured.err
    assert code == 0


def test_run_batch_no_summary_by_default(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    (tmp_path / "a.sol").write_text("// a")
    with patch("omen.batch.analyze", return_value=_make_mock_report("a.sol", [])):
        run_batch(str(tmp_path), "sol", "all")  # batch_summary defaults False
    captured = capsys.readouterr()
    assert "omen batch summary" not in captured.out
    assert "omen batch summary" not in captured.err


def test_run_batch_summary_reflects_errors(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    (tmp_path / "good.sol").write_text("// good")
    (tmp_path / "bad.sol").write_text("// bad")

    def side_effect(contract, input_type, check, rpc_url, **kwargs):
        if "bad" in contract:
            raise RuntimeError("boom")
        return _make_mock_report("good.sol", [_finding("medium")])

    with patch("omen.batch.analyze", side_effect=side_effect):
        code = run_batch(str(tmp_path), "sol", "all", batch_summary=True)

    captured = capsys.readouterr()
    assert "1 scanned, 1 with findings, 1 errored" in captured.err
    assert code == 1  # error still wins the exit code


def test_run_batch_summary_composes_with_output_file(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    (tmp_path / "a.sol").write_text("// a")
    out_file = tmp_path / "scan.jsonl"
    with patch(
        "omen.batch.analyze", return_value=_make_mock_report("a.sol", [_finding("high")])
    ):
        run_batch(
            str(tmp_path),
            "sol",
            "all",
            output_file=str(out_file),
            batch_summary=True,
        )
    captured = capsys.readouterr()
    # JSONL went to the file; nothing on stdout; summary on stderr.
    assert out_file.exists()
    json.loads(out_file.read_text().strip())
    assert captured.out.strip() == ""
    assert "omen batch summary" in captured.err


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def test_cli_help_includes_batch_summary() -> None:
    from omen.cli import build_parser

    text = build_parser().format_help()
    assert "--batch-summary" in text


def test_cli_batch_summary_default_false() -> None:
    from omen.cli import build_parser

    args = build_parser().parse_args(
        ["--batch", "/tmp", "--input-type", "sol"]
    )
    assert args.batch_summary is False


def test_cli_batch_summary_sets_true() -> None:
    from omen.cli import build_parser

    args = build_parser().parse_args(
        ["--batch", "/tmp", "--input-type", "sol", "--batch-summary"]
    )
    assert args.batch_summary is True


# ---------------------------------------------------------------------------
# config integration
# ---------------------------------------------------------------------------


def test_config_accepts_batch_summary_bool(tmp_path: Path) -> None:
    from omen.config import load_config

    cfg_file = tmp_path / "omen.toml"
    cfg_file.write_text('[omen]\nbatch-summary = true\n')
    cfg = load_config(str(cfg_file))
    assert cfg["batch_summary"] is True


def test_config_rejects_non_bool_batch_summary(tmp_path: Path) -> None:
    from omen.config import ConfigError, load_config

    cfg_file = tmp_path / "omen.toml"
    cfg_file.write_text('[omen]\nbatch-summary = "yes"\n')
    with pytest.raises(ConfigError, match="batch_summary must be a boolean"):
        load_config(str(cfg_file))


def test_config_rejects_int_batch_summary(tmp_path: Path) -> None:
    from omen.config import ConfigError, load_config

    cfg_file = tmp_path / "omen.toml"
    cfg_file.write_text('[omen]\nbatch-summary = 1\n')
    with pytest.raises(ConfigError, match="batch_summary must be a boolean"):
        load_config(str(cfg_file))


# ---------------------------------------------------------------------------
# subprocess end-to-end (bytecode batch, no compiler needed)
# ---------------------------------------------------------------------------


def test_subprocess_batch_summary_end_to_end(tmp_path: Path) -> None:
    """A real --batch run with --batch-summary emits the roll-up to stderr.

    Batch input types are ``sol`` and ``address``; both need either a compiler
    or an RPC, neither of which is guaranteed in CI. The compiler-free assertion
    that still exercises the full CLI → run_batch → summarize_batch wiring is:
    point a sol-dir batch at a file when no solc is installed, which produces
    per-item errors — and the summary must *still* emit (it is the "how did the
    whole scan go" line, which is exactly when an all-errored scan wants it).
    The flag is accepted (not a usage error) and the roll-up lands on stderr,
    while stdout carries only JSONL (here, none, since every item errored).
    """
    sol_dir = tmp_path / "contracts"
    sol_dir.mkdir()
    (sol_dir / "x.sol").write_text("// x")
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "omen.cli",
            "--batch",
            str(sol_dir),
            "--input-type",
            "sol",
            "--check",
            "suicidal",
            "--batch-summary",
        ],
        capture_output=True,
        text=True,
    )
    # 0 if solc happens to be present and the trivial file scanned, 1 if it
    # errored (no solc / compile error). Either way the flag is wired and the
    # summary is on stderr, and stdout is pure JSONL (possibly empty).
    assert proc.returncode in (0, 1)
    assert "omen batch summary" in proc.stderr
    for line in proc.stdout.splitlines():
        if line.strip():
            json.loads(line)  # stdout stays machine-clean
