"""Tests for the --limit top-N finding cap (POST_V01 Rotation 2, R2.4).

The Rotation 2 triage pipeline is filter (which findings survive) -> sort
(what order they are read in) -> limit (how many to read). After
``--sort severity`` puts the worst-first, ``--limit N`` is the "just show me
the top N leads" move on a whole-program scan that still emits dozens of
findings after the severity/confidence filters. Unlike the filters, the cap
*does* change which findings appear, so the report records the pre-cap
``total_findings`` and a ``truncated`` flag for honest "N of M shown"
reporting.

These tests use the same synthetic mixed-confidence bytecode fixture as the
sort/severity/confidence tests so they run with no solc dependency::

    CALLVALUE(0x34) CALL(0xf1) SSTORE(0x55) SELFDESTRUCT(0xff)

which yields a suicidal finding (HIGH/high) and a reentrancy finding
(HIGH/low). With the default sort, suicidal leads, so ``--limit 1`` keeps the
higher-impact suicidal lead and drops the reentrancy one. The pure
``parse_limit`` / ``_limit_findings`` tests cover the primitive directly.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from omen.analyzer import AnalysisReport, _limit_findings, analyze
from omen.cli import build_parser
from omen.findings import Evidence, Finding, Severity, parse_limit


# ---------------------------------------------------------------------------
# parse_limit — the validation primitive
# ---------------------------------------------------------------------------


def test_parse_limit_none_is_no_limit():
    assert parse_limit(None) is None


def test_parse_limit_empty_string_is_no_limit():
    assert parse_limit("") is None
    assert parse_limit("   ") is None


def test_parse_limit_accepts_positive_int():
    assert parse_limit(5) == 5


def test_parse_limit_accepts_numeric_string():
    assert parse_limit("3") == 3


def test_parse_limit_rejects_zero():
    with pytest.raises(ValueError):
        parse_limit(0)


def test_parse_limit_rejects_negative():
    with pytest.raises(ValueError):
        parse_limit(-1)


def test_parse_limit_rejects_non_numeric_string():
    with pytest.raises(ValueError):
        parse_limit("ten")


def test_parse_limit_rejects_bool():
    # bool is an int subclass; a True/False slipping in is a bug, not a cap.
    with pytest.raises(ValueError):
        parse_limit(True)


# ---------------------------------------------------------------------------
# _limit_findings — the pure cap step
# ---------------------------------------------------------------------------


def _finding(category: str) -> Finding:
    return Finding(
        category=category,
        severity=Severity.HIGH,
        title=category,
        description="test finding",
        detector="test",
        confidence="high",
        evidence=Evidence(),
    )


def _five() -> list[Finding]:
    return [_finding(c) for c in ("a", "b", "c", "d", "e")]


def test_limit_none_keeps_all():
    findings = _five()
    assert _limit_findings(findings, None) == findings


def test_limit_caps_to_n_from_the_front():
    findings = _five()
    capped = _limit_findings(findings, 2)
    assert [f.category for f in capped] == ["a", "b"]


def test_limit_larger_than_list_keeps_all():
    findings = _five()
    assert _limit_findings(findings, 99) == findings


def test_limit_does_not_mutate_input():
    findings = _five()
    original = list(findings)
    _limit_findings(findings, 2)
    assert findings == original


# ---------------------------------------------------------------------------
# AnalysisReport.to_dict — total_findings / truncated bookkeeping
# ---------------------------------------------------------------------------


def _report(findings, total=None) -> AnalysisReport:
    return AnalysisReport(
        tool="omen",
        version="test",
        input_type="bytecode",
        origin="x.bin",
        checks=["all"],
        findings=findings,
        total_findings=total,
    )


def test_to_dict_total_findings_defaults_to_shown_count():
    d = _report(_five()).to_dict()
    assert d["finding_count"] == 5
    assert d["total_findings"] == 5
    assert d["truncated"] is False


def test_to_dict_reports_truncation():
    # Three shown, five existed before the cap.
    d = _report(_five()[:3], total=5).to_dict()
    assert d["finding_count"] == 3
    assert d["total_findings"] == 5
    assert d["truncated"] is True


# ---------------------------------------------------------------------------
# analyze() integration — bytecode mode, no solc required
# ---------------------------------------------------------------------------


def test_analyze_no_limit_keeps_all_and_not_truncated(fixtures_dir):
    report = analyze(
        contract=str(fixtures_dir / "mixed-confidence.bin"),
        input_type="bytecode",
        check="all",
    )
    d = report.to_dict()
    assert d["finding_count"] == d["total_findings"]
    assert d["truncated"] is False
    assert d["finding_count"] >= 2  # at least suicidal + reentrancy


def test_analyze_limit_keeps_top_lead_after_sort(fixtures_dir):
    # Default sort is severity-then-confidence, so suicidal (HIGH/high) leads
    # reentrancy (HIGH/low). --limit 1 keeps the higher-impact suicidal lead.
    report = analyze(
        contract=str(fixtures_dir / "mixed-confidence.bin"),
        input_type="bytecode",
        check="all",
        limit=1,
    )
    assert [f.category for f in report.findings] == ["suicidal"]
    d = report.to_dict()
    assert d["finding_count"] == 1
    assert d["total_findings"] >= 2
    assert d["truncated"] is True


def test_analyze_limit_runs_after_sort_none(fixtures_dir):
    # With sort=none the cap takes the first finding in raw detector order.
    # _analyze_bytecode emits suicidal before reentrancy, so the cap still
    # keeps suicidal here, but the point is the cap is applied to whatever
    # order sort produced (not re-sorted).
    report = analyze(
        contract=str(fixtures_dir / "mixed-confidence.bin"),
        input_type="bytecode",
        check="all",
        sort="none",
        limit=1,
    )
    assert len(report.findings) == 1


def test_analyze_limit_accepts_string(fixtures_dir):
    report = analyze(
        contract=str(fixtures_dir / "mixed-confidence.bin"),
        input_type="bytecode",
        check="all",
        limit="1",
    )
    assert len(report.findings) == 1


def test_analyze_limit_composes_with_filters(fixtures_dir):
    # min_confidence=high drops the low-confidence reentrancy lead, leaving
    # only suicidal; a generous limit then changes nothing and is not flagged
    # as truncation.
    report = analyze(
        contract=str(fixtures_dir / "mixed-confidence.bin"),
        input_type="bytecode",
        check="all",
        min_confidence="high",
        limit=10,
    )
    d = report.to_dict()
    assert {f.category for f in report.findings} == {"suicidal"}
    assert d["truncated"] is False


def test_analyze_rejects_zero_limit(fixtures_dir):
    with pytest.raises(ValueError):
        analyze(
            contract=str(fixtures_dir / "mixed-confidence.bin"),
            input_type="bytecode",
            check="all",
            limit=0,
        )


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def test_help_lists_limit():
    text = build_parser().format_help()
    assert "--limit" in text


def test_cli_default_limit_is_none():
    args = build_parser().parse_args(
        ["--contract", "x.bin", "--input-type", "bytecode"]
    )
    assert args.limit is None


def test_cli_parses_positive_limit():
    args = build_parser().parse_args(
        ["--contract", "x.bin", "--input-type", "bytecode", "--limit", "3"]
    )
    assert args.limit == 3


def test_cli_rejects_zero_limit():
    with pytest.raises(SystemExit):
        build_parser().parse_args(
            ["--contract", "x.bin", "--input-type", "bytecode", "--limit", "0"]
        )


def test_cli_rejects_negative_limit():
    with pytest.raises(SystemExit):
        build_parser().parse_args(
            ["--contract", "x.bin", "--input-type", "bytecode", "--limit", "-2"]
        )


def test_cli_rejects_non_numeric_limit():
    with pytest.raises(SystemExit):
        build_parser().parse_args(
            ["--contract", "x.bin", "--input-type", "bytecode", "--limit", "lots"]
        )


# ---------------------------------------------------------------------------
# batch forwarding
# ---------------------------------------------------------------------------


def test_batch_forwards_limit(fixtures_dir, tmp_path, capsys):
    """run_batch applies --limit per-contract across the batch (JSONL)."""
    from omen.batch import run_batch

    list_file = tmp_path / "targets.txt"
    bin_path = str(fixtures_dir / "mixed-confidence.bin")
    list_file.write_text(f"{bin_path}\n{bin_path}\n")

    exit_code = run_batch(
        path=str(list_file),
        input_type="bytecode",
        check="all",
        limit=1,
    )
    assert exit_code == 0

    captured = capsys.readouterr()
    lines = [ln for ln in captured.out.splitlines() if ln.strip()]
    assert len(lines) == 2
    for line in lines:
        report = json.loads(line)
        # Each per-item report is capped to one finding (the top lead).
        assert report["finding_count"] == 1
        assert report["total_findings"] >= 2
        assert report["truncated"] is True
        assert report["findings"][0]["category"] == "suicidal"


# ---------------------------------------------------------------------------
# h1md formatter surfaces truncation honestly
# ---------------------------------------------------------------------------


def test_h1md_shows_top_n_of_m_when_truncated(fixtures_dir):
    from omen.formats import render

    report = analyze(
        contract=str(fixtures_dir / "mixed-confidence.bin"),
        input_type="bytecode",
        check="all",
        limit=1,
    )
    md = render(report, "h1md")
    assert "1 of" in md
    assert "--limit" in md


def test_h1md_plain_count_when_not_truncated(fixtures_dir):
    from omen.formats import render

    report = analyze(
        contract=str(fixtures_dir / "mixed-confidence.bin"),
        input_type="bytecode",
        check="all",
    )
    md = render(report, "h1md")
    assert "of " not in md.split("**Findings:**")[1].splitlines()[0]


# ---------------------------------------------------------------------------
# end-to-end subprocess
# ---------------------------------------------------------------------------


def test_cli_limit_end_to_end(fixtures_dir):
    """A real subprocess run honours --limit (no solc needed)."""
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
            "--limit",
            "1",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    assert report["finding_count"] == 1
    assert report["total_findings"] >= 2
    assert report["truncated"] is True
    assert report["findings"][0]["category"] == "suicidal"
