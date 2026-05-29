"""Tests for --diff report-to-report delta (POST_V01 R3.2).

--diff is the temporal complement to --baseline (R3.1): where --baseline
suppresses already-known findings during a *live* scan, --diff compares two
*already-saved* omen JSON reports and reports the delta — findings added (in
NEW, not OLD), removed (in OLD, not NEW), and the unchanged count. It is a pure
offline operation: no contract, compiler, Slither, or network, so it runs on a
fresh checkout in CI exactly like --list-checks.

A finding's identity for matching is the same stable fingerprint --baseline uses
(category + detector + contract + location), so a --severity-override re-stamp or
a Slither wording change does not show up as churn. --fail-on gates on the
*added* findings only (exit 3), the "fail the PR on a regression" CI move.

These tests cover the pure primitives (loader, diff_findings, gate), the
renderers (text + json), and the CLI/subprocess end-to-end behaviour. No solc or
network is needed anywhere.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from omen.cli import build_parser, main
from omen.diff import (
    build_diff,
    diff_gate_triggered,
    render,
    to_json,
    to_text,
)
from omen.findings import (
    diff_findings,
    finding_fingerprint,
    load_baseline_findings,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fdict(
    category: str = "reentrancy",
    *,
    detector: str = "reentrancy-eth",
    contract: str | None = "A",
    severity: str = "high",
    confidence: str = "high",
    source_mapping: list[str] | None = None,
    opcodes: list[dict] | None = None,
) -> dict:
    """Build a report-shaped finding dict (the to_dict() form)."""
    return {
        "category": category,
        "severity": severity,
        "title": "t",
        "description": "d",
        "detector": detector,
        "contract": contract,
        "confidence": confidence,
        "evidence": {
            "source_mapping": source_mapping if source_mapping is not None else ["A.sol#10-12"],
            "opcodes": opcodes or [],
        },
    }


def _report(*findings: dict) -> dict:
    return {"version": "0.1.0", "findings": list(findings)}


def _write(tmp_path: Path, name: str, obj) -> str:
    p = tmp_path / name
    p.write_text(json.dumps(obj), encoding="utf-8")
    return str(p)


# ---------------------------------------------------------------------------
# load_baseline_findings — fingerprint-keyed full-finding loader
# ---------------------------------------------------------------------------


def test_load_findings_keys_by_fingerprint_keeps_full_dict(tmp_path):
    f = _fdict(category="suicidal", detector="suicidal")
    path = _write(tmp_path, "r.json", _report(f))
    loaded = load_baseline_findings(path)
    assert list(loaded.keys()) == [finding_fingerprint(f)]
    # The full dict is preserved (not just identity), so --diff can show details.
    assert loaded[finding_fingerprint(f)]["title"] == "t"
    assert loaded[finding_fingerprint(f)]["category"] == "suicidal"


def test_load_findings_reads_jsonl_batch_stream(tmp_path):
    f1 = _fdict(category="reentrancy", contract="A")
    f2 = _fdict(category="suicidal", detector="suicidal", contract="B",
                source_mapping=["B.sol#1"])
    p = tmp_path / "batch.jsonl"
    p.write_text(
        json.dumps(_report(f1)) + "\n" + json.dumps(_report(f2)) + "\n",
        encoding="utf-8",
    )
    loaded = load_baseline_findings(str(p))
    assert set(loaded) == {finding_fingerprint(f1), finding_fingerprint(f2)}


def test_load_findings_reads_json_array_of_reports(tmp_path):
    f1 = _fdict(category="reentrancy")
    f2 = _fdict(category="suicidal", detector="suicidal", source_mapping=["A.sol#9"])
    path = _write(tmp_path, "arr.json", [_report(f1), _report(f2)])
    loaded = load_baseline_findings(path)
    assert set(loaded) == {finding_fingerprint(f1), finding_fingerprint(f2)}


def test_load_findings_empty_findings_is_valid_empty_map(tmp_path):
    path = _write(tmp_path, "clean.json", _report())
    assert load_baseline_findings(path) == {}


def test_load_findings_empty_file_is_empty_map(tmp_path):
    p = tmp_path / "blank.json"
    p.write_text("", encoding="utf-8")
    assert load_baseline_findings(str(p)) == {}


def test_load_findings_skips_non_dict_entries(tmp_path):
    p = tmp_path / "junk.json"
    p.write_text(json.dumps({"findings": ["not-a-dict", _fdict()]}), encoding="utf-8")
    loaded = load_baseline_findings(str(p))
    assert len(loaded) == 1


def test_load_findings_first_wins_on_duplicate_fingerprint(tmp_path):
    a = _fdict()
    b = _fdict()  # same identity, different wording would still collide
    b["title"] = "second"
    path = _write(tmp_path, "dup.json", _report(a, b))
    loaded = load_baseline_findings(path)
    assert len(loaded) == 1
    assert loaded[finding_fingerprint(a)]["title"] == "t"  # first wins


def test_load_findings_missing_file_raises(tmp_path):
    with pytest.raises(ValueError, match="cannot read"):
        load_baseline_findings(str(tmp_path / "nope.json"))


def test_load_findings_non_json_raises(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid JSON"):
        load_baseline_findings(str(p))


# ---------------------------------------------------------------------------
# diff_findings — the pure set-delta primitive
# ---------------------------------------------------------------------------


def test_diff_added_removed_unchanged():
    keep = _fdict(category="reentrancy")
    gone = _fdict(category="suicidal", detector="suicidal", source_mapping=["A.sol#20"])
    new = _fdict(category="access-control", detector="protected-vars",
                 source_mapping=["A.sol#30"])
    old_map = {finding_fingerprint(keep): keep, finding_fingerprint(gone): gone}
    new_map = {finding_fingerprint(keep): keep, finding_fingerprint(new): new}
    delta = diff_findings(old_map, new_map)
    assert [f["category"] for f in delta["added"]] == ["access-control"]
    assert [f["category"] for f in delta["removed"]] == ["suicidal"]
    assert [f["category"] for f in delta["unchanged"]] == ["reentrancy"]


def test_diff_identical_reports_no_changes():
    f = _fdict()
    m = {finding_fingerprint(f): f}
    delta = diff_findings(m, m)
    assert delta["added"] == []
    assert delta["removed"] == []
    assert len(delta["unchanged"]) == 1


def test_diff_is_deterministic_by_fingerprint_order():
    # Two adds in arbitrary insertion order come out sorted by fingerprint, so
    # the diff is stable regardless of how the report listed them.
    a = _fdict(category="reentrancy", source_mapping=["A.sol#1"])
    b = _fdict(category="reentrancy", source_mapping=["A.sol#2"])
    new_map = {finding_fingerprint(b): b, finding_fingerprint(a): a}
    delta = diff_findings({}, new_map)
    fps = [finding_fingerprint(f) for f in delta["added"]]
    assert fps == sorted(fps)


def test_diff_ignores_severity_and_wording_changes():
    # A --severity-override re-stamp or a reworded description must NOT look like
    # churn: same fingerprint => unchanged.
    old = _fdict(severity="high", confidence="high")
    new = _fdict(severity="critical", confidence="low")
    new["description"] = "totally different wording"
    delta = diff_findings(
        {finding_fingerprint(old): old},
        {finding_fingerprint(new): new},
    )
    assert delta["added"] == []
    assert delta["removed"] == []
    assert len(delta["unchanged"]) == 1


# ---------------------------------------------------------------------------
# build_diff + gate
# ---------------------------------------------------------------------------


def test_build_diff_summary_counts(tmp_path):
    keep = _fdict(category="reentrancy")
    gone = _fdict(category="suicidal", detector="suicidal", source_mapping=["A.sol#20"])
    added = _fdict(category="access-control", detector="protected-vars",
                   source_mapping=["A.sol#30"])
    old = _write(tmp_path, "old.json", _report(keep, gone))
    new = _write(tmp_path, "new.json", _report(keep, added))
    diff = build_diff(old, new)
    assert diff["summary"] == {"added": 1, "removed": 1, "unchanged": 1}
    assert diff["old"] == old
    assert diff["new"] == new


def test_gate_trips_on_added_high():
    diff = {"added": [_fdict(severity="high")], "removed": [], "unchanged": []}
    assert diff_gate_triggered(diff, "high") is True
    assert diff_gate_triggered(diff, "critical") is False
    assert diff_gate_triggered(diff, "never") is False
    assert diff_gate_triggered(diff, None) is False


def test_gate_ignores_removed_and_unchanged():
    # A high finding that is only removed or unchanged must NOT trip the gate —
    # only newly-introduced (added) findings are regressions.
    diff = {
        "added": [_fdict(severity="low")],
        "removed": [_fdict(severity="critical")],
        "unchanged": [_fdict(severity="critical")],
    }
    assert diff_gate_triggered(diff, "high") is False


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------


def test_to_text_lists_added_and_removed():
    diff = {
        "version": "0.1.0",
        "old": "o.json",
        "new": "n.json",
        "summary": {"added": 1, "removed": 1, "unchanged": 2},
        "added": [_fdict(category="access-control", severity="high",
                         source_mapping=["A.sol#30"])],
        "removed": [_fdict(category="suicidal", severity="high",
                           source_mapping=["A.sol#20"])],
        "unchanged": [],
    }
    text = to_text(diff)
    assert "+1 added" in text and "-1 removed" in text and "=2 unchanged" in text
    assert "+ HIGH" in text and "access-control" in text and "A.sol#30" in text
    assert "- HIGH" in text and "suicidal" in text and "A.sol#20" in text


def test_to_text_no_changes_message():
    diff = {
        "version": "0.1.0", "old": "o", "new": "n",
        "summary": {"added": 0, "removed": 0, "unchanged": 3},
        "added": [], "removed": [], "unchanged": [],
    }
    assert "No changes between the two reports." in to_text(diff)


def test_to_text_opcode_location_for_bytecode_findings():
    diff = {
        "version": "0.1.0", "old": "o", "new": "n",
        "summary": {"added": 1, "removed": 0, "unchanged": 0},
        "added": [_fdict(category="suicidal", detector="opcode",
                         source_mapping=[], opcodes=[{"offset": 3, "op": "SELFDESTRUCT"}])],
        "removed": [], "unchanged": [],
    }
    assert "@0x3" in to_text(diff)


def test_to_json_roundtrips(tmp_path):
    diff = {
        "version": "0.1.0", "old": "o", "new": "n",
        "summary": {"added": 1, "removed": 0, "unchanged": 0},
        "added": [_fdict()], "removed": [], "unchanged": [],
    }
    parsed = json.loads(to_json(diff))
    assert parsed["summary"]["added"] == 1
    assert parsed["added"][0]["category"] == "reentrancy"


def test_render_dispatches_format():
    diff = {
        "version": "0.1.0", "old": "o", "new": "n",
        "summary": {"added": 0, "removed": 0, "unchanged": 0},
        "added": [], "removed": [], "unchanged": [],
    }
    assert render(diff, "json").startswith("{")
    assert "report diff" in render(diff, "text")
    with pytest.raises(ValueError, match="unknown diff format"):
        render(diff, "sarif")


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------


def test_cli_parses_diff_two_args():
    parser = build_parser()
    args = parser.parse_args(["--diff", "old.json", "new.json"])
    assert args.diff == ["old.json", "new.json"]


def test_cli_diff_default_is_none():
    parser = build_parser()
    args = parser.parse_args(["--list-checks"])
    assert args.diff is None


def test_cli_diff_needs_no_target(tmp_path, capsys):
    # --diff runs offline, with no --contract/--batch/--input-type required.
    old = _write(tmp_path, "old.json", _report(_fdict()))
    new = _write(tmp_path, "new.json", _report(_fdict()))
    rc = main(["--diff", old, new])
    assert rc == 0
    out = capsys.readouterr().out
    assert "report diff" in out
    assert "No changes" in out


def test_cli_diff_json_format(tmp_path, capsys):
    keep = _fdict(category="reentrancy")
    added = _fdict(category="access-control", detector="protected-vars",
                   source_mapping=["A.sol#30"])
    old = _write(tmp_path, "old.json", _report(keep))
    new = _write(tmp_path, "new.json", _report(keep, added))
    rc = main(["--diff", old, new, "--format", "json"])
    assert rc == 0
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["summary"] == {"added": 1, "removed": 0, "unchanged": 1}
    assert parsed["added"][0]["category"] == "access-control"


def test_cli_diff_fail_on_trips_on_added(tmp_path, capsys):
    keep = _fdict(category="reentrancy")
    added = _fdict(category="access-control", detector="protected-vars",
                   severity="high", source_mapping=["A.sol#30"])
    old = _write(tmp_path, "old.json", _report(keep))
    new = _write(tmp_path, "new.json", _report(keep, added))
    rc = main(["--diff", old, new, "--fail-on", "high"])
    assert rc == 3  # CI gate trips on the new high finding


def test_cli_diff_fail_on_does_not_trip_on_removed(tmp_path, capsys):
    # The new report only *removed* a high finding — the gate must not trip.
    gone = _fdict(category="suicidal", detector="suicidal", severity="high",
                  source_mapping=["A.sol#20"])
    old = _write(tmp_path, "old.json", _report(gone))
    new = _write(tmp_path, "new.json", _report())
    rc = main(["--diff", old, new, "--fail-on", "critical"])
    assert rc == 0


def test_cli_diff_missing_file_is_usage_error(tmp_path):
    new = _write(tmp_path, "new.json", _report())
    with pytest.raises(SystemExit) as exc:
        main(["--diff", str(tmp_path / "nope.json"), new])
    assert exc.value.code == 2


def test_cli_diff_bad_format_is_usage_error(tmp_path):
    old = _write(tmp_path, "old.json", _report())
    new = _write(tmp_path, "new.json", _report())
    with pytest.raises(SystemExit) as exc:
        main(["--diff", old, new, "--format", "sarif"])
    assert exc.value.code == 2


def test_cli_diff_output_file(tmp_path):
    keep = _fdict(category="reentrancy")
    added = _fdict(category="access-control", detector="protected-vars",
                   source_mapping=["A.sol#30"])
    old = _write(tmp_path, "old.json", _report(keep))
    new = _write(tmp_path, "new.json", _report(keep, added))
    out = tmp_path / "diff.txt"
    rc = main(["--diff", old, new, "-o", str(out)])
    assert rc == 0
    body = out.read_text(encoding="utf-8")
    assert "report diff" in body
    assert "access-control" in body


# ---------------------------------------------------------------------------
# Subprocess end-to-end
# ---------------------------------------------------------------------------


def test_subprocess_diff_end_to_end(tmp_path):
    keep = _fdict(category="reentrancy")
    added = _fdict(category="access-control", detector="protected-vars",
                   severity="high", source_mapping=["A.sol#30"])
    old = _write(tmp_path, "old.json", _report(keep))
    new = _write(tmp_path, "new.json", _report(keep, added))
    proc = subprocess.run(
        [sys.executable, "-m", "omen.cli", "--diff", old, new,
         "--format", "json", "--fail-on", "high"],
        capture_output=True, text=True,
    )
    assert proc.returncode == 3  # the new high finding trips the gate
    parsed = json.loads(proc.stdout)
    assert parsed["summary"]["added"] == 1
    assert parsed["added"][0]["category"] == "access-control"
