"""Tests for --sarif-merge multi-run SARIF consolidation (POST_V01 R3.4).

--sarif-merge is the spatial complement to --diff (R3.2): where --diff reports
the *temporal* delta between two saved reports, --sarif-merge *unions* the
findings of N saved reports into one SARIF 2.1.0 document — the single
code-scanning upload a per-module CI matrix or sharded scan needs (GitHub
Advanced Security takes one document per upload). It is a pure offline action:
no contract, compiler, Slither, or network, so it runs on a fresh checkout in
CI exactly like --list-checks / --diff.

Findings shared across inputs are deduplicated by the same stable fingerprint
--baseline/--diff/--sarif-baseline use (category + detector + contract +
location), so an overlapping contract is not double-counted, and the output is
worst-first and deterministic regardless of input order. --fail-on gates on the
merged, deduplicated findings (exit 3).

These tests cover the pure primitives (loader/dedup, gate), the SARIF builder
(shape, dedup, ordering, rules), and the CLI/subprocess end-to-end behaviour. No
solc or network is needed anywhere.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from omen.cli import build_parser, main
from omen.findings import finding_fingerprint
from omen.merge import (
    build_merged_sarif,
    load_merge_findings,
    merge_gate_triggered,
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
    title: str = "t",
    description: str = "d",
    source_mapping: list[str] | None = None,
    opcodes: list[dict] | None = None,
) -> dict:
    """Build a report-shaped finding dict (the to_dict() form)."""
    return {
        "category": category,
        "severity": severity,
        "title": title,
        "description": description,
        "detector": detector,
        "contract": contract,
        "confidence": confidence,
        "evidence": {
            "source_mapping": source_mapping
            if source_mapping is not None
            else ["A.sol#10-12"],
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
# load_merge_findings — load + dedup + deterministic order
# ---------------------------------------------------------------------------


def test_load_merge_unions_two_reports(tmp_path):
    a = _fdict(category="reentrancy", source_mapping=["A.sol#1"])
    b = _fdict(category="suicidal", detector="suicidal", source_mapping=["B.sol#2"])
    p1 = _write(tmp_path, "r1.json", _report(a))
    p2 = _write(tmp_path, "r2.json", _report(b))
    merged = load_merge_findings([p1, p2])
    cats = {f["category"] for f in merged}
    assert cats == {"reentrancy", "suicidal"}


def test_load_merge_deduplicates_overlapping_finding(tmp_path):
    # The same finding (same fingerprint) appears in both inputs -> one result.
    shared = _fdict(category="reentrancy", source_mapping=["A.sol#1"])
    other = _fdict(category="suicidal", detector="suicidal", source_mapping=["B.sol#2"])
    p1 = _write(tmp_path, "r1.json", _report(shared, other))
    p2 = _write(tmp_path, "r2.json", _report(shared))
    merged = load_merge_findings([p1, p2])
    assert len(merged) == 2
    fps = [finding_fingerprint(f) for f in merged]
    assert len(fps) == len(set(fps))


def test_load_merge_first_input_wins_on_duplicate(tmp_path):
    # Same fingerprint, different wording across inputs: first input wins.
    first = _fdict(title="first")
    second = _fdict(title="second")  # identical identity
    p1 = _write(tmp_path, "r1.json", _report(first))
    p2 = _write(tmp_path, "r2.json", _report(second))
    merged = load_merge_findings([p1, p2])
    assert len(merged) == 1
    assert merged[0]["title"] == "first"


def test_load_merge_is_worst_first_then_fingerprint(tmp_path):
    low = _fdict(category="overflow", detector="overflow", severity="low",
                 source_mapping=["A.sol#5"])
    crit = _fdict(category="suicidal", detector="suicidal", severity="critical",
                  source_mapping=["A.sol#9"])
    med = _fdict(category="tx-origin", detector="tx-origin", severity="medium",
                 source_mapping=["A.sol#7"])
    # Inputs in a deliberately scrambled order; output must be worst-first.
    p1 = _write(tmp_path, "r1.json", _report(low))
    p2 = _write(tmp_path, "r2.json", _report(crit))
    p3 = _write(tmp_path, "r3.json", _report(med))
    merged = load_merge_findings([p3, p1, p2])
    assert [f["severity"] for f in merged] == ["critical", "medium", "low"]


def test_load_merge_order_independent_of_input_order(tmp_path):
    a = _fdict(category="reentrancy", source_mapping=["A.sol#1"])
    b = _fdict(category="reentrancy", source_mapping=["A.sol#2"])
    p1 = _write(tmp_path, "r1.json", _report(a))
    p2 = _write(tmp_path, "r2.json", _report(b))
    one = [finding_fingerprint(f) for f in load_merge_findings([p1, p2])]
    two = [finding_fingerprint(f) for f in load_merge_findings([p2, p1])]
    assert one == two  # same set, same (severity, fingerprint) ordering


def test_load_merge_reads_jsonl_and_array_inputs(tmp_path):
    f1 = _fdict(category="reentrancy", contract="A")
    f2 = _fdict(category="suicidal", detector="suicidal", contract="B",
                source_mapping=["B.sol#1"])
    jsonl = tmp_path / "batch.jsonl"
    jsonl.write_text(
        json.dumps(_report(f1)) + "\n" + json.dumps(_report(f2)) + "\n",
        encoding="utf-8",
    )
    f3 = _fdict(category="greedy", detector="greedy", source_mapping=["C.sol#3"])
    arr = _write(tmp_path, "arr.json", [_report(f3)])
    merged = load_merge_findings([str(jsonl), arr])
    assert {f["category"] for f in merged} == {"reentrancy", "suicidal", "greedy"}


def test_load_merge_single_input_is_allowed(tmp_path):
    p = _write(tmp_path, "r.json", _report(_fdict()))
    assert len(load_merge_findings([p])) == 1


def test_load_merge_empty_reports_yield_empty(tmp_path):
    p1 = _write(tmp_path, "a.json", _report())
    p2 = _write(tmp_path, "b.json", _report())
    assert load_merge_findings([p1, p2]) == []


def test_load_merge_missing_file_raises(tmp_path):
    ok = _write(tmp_path, "ok.json", _report(_fdict()))
    with pytest.raises(ValueError, match="cannot read"):
        load_merge_findings([ok, str(tmp_path / "nope.json")])


def test_load_merge_non_json_raises(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid JSON"):
        load_merge_findings([str(bad)])


# ---------------------------------------------------------------------------
# build_merged_sarif — document shape, dedup, rules
# ---------------------------------------------------------------------------


def test_build_merged_sarif_is_valid_sarif_shell(tmp_path):
    p = _write(tmp_path, "r.json", _report(_fdict()))
    doc = json.loads(build_merged_sarif([p]))
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-schema-2.1.0.json")
    assert len(doc["runs"]) == 1
    assert doc["runs"][0]["tool"]["driver"]["name"] == "omen"


def test_build_merged_sarif_unions_results(tmp_path):
    a = _fdict(category="reentrancy", source_mapping=["A.sol#1"])
    b = _fdict(category="suicidal", detector="suicidal", source_mapping=["B.sol#2"])
    p1 = _write(tmp_path, "r1.json", _report(a))
    p2 = _write(tmp_path, "r2.json", _report(b))
    doc = json.loads(build_merged_sarif([p1, p2]))
    rule_ids = {r["ruleId"] for r in doc["runs"][0]["results"]}
    assert rule_ids == {"omen/reentrancy", "omen/suicidal"}


def test_build_merged_sarif_deduplicates(tmp_path):
    shared = _fdict(category="reentrancy", source_mapping=["A.sol#1"])
    p1 = _write(tmp_path, "r1.json", _report(shared))
    p2 = _write(tmp_path, "r2.json", _report(shared))
    doc = json.loads(build_merged_sarif([p1, p2]))
    assert len(doc["runs"][0]["results"]) == 1


def test_build_merged_sarif_one_rule_per_category(tmp_path):
    a = _fdict(category="reentrancy", source_mapping=["A.sol#1"])
    b = _fdict(category="reentrancy", source_mapping=["A.sol#2"])  # same category
    p = _write(tmp_path, "r.json", _report(a, b))
    doc = json.loads(build_merged_sarif([p]))
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert rules[0]["id"] == "omen/reentrancy"


def test_build_merged_sarif_maps_severity_to_level_and_score(tmp_path):
    crit = _fdict(category="suicidal", detector="suicidal", severity="critical")
    p = _write(tmp_path, "r.json", _report(crit))
    doc = json.loads(build_merged_sarif([p]))
    result = doc["runs"][0]["results"][0]
    assert result["level"] == "error"  # critical -> error
    assert result["properties"]["severity"] == "critical"
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["properties"]["security-severity"] == "9.5"


def test_build_merged_sarif_source_location_region(tmp_path):
    f = _fdict(category="reentrancy", source_mapping=["Vault.sol#12-18"])
    p = _write(tmp_path, "r.json", _report(f))
    doc = json.loads(build_merged_sarif([p]))
    loc = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "Vault.sol"
    assert loc["region"] == {"startLine": 12, "endLine": 18}


def test_build_merged_sarif_bytecode_finding_has_no_location(tmp_path):
    f = _fdict(category="suicidal", detector="opcode", source_mapping=[],
               opcodes=[{"offset": 3, "op": "SELFDESTRUCT"}])
    p = _write(tmp_path, "r.json", _report(f))
    doc = json.loads(build_merged_sarif([p]))
    result = doc["runs"][0]["results"][0]
    assert "locations" not in result
    assert result["properties"]["opcodes"] == [{"offset": 3, "op": "SELFDESTRUCT"}]


def test_build_merged_sarif_is_deterministic(tmp_path):
    a = _fdict(category="reentrancy", source_mapping=["A.sol#1"])
    b = _fdict(category="suicidal", detector="suicidal", source_mapping=["B.sol#2"])
    p1 = _write(tmp_path, "r1.json", _report(a))
    p2 = _write(tmp_path, "r2.json", _report(b))
    assert build_merged_sarif([p1, p2]) == build_merged_sarif([p2, p1])


# ---------------------------------------------------------------------------
# merge_gate_triggered
# ---------------------------------------------------------------------------


def test_merge_gate_trips_on_high(tmp_path):
    high = _fdict(category="reentrancy", severity="high")
    p = _write(tmp_path, "r.json", _report(high))
    assert merge_gate_triggered([p], "high") is True
    assert merge_gate_triggered([p], "critical") is False
    assert merge_gate_triggered([p], "never") is False
    assert merge_gate_triggered([p], None) is False


def test_merge_gate_counts_deduplicated_set(tmp_path):
    # A finding in both inputs is counted once; the gate still trips on it.
    high = _fdict(category="reentrancy", severity="high")
    p1 = _write(tmp_path, "r1.json", _report(high))
    p2 = _write(tmp_path, "r2.json", _report(high))
    assert merge_gate_triggered([p1, p2], "high") is True


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------


def test_cli_parses_sarif_merge_multi_args():
    parser = build_parser()
    args = parser.parse_args(["--sarif-merge", "a.json", "b.json", "c.json"])
    assert args.sarif_merge == ["a.json", "b.json", "c.json"]


def test_cli_sarif_merge_default_is_none():
    parser = build_parser()
    args = parser.parse_args(["--list-checks"])
    assert args.sarif_merge is None


def test_cli_sarif_merge_needs_no_target(tmp_path, capsys):
    p1 = _write(tmp_path, "r1.json", _report(_fdict(category="reentrancy")))
    p2 = _write(tmp_path, "r2.json",
                _report(_fdict(category="suicidal", detector="suicidal",
                               source_mapping=["B.sol#2"])))
    rc = main(["--sarif-merge", p1, p2])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["version"] == "2.1.0"
    assert len(doc["runs"][0]["results"]) == 2


def test_cli_sarif_merge_rejects_explicit_format(tmp_path):
    p = _write(tmp_path, "r.json", _report(_fdict()))
    with pytest.raises(SystemExit) as exc:
        main(["--sarif-merge", p, "--format", "json"])
    assert exc.value.code == 2


def test_cli_sarif_merge_accepts_explicit_sarif_format(tmp_path, capsys):
    # --format sarif is redundant but harmless; it must not error.
    p = _write(tmp_path, "r.json", _report(_fdict()))
    rc = main(["--sarif-merge", p, "--format", "sarif"])
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["version"] == "2.1.0"


def test_cli_sarif_merge_fail_on_trips(tmp_path):
    high = _fdict(category="reentrancy", severity="high")
    p = _write(tmp_path, "r.json", _report(high))
    rc = main(["--sarif-merge", p, "--fail-on", "high"])
    assert rc == 3


def test_cli_sarif_merge_fail_on_does_not_trip_below_threshold(tmp_path):
    low = _fdict(category="overflow", detector="overflow", severity="low")
    p = _write(tmp_path, "r.json", _report(low))
    rc = main(["--sarif-merge", p, "--fail-on", "high"])
    assert rc == 0


def test_cli_sarif_merge_missing_file_is_usage_error(tmp_path):
    ok = _write(tmp_path, "ok.json", _report())
    with pytest.raises(SystemExit) as exc:
        main(["--sarif-merge", ok, str(tmp_path / "nope.json")])
    assert exc.value.code == 2


def test_cli_sarif_merge_output_file(tmp_path):
    p1 = _write(tmp_path, "r1.json", _report(_fdict(category="reentrancy")))
    p2 = _write(tmp_path, "r2.json",
                _report(_fdict(category="suicidal", detector="suicidal",
                               source_mapping=["B.sol#2"])))
    out = tmp_path / "merged.sarif"
    rc = main(["--sarif-merge", p1, p2, "-o", str(out)])
    assert rc == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert len(doc["runs"][0]["results"]) == 2


# ---------------------------------------------------------------------------
# Subprocess end-to-end
# ---------------------------------------------------------------------------


def test_subprocess_sarif_merge_end_to_end(tmp_path):
    shared = _fdict(category="reentrancy", severity="high", source_mapping=["A.sol#1"])
    extra = _fdict(category="suicidal", detector="suicidal", severity="critical",
                   source_mapping=["B.sol#2"])
    p1 = _write(tmp_path, "r1.json", _report(shared))
    p2 = _write(tmp_path, "r2.json", _report(shared, extra))
    proc = subprocess.run(
        [sys.executable, "-m", "omen.cli", "--sarif-merge", p1, p2,
         "--fail-on", "critical"],
        capture_output=True, text=True,
    )
    assert proc.returncode == 3  # the critical finding trips the gate
    doc = json.loads(proc.stdout)
    # shared appears in both inputs but is deduplicated -> 2 results, not 3.
    assert len(doc["runs"][0]["results"]) == 2
    # worst-first: critical leads.
    assert doc["runs"][0]["results"][0]["properties"]["severity"] == "critical"
