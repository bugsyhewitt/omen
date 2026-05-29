"""Tests for --sarif-baseline SARIF-native suppression (POST_V01 R3.3).

--baseline (R3.1) *drops* known findings from the report entirely. The
SARIF-native, GitHub-code-scanning equivalent is *not* to drop them but to keep
every result and tag each with a ``baselineState`` of ``"new"`` or
``"unchanged"``: GitHub Advanced Security reads that field to fold the
pre-existing ("unchanged") alerts into its baseline view while surfacing the
"new" ones. --sarif-baseline is that lever.

The annotation reuses the exact R3.1 fingerprint identity
(category + detector + contract + location, excluding severity and wording), so
a --severity-override re-stamp or a Slither wording change never flips a known
finding from "unchanged" to "new". --sarif-baseline only applies to
``--format sarif`` in single --contract mode (batch emits JSONL, never a SARIF
document); other formats / --batch are usage errors.

The end-to-end CLI tests use the synthetic mixed-confidence bytecode fixture
(no solc needed):

    CALLVALUE(0x34) CALL(0xf1) SSTORE(0x55) SELFDESTRUCT(0xff)

which yields a HIGH-confidence suicidal finding (opcode @0x3) and a
LOW-confidence reentrancy finding (opcode @0x2).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from omen.analyzer import AnalysisReport, analyze
from omen.cli import build_parser, main
from omen.findings import Evidence, Finding, Severity, finding_fingerprint
from omen.formats import render, to_sarif

FIXTURE = "mixed-confidence.bin"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(
    category: str = "suicidal",
    *,
    detector: str = "omen:bytecode-selfdestruct",
    contract: str | None = "0xabc",
    severity: Severity = Severity.HIGH,
    opcodes: list | None = None,
) -> Finding:
    return Finding(
        category=category,
        severity=severity,
        title=f"{category} finding",
        description=f"{category} detected",
        detector=detector,
        contract=contract,
        confidence="high",
        evidence=Evidence(
            opcodes=opcodes if opcodes is not None else [{"opcode": "SELFDESTRUCT", "offset": 16}]
        ),
    )


def _report(findings: list[Finding]) -> AnalysisReport:
    return AnalysisReport(
        tool="omen",
        version="0.1.0",
        input_type="bytecode",
        origin="x.bin",
        checks=["all"],
        findings=findings,
    )


def _sarif_baseline_file(tmp_path: Path, doc: dict, name: str = "baseline.json") -> str:
    p = tmp_path / name
    p.write_text(json.dumps(doc), encoding="utf-8")
    return str(p)


# ---------------------------------------------------------------------------
# Formatter-level: baselineState annotation
# ---------------------------------------------------------------------------


def test_no_baseline_omits_baseline_state():
    """Without a baseline, the SARIF output is unchanged — no baselineState."""
    f = _finding()
    data = json.loads(to_sarif(_report([f])))
    result = data["runs"][0]["results"][0]
    assert "baselineState" not in result


def test_empty_baseline_marks_every_result_new():
    """An empty baseline (a clean prior scan) means every finding is new — but
    the results are still emitted (suppression is GitHub's job, not omen's)."""
    f = _finding()
    data = json.loads(to_sarif(_report([f]), baseline=set()))
    results = data["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["baselineState"] == "new"


def test_known_finding_is_unchanged_and_new_one_is_new():
    """A finding whose fingerprint is in the baseline is 'unchanged'; one that is
    not is 'new'. Crucially, both still appear in the SARIF output."""
    known = _finding(category="suicidal")
    fresh = _finding(
        category="reentrancy",
        detector="omen:bytecode-reentrancy",
        opcodes=[{"opcode": "SSTORE", "offset": 2}],
    )
    baseline = {finding_fingerprint(known)}
    data = json.loads(to_sarif(_report([known, fresh]), baseline=baseline))
    results = data["runs"][0]["results"]
    states = {r["ruleId"]: r["baselineState"] for r in results}
    assert states == {"omen/suicidal": "unchanged", "omen/reentrancy": "new"}
    assert len(results) == 2  # nothing dropped


def test_baseline_state_survives_severity_override():
    """The fingerprint excludes severity, so a severity change between the
    baseline finding and the live one keeps it 'unchanged', not 'new'."""
    baseline_finding = _finding(category="suicidal", severity=Severity.MEDIUM)
    live = _finding(category="suicidal", severity=Severity.CRITICAL)
    baseline = {finding_fingerprint(baseline_finding)}
    data = json.loads(to_sarif(_report([live]), baseline=baseline))
    assert data["runs"][0]["results"][0]["baselineState"] == "unchanged"


def test_baseline_does_not_disturb_existing_sarif_shape():
    """Adding baselineState leaves the rest of the result (ruleId, level,
    message, properties, locations) intact."""
    f = _finding()
    plain = json.loads(to_sarif(_report([f])))["runs"][0]["results"][0]
    annotated = json.loads(to_sarif(_report([f]), baseline=set()))["runs"][0][
        "results"
    ][0]
    # Strip the only added key and the two must match exactly.
    annotated_without = {k: v for k, v in annotated.items() if k != "baselineState"}
    assert annotated_without == plain


def test_empty_report_with_baseline_is_valid_sarif():
    data = json.loads(to_sarif(_report([]), baseline={"x|y||z"}))
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["results"] == []


# ---------------------------------------------------------------------------
# render() threading
# ---------------------------------------------------------------------------


def test_render_threads_sarif_baseline_only_to_sarif():
    known = _finding()
    baseline = {finding_fingerprint(known)}
    out = render(_report([known]), "sarif", sarif_baseline=baseline)
    assert json.loads(out)["runs"][0]["results"][0]["baselineState"] == "unchanged"


def test_render_ignores_sarif_baseline_for_non_sarif_formats():
    """baselineState is a SARIF concept; passing the kwarg for json/text/h1md is
    silently ignored (the other formats render exactly as before)."""
    f = _finding()
    baseline = {finding_fingerprint(f)}
    for fmt in ("json", "text", "h1md"):
        assert render(_report([f]), fmt, sarif_baseline=baseline) == render(
            _report([f]), fmt
        )


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def test_cli_sarif_baseline_in_help():
    assert "--sarif-baseline" in build_parser().format_help()


def test_cli_sarif_baseline_parses_and_defaults_none():
    parser = build_parser()
    ns = parser.parse_args(["--contract", "x.bin", "--input-type", "bytecode"])
    assert ns.sarif_baseline is None
    ns2 = parser.parse_args(
        [
            "--contract",
            "x.bin",
            "--input-type",
            "bytecode",
            "--sarif-baseline",
            "b.json",
        ]
    )
    assert ns2.sarif_baseline == "b.json"


def test_cli_sarif_baseline_requires_sarif_format(tmp_path, capsys):
    """--sarif-baseline with the default (json) format is a usage error."""
    base = _sarif_baseline_file(tmp_path, {"findings": []})
    with pytest.raises(SystemExit) as exc:
        main(
            [
                "--contract",
                str(tmp_path / "any.bin"),
                "--input-type",
                "bytecode",
                "--sarif-baseline",
                base,
            ]
        )
    assert exc.value.code == 2
    assert "sarif" in capsys.readouterr().err.lower()


def test_cli_sarif_baseline_rejects_batch(tmp_path, capsys):
    base = _sarif_baseline_file(tmp_path, {"findings": []})
    with pytest.raises(SystemExit) as exc:
        main(
            [
                "--batch",
                str(tmp_path),
                "--input-type",
                "sol",
                "--format",
                "sarif",
                "--sarif-baseline",
                base,
            ]
        )
    assert exc.value.code == 2
    assert "batch" in capsys.readouterr().err.lower()


def test_cli_missing_sarif_baseline_is_usage_error(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        main(
            [
                "--contract",
                str(tmp_path / "any.bin"),
                "--input-type",
                "bytecode",
                "--format",
                "sarif",
                "--sarif-baseline",
                str(tmp_path / "nope.json"),
            ]
        )
    assert exc.value.code == 2
    assert "sarif-baseline" in capsys.readouterr().err.lower()


def test_cli_non_json_sarif_baseline_is_usage_error(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("not json {", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        main(
            [
                "--contract",
                str(tmp_path / "any.bin"),
                "--input-type",
                "bytecode",
                "--format",
                "sarif",
                "--sarif-baseline",
                str(bad),
            ]
        )
    assert exc.value.code == 2


# ---------------------------------------------------------------------------
# End-to-end against the bytecode fixture (no solc)
# ---------------------------------------------------------------------------


def test_e2e_self_baseline_marks_all_unchanged(tmp_path, fixtures_dir, capsys):
    """Capture a scan, feed it back as the SARIF baseline: every result is
    'unchanged' (the legacy is acknowledged), yet every result still appears."""
    first = analyze(
        contract=str(fixtures_dir / FIXTURE), input_type="bytecode", check="all"
    )
    base = _sarif_baseline_file(tmp_path, first.to_dict())
    rc = main(
        [
            "--contract",
            str(fixtures_dir / FIXTURE),
            "--input-type",
            "bytecode",
            "--check",
            "all",
            "--format",
            "sarif",
            "--sarif-baseline",
            base,
        ]
    )
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    results = data["runs"][0]["results"]
    assert results  # findings are kept, not dropped
    assert all(r["baselineState"] == "unchanged" for r in results)


def test_e2e_partial_baseline_marks_new_finding_new(tmp_path, fixtures_dir, capsys):
    """A baseline holding only the reentrancy finding leaves the suicidal one
    'new' while the reentrancy one is 'unchanged' — the regression is flagged
    without dropping the known issue."""
    baseline_doc = {
        "findings": [
            {
                "category": "reentrancy",
                "detector": "omen:bytecode-reentrancy",
                "contract": None,
                "evidence": {
                    "source_mapping": [],
                    "opcodes": [{"opcode": "SSTORE", "offset": 2}],
                },
            }
        ]
    }
    base = _sarif_baseline_file(tmp_path, baseline_doc)
    rc = main(
        [
            "--contract",
            str(fixtures_dir / FIXTURE),
            "--input-type",
            "bytecode",
            "--check",
            "all",
            "--format",
            "sarif",
            "--sarif-baseline",
            base,
        ]
    )
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    states = {
        r["ruleId"]: r["baselineState"] for r in data["runs"][0]["results"]
    }
    assert states["omen/reentrancy"] == "unchanged"
    assert states["omen/suicidal"] == "new"


def test_e2e_sarif_baseline_does_not_change_fail_on_gate(tmp_path, fixtures_dir):
    """--sarif-baseline only annotates; unlike --baseline it does NOT suppress,
    so the --fail-on gate still trips on the (un-dropped) findings."""
    first = analyze(
        contract=str(fixtures_dir / FIXTURE), input_type="bytecode", check="all"
    )
    base = _sarif_baseline_file(tmp_path, first.to_dict())
    rc = main(
        [
            "--contract",
            str(fixtures_dir / FIXTURE),
            "--input-type",
            "bytecode",
            "--check",
            "all",
            "--format",
            "sarif",
            "--sarif-baseline",
            base,
            "--fail-on",
            "high",
        ]
    )
    # The suicidal finding is HIGH and is NOT dropped, so the gate trips (exit 3)
    # even though every result is baselineState 'unchanged'. This is the explicit
    # contrast with --baseline (which would suppress and exit 0).
    assert rc == 3
