"""Tests for --baseline finding suppression (POST_V01).

A static scanner adopted on a legacy codebase drowns the team in pre-existing
findings: the first CI run lights up red on issues that predate the scanner, so
the gate is either disabled or ignored. --baseline is the standard fix
(cf. Slither --triage-mode, semgrep --baseline, trivy .trivyignore): capture
today's findings as a known-good baseline, commit it, then on every subsequent
run suppress findings already in the baseline so the report — and the --fail-on
gate — surface only findings introduced *after* it.

The suppression runs in ``analyze`` *before* the --min-severity/--min-confidence
filters, --sort ordering, --limit cap, and crucially the --fail-on gate, so a
baselined finding neither appears, counts toward total_findings, nor trips the
gate. A finding's identity for matching is its fingerprint —
category + detector + contract + location — deliberately excluding severity and
wording, so a --severity-override re-stamp or a Slither wording change does not
make a known finding look new.

These tests use the synthetic mixed-confidence bytecode fixture (no solc
needed):

    CALLVALUE(0x34) CALL(0xf1) SSTORE(0x55) SELFDESTRUCT(0xff)

which yields a HIGH-confidence suicidal finding (opcode @0x3) and a LOW-confidence
reentrancy finding (opcode @0x2). The pure fingerprint/loader/suppress tests
cover the rest of the surface directly.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from omen.analyzer import analyze
from omen.cli import build_parser, main
from omen.findings import (
    Evidence,
    Finding,
    Severity,
    finding_fingerprint,
    load_baseline_fingerprints,
    suppress_baseline,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(
    category: str = "reentrancy",
    *,
    detector: str = "test",
    contract: str | None = None,
    severity: Severity = Severity.HIGH,
    confidence: str = "high",
    title: str = "t",
    description: str = "d",
    source_mapping: list[str] | None = None,
    opcodes: list[dict] | None = None,
) -> Finding:
    return Finding(
        category=category,
        severity=severity,
        title=title,
        description=description,
        detector=detector,
        contract=contract,
        confidence=confidence,
        evidence=Evidence(
            source_mapping=source_mapping or [],
            opcodes=opcodes or [],
        ),
    )


# ---------------------------------------------------------------------------
# finding_fingerprint — the pure identity primitive
# ---------------------------------------------------------------------------


def test_fingerprint_source_mode_uses_category_detector_contract_location():
    f = _finding(
        category="reentrancy",
        detector="reentrancy-eth",
        contract="Vault",
        source_mapping=["Vault.sol#12-18"],
    )
    assert finding_fingerprint(f) == "reentrancy|reentrancy-eth|Vault|Vault.sol#12-18"


def test_fingerprint_bytecode_mode_uses_opcode_offsets():
    f = _finding(
        category="suicidal",
        detector="omen:bytecode-selfdestruct",
        opcodes=[{"opcode": "SELFDESTRUCT", "offset": 3}],
    )
    assert finding_fingerprint(f) == "suicidal|omen:bytecode-selfdestruct||@3"


def test_fingerprint_is_location_order_insensitive():
    a = _finding(source_mapping=["A.sol#1", "B.sol#2"])
    b = _finding(source_mapping=["B.sol#2", "A.sol#1"])
    assert finding_fingerprint(a) == finding_fingerprint(b)


def test_fingerprint_ignores_severity_confidence_wording():
    """A re-stamped severity / different confidence / different wording must NOT
    change the fingerprint — that is what keeps a known finding from looking new
    after a --severity-override or a Slither release wording drift."""
    a = _finding(
        severity=Severity.HIGH,
        confidence="high",
        title="old title",
        description="old desc",
        source_mapping=["X.sol#5"],
    )
    b = _finding(
        severity=Severity.CRITICAL,
        confidence="low",
        title="new title",
        description="new desc",
        source_mapping=["X.sol#5"],
    )
    assert finding_fingerprint(a) == finding_fingerprint(b)


def test_fingerprint_distinguishes_category():
    a = _finding(category="reentrancy", source_mapping=["X.sol#5"])
    b = _finding(category="suicidal", source_mapping=["X.sol#5"])
    assert finding_fingerprint(a) != finding_fingerprint(b)


def test_fingerprint_distinguishes_location():
    a = _finding(source_mapping=["X.sol#5"])
    b = _finding(source_mapping=["X.sol#9"])
    assert finding_fingerprint(a) != finding_fingerprint(b)


def test_fingerprint_distinguishes_detector():
    a = _finding(detector="reentrancy-eth", source_mapping=["X.sol#5"])
    b = _finding(detector="reentrancy-no-eth", source_mapping=["X.sol#5"])
    assert finding_fingerprint(a) != finding_fingerprint(b)


def test_fingerprint_dict_and_object_forms_agree():
    """The fingerprint of a live Finding must equal the fingerprint computed
    from its to_dict() form — the symmetry that lets a live finding match one
    read out of a baseline JSON file."""
    f = _finding(
        category="suicidal",
        detector="omen:bytecode-selfdestruct",
        contract="C",
        opcodes=[{"opcode": "SELFDESTRUCT", "offset": 3}],
    )
    assert finding_fingerprint(f) == finding_fingerprint(f.to_dict())


# ---------------------------------------------------------------------------
# load_baseline_fingerprints — the loader
# ---------------------------------------------------------------------------


def _write(tmp_path: Path, obj, name: str = "baseline.json") -> str:
    p = tmp_path / name
    p.write_text(json.dumps(obj), encoding="utf-8")
    return str(p)


def test_load_single_report(tmp_path):
    report = {
        "findings": [
            {
                "category": "reentrancy",
                "detector": "reentrancy-eth",
                "contract": "Vault",
                "evidence": {"source_mapping": ["Vault.sol#12-18"], "opcodes": []},
            }
        ]
    }
    fps = load_baseline_fingerprints(_write(tmp_path, report))
    assert fps == {"reentrancy|reentrancy-eth|Vault|Vault.sol#12-18"}


def test_load_jsonl_batch_stream(tmp_path):
    """A batch baseline is a JSONL stream — one report object per line."""
    lines = [
        json.dumps(
            {
                "findings": [
                    {
                        "category": "suicidal",
                        "detector": "d1",
                        "contract": None,
                        "evidence": {"source_mapping": ["A.sol#1"], "opcodes": []},
                    }
                ]
            }
        ),
        json.dumps(
            {
                "findings": [
                    {
                        "category": "greedy",
                        "detector": "d2",
                        "contract": None,
                        "evidence": {"source_mapping": ["B.sol#2"], "opcodes": []},
                    }
                ]
            }
        ),
    ]
    p = tmp_path / "batch.jsonl"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    fps = load_baseline_fingerprints(str(p))
    assert fps == {"suicidal|d1||A.sol#1", "greedy|d2||B.sol#2"}


def test_load_json_array_of_reports(tmp_path):
    arr = [
        {"findings": [{"category": "a", "detector": "d", "evidence": {"source_mapping": ["A#1"]}}]},
        {"findings": [{"category": "b", "detector": "d", "evidence": {"source_mapping": ["B#2"]}}]},
    ]
    fps = load_baseline_fingerprints(_write(tmp_path, arr))
    assert fps == {"a|d||A#1", "b|d||B#2"}


def test_load_empty_findings_yields_empty_set(tmp_path):
    """A baseline captured from a clean scan is valid and suppresses nothing."""
    assert load_baseline_fingerprints(_write(tmp_path, {"findings": []})) == set()


def test_load_empty_file_yields_empty_set(tmp_path):
    p = tmp_path / "empty.json"
    p.write_text("", encoding="utf-8")
    assert load_baseline_fingerprints(str(p)) == set()


def test_load_skips_non_dict_finding_entries(tmp_path):
    report = {"findings": ["not-a-dict", {"category": "a", "detector": "d", "evidence": {"source_mapping": ["A#1"]}}]}
    assert load_baseline_fingerprints(_write(tmp_path, report)) == {"a|d||A#1"}


def test_load_missing_file_raises(tmp_path):
    with pytest.raises(ValueError, match="cannot read"):
        load_baseline_fingerprints(str(tmp_path / "nope.json"))


def test_load_non_json_raises(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("this is not json {", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid JSON"):
        load_baseline_fingerprints(str(p))


# ---------------------------------------------------------------------------
# suppress_baseline — the pure suppressor
# ---------------------------------------------------------------------------


def test_suppress_none_baseline_is_noop():
    findings = [_finding(source_mapping=["X#1"])]
    assert suppress_baseline(findings, None) is findings


def test_suppress_empty_baseline_is_noop():
    findings = [_finding(source_mapping=["X#1"])]
    assert suppress_baseline(findings, set()) is findings


def test_suppress_drops_baselined_keeps_new():
    known = _finding(category="reentrancy", detector="d", source_mapping=["X#1"])
    new = _finding(category="suicidal", detector="d", source_mapping=["X#2"])
    baseline = {finding_fingerprint(known)}
    result = suppress_baseline([known, new], baseline)
    assert result == [new]


def test_suppress_drops_all_when_all_baselined():
    a = _finding(category="a", detector="d", source_mapping=["A#1"])
    b = _finding(category="b", detector="d", source_mapping=["B#2"])
    baseline = {finding_fingerprint(a), finding_fingerprint(b)}
    assert suppress_baseline([a, b], baseline) == []


# ---------------------------------------------------------------------------
# analyze() integration — bytecode mode, no solc required
# ---------------------------------------------------------------------------

FIXTURE = "tests/fixtures/mixed-confidence.bin"
# The two findings the fixture yields, by fingerprint.
SUICIDAL_FP = "suicidal|omen:bytecode-selfdestruct||@3"
REENTRANCY_FP = "reentrancy|omen:bytecode-reentrancy||@2"


def _baseline_file(tmp_path: Path, fingerprints_from: dict) -> str:
    p = tmp_path / "baseline.json"
    p.write_text(json.dumps(fingerprints_from), encoding="utf-8")
    return str(p)


def test_analyze_no_baseline_keeps_all(fixtures_dir):
    report = analyze(contract=str(fixtures_dir / "mixed-confidence.bin"),
                     input_type="bytecode", check="all")
    assert len(report.findings) == 2


def test_analyze_baseline_from_self_suppresses_everything(tmp_path, fixtures_dir):
    """Capture the fixture's own report as a baseline, then re-scan with it: a
    re-scan of unchanged code surfaces nothing new — the core CI guarantee."""
    first = analyze(contract=str(fixtures_dir / "mixed-confidence.bin"),
                    input_type="bytecode", check="all")
    baseline = _baseline_file(tmp_path, first.to_dict())

    second = analyze(contract=str(fixtures_dir / "mixed-confidence.bin"),
                     input_type="bytecode", check="all", baseline=baseline)
    assert second.findings == []
    assert second.total_findings == 0
    assert second.to_dict()["finding_count"] == 0


def test_analyze_baseline_suppresses_only_known_finding(tmp_path, fixtures_dir):
    """A baseline holding only the reentrancy finding leaves the suicidal one as
    the new finding."""
    baseline_doc = {"findings": [{
        "category": "reentrancy",
        "detector": "omen:bytecode-reentrancy",
        "contract": None,
        "evidence": {"source_mapping": [], "opcodes": [{"opcode": "SSTORE", "offset": 2}]},
    }]}
    baseline = _baseline_file(tmp_path, baseline_doc)

    report = analyze(contract=str(fixtures_dir / "mixed-confidence.bin"),
                     input_type="bytecode", check="all", baseline=baseline)
    cats = {f.category for f in report.findings}
    assert cats == {"suicidal"}
    assert report.total_findings == 1


def test_analyze_baseline_suppresses_before_fail_on_gate(tmp_path, fixtures_dir):
    """The defining CI behaviour: a fully-baselined scan does NOT trip the
    --fail-on gate (no NEW findings), while the same scan without the baseline
    does."""
    first = analyze(contract=str(fixtures_dir / "mixed-confidence.bin"),
                    input_type="bytecode", check="all")
    baseline = _baseline_file(tmp_path, first.to_dict())

    gated = analyze(contract=str(fixtures_dir / "mixed-confidence.bin"),
                    input_type="bytecode", check="all", fail_on="high")
    assert gated.gate_triggered is True  # suicidal/reentrancy are HIGH

    baselined = analyze(contract=str(fixtures_dir / "mixed-confidence.bin"),
                        input_type="bytecode", check="all", fail_on="high",
                        baseline=baseline)
    assert baselined.gate_triggered is False  # nothing new -> gate stays clean


def test_analyze_new_finding_still_trips_gate(tmp_path, fixtures_dir):
    """If the baseline holds only one of the two findings, the other is new and
    still trips the gate — the build fails on the regression, not the legacy."""
    baseline_doc = {"findings": [{
        "category": "reentrancy",
        "detector": "omen:bytecode-reentrancy",
        "contract": None,
        "evidence": {"source_mapping": [], "opcodes": [{"opcode": "SSTORE", "offset": 2}]},
    }]}
    baseline = _baseline_file(tmp_path, baseline_doc)
    report = analyze(contract=str(fixtures_dir / "mixed-confidence.bin"),
                     input_type="bytecode", check="all", fail_on="high",
                     baseline=baseline)
    assert report.gate_triggered is True
    assert {f.category for f in report.findings} == {"suicidal"}


def test_analyze_baseline_survives_severity_override(tmp_path, fixtures_dir):
    """A --severity-override re-stamp must not make a baselined finding look new:
    the fingerprint excludes severity, so the override applies and the finding is
    still suppressed."""
    first = analyze(contract=str(fixtures_dir / "mixed-confidence.bin"),
                    input_type="bytecode", check="all")
    baseline = _baseline_file(tmp_path, first.to_dict())
    report = analyze(contract=str(fixtures_dir / "mixed-confidence.bin"),
                     input_type="bytecode", check="all", baseline=baseline,
                     severity_override="suicidal=critical")
    assert report.findings == []


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def test_cli_baseline_in_help():
    parser = build_parser()
    help_text = parser.format_help()
    assert "--baseline" in help_text


def test_cli_baseline_parses_and_defaults_none():
    parser = build_parser()
    ns = parser.parse_args(["--contract", "x.bin", "--input-type", "bytecode"])
    assert ns.baseline is None
    ns2 = parser.parse_args(
        ["--contract", "x.bin", "--input-type", "bytecode", "--baseline", "b.json"]
    )
    assert ns2.baseline == "b.json"


def test_cli_missing_baseline_is_usage_error(tmp_path, capsys):
    """A missing/unreadable baseline file is surfaced as a usage error (exit 2,
    argparse SystemExit) before any analysis, like the other up-front
    validations (cf. test_limit / test_config)."""
    with pytest.raises(SystemExit) as exc:
        main([
            "--contract", str(tmp_path / "any.bin"),
            "--input-type", "bytecode",
            "--baseline", str(tmp_path / "does-not-exist.json"),
        ])
    assert exc.value.code == 2
    assert "baseline" in capsys.readouterr().err.lower()


def test_cli_non_json_baseline_is_usage_error(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("not json {", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        main([
            "--contract", str(tmp_path / "any.bin"),
            "--input-type", "bytecode",
            "--baseline", str(bad),
        ])
    assert exc.value.code == 2
    assert "baseline" in capsys.readouterr().err.lower()


# ---------------------------------------------------------------------------
# config: baseline is a recognised path key
# ---------------------------------------------------------------------------


def test_config_accepts_baseline_key(tmp_path):
    from omen.config import load_config

    p = tmp_path / "omen.toml"
    p.write_text('baseline = "omen-baseline.json"\n', encoding="utf-8")
    cfg = load_config(str(p))
    assert cfg["baseline"] == "omen-baseline.json"


def test_config_rejects_non_string_baseline(tmp_path):
    from omen.config import ConfigError, load_config

    p = tmp_path / "omen.toml"
    p.write_text("baseline = 5\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(str(p))


# ---------------------------------------------------------------------------
# subprocess end-to-end (single-contract bytecode, no compiler needed)
# ---------------------------------------------------------------------------


def test_subprocess_baseline_end_to_end(tmp_path: Path) -> None:
    """Full CLI path: first scan writes a baseline JSON; a second scan with
    --baseline --fail-on high finds nothing new and exits 0 (the gate stays
    clean), and its report shows zero findings."""
    import os

    # Resolve this checkout's package dir and fixture independently of cwd, and
    # put the package on the subprocess PYTHONPATH so it runs *this* omen, not a
    # globally-installed copy.
    here = Path(__file__).resolve().parent
    src = here.parent / "src"
    fixture = here / "fixtures" / "mixed-confidence.bin"
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(src)] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else [])
    )
    baseline = tmp_path / "baseline.json"

    # 1) Capture the baseline.
    cap = subprocess.run(
        [sys.executable, "-m", "omen.cli", "--contract", str(fixture),
         "--input-type", "bytecode", "--check", "all", "-o", str(baseline)],
        capture_output=True, text=True, env=env,
    )
    assert cap.returncode == 0, cap.stderr
    captured = json.loads(baseline.read_text())
    assert captured["finding_count"] == 2

    # 2) Re-scan unchanged code with the baseline + a strict gate.
    rerun = subprocess.run(
        [sys.executable, "-m", "omen.cli", "--contract", str(fixture),
         "--input-type", "bytecode", "--check", "all",
         "--baseline", str(baseline), "--fail-on", "high"],
        capture_output=True, text=True, env=env,
    )
    assert rerun.returncode == 0, rerun.stderr  # nothing new -> gate clean
    report = json.loads(rerun.stdout)
    assert report["finding_count"] == 0
    assert report["gate_triggered"] is False
