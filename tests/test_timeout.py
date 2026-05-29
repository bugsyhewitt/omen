"""Tests for the --timeout per-contract batch budget (POST_V01 R2.14).

The bounty workflow --batch exists for is scanning a whole program scope —
dozens to hundreds of contracts. R2.13 (--parallel) sped the scan up by running
several contracts at once; --timeout protects the *throughput* from the opposite
hazard: a single pathological contract (a compiler that hangs, a runaway
symbolic path) that would otherwise stall the whole scan. A per-contract
wall-clock budget abandons such a scan and records it as a per-item error, so
the batch makes progress past it.

The design deliberately reuses the existing --parallel thread-pool orchestration
seam — the budget is enforced with ``Future.result(timeout=...)`` from the
driver thread — rather than subprocess-wrapping or killing the in-process
Slither analysis (which would change omen's defining architecture and violate
the Anti-Abstraction / Simplicity gates). The defining invariants carry over
from --parallel: a timed-out item folds in as a per-item error in the same
``(None, error)`` shape an exception produces, and results are assembled in
deterministic *input order* regardless of finish order. These tests cover the
parse_timeout value primitive, the run_batch timeout behaviour (mocked analyze,
so they run with no compiler), the config-file key, and the CLI surface.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from omen.batch import parse_timeout, run_batch
from omen.cli import build_parser


# --- parse_timeout: the value parser ----------------------------------------


def test_parse_timeout_none_is_none():
    """The flag default (None) means no budget."""
    assert parse_timeout(None) is None


def test_parse_timeout_int():
    assert parse_timeout(30) == 30.0


def test_parse_timeout_float():
    assert parse_timeout(2.5) == 2.5


def test_parse_timeout_decimal_string():
    """A decimal string (config/CLI raw value) is accepted."""
    assert parse_timeout("1.5") == 1.5


def test_parse_timeout_zero_rejected():
    with pytest.raises(ValueError, match="positive number"):
        parse_timeout(0)


def test_parse_timeout_negative_rejected():
    with pytest.raises(ValueError, match="positive number"):
        parse_timeout(-3)


def test_parse_timeout_bool_rejected():
    """bool is an int in Python but never a sensible budget."""
    with pytest.raises(ValueError, match="positive number"):
        parse_timeout(True)


def test_parse_timeout_nan_rejected():
    with pytest.raises(ValueError, match="positive number"):
        parse_timeout(float("nan"))


def test_parse_timeout_inf_rejected():
    with pytest.raises(ValueError, match="positive number"):
        parse_timeout(float("inf"))


def test_parse_timeout_non_numeric_string_rejected():
    with pytest.raises(ValueError, match="positive number"):
        parse_timeout("soon")


# --- run_batch: timeout behaviour (mocked analyze) --------------------------


def _make_report(
    origin: str, *, gate: bool = False, findings: list | None = None
) -> MagicMock:
    report = MagicMock()
    report.gate_triggered = gate
    flist = findings or []
    report.to_dict.return_value = {
        "tool": "omen",
        "version": "0.1.0",
        "input_type": "sol",
        "origin": origin,
        "checks": ["suicidal"],
        "finding_count": len(flist),
        "total_findings": len(flist),
        "gate_triggered": gate,
        "findings": flist,
    }
    return report


def _list_file(tmp_path: Path, n: int) -> Path:
    """A list file of n .sol paths, named so input order is c0..c(n-1)."""
    lf = tmp_path / "list.txt"
    lf.write_text("\n".join(f"/contracts/c{i}.sol" for i in range(n)) + "\n")
    return lf


def test_run_batch_timeout_abandons_slow_item(
    tmp_path: Path, capsys: pytest.CaptureFixture
):
    """A contract that overruns the budget becomes a per-item error (exit 1)."""
    lf = _list_file(tmp_path, 3)

    def side_effect(contract, **kwargs):
        if contract.endswith("c1.sol"):
            time.sleep(2.0)  # well past the budget
        return _make_report(contract)

    # parallel=3 so each item gets its own worker — a stuck c1 does not block
    # c2 in the pool queue, which is the "make progress past a stuck contract"
    # guarantee --timeout exists for.
    with patch("omen.batch.analyze", side_effect=side_effect):
        exit_code = run_batch(str(lf), "sol", "all", timeout=0.2, parallel=3)

    captured = capsys.readouterr()
    out = [ln for ln in captured.out.splitlines() if ln.strip()]
    origins = [json.loads(ln)["origin"] for ln in out]
    # the slow item is abandoned; the other two still produce output, in order
    assert origins == ["/contracts/c0.sol", "/contracts/c2.sol"]
    assert "timeout" in captured.err
    assert "c1.sol" in captured.err
    assert exit_code == 1  # a timed-out item is an error


def test_run_batch_timeout_clean_run_unaffected(
    tmp_path: Path, capsys: pytest.CaptureFixture
):
    """A generous budget that nothing overruns leaves the result unchanged."""
    lf = _list_file(tmp_path, 4)

    with patch(
        "omen.batch.analyze",
        side_effect=lambda contract, **kw: _make_report(contract),
    ):
        exit_code = run_batch(str(lf), "sol", "all", timeout=10)

    out = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
    origins = [json.loads(ln)["origin"] for ln in out]
    assert origins == [f"/contracts/c{i}.sol" for i in range(4)]
    assert exit_code == 0


def test_run_batch_timeout_preserves_input_order(
    tmp_path: Path, capsys: pytest.CaptureFixture
):
    """Output stays in input order under a timeout, regardless of finish order."""
    lf = _list_file(tmp_path, 5)

    def side_effect(contract, **kwargs):
        # earlier items finish later, but none overruns the generous budget
        idx = int(contract.rsplit("c", 1)[1].split(".")[0])
        time.sleep(0.02 * (5 - idx))
        return _make_report(contract)

    with patch("omen.batch.analyze", side_effect=side_effect):
        exit_code = run_batch(str(lf), "sol", "all", timeout=5, parallel=4)

    out = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
    origins = [json.loads(ln)["origin"] for ln in out]
    assert origins == [f"/contracts/c{i}.sol" for i in range(5)]
    assert exit_code == 0


def test_run_batch_timeout_counts_in_summary(
    tmp_path: Path, capsys: pytest.CaptureFixture
):
    """--batch-summary counts a timed-out item as an error."""
    lf = _list_file(tmp_path, 3)

    def side_effect(contract, **kwargs):
        if contract.endswith("c0.sol"):
            time.sleep(2.0)
        return _make_report(contract)

    with patch("omen.batch.analyze", side_effect=side_effect):
        run_batch(
            str(lf), "sol", "all", timeout=0.2, parallel=3, batch_summary=True
        )

    err = capsys.readouterr().err
    assert "2 scanned" in err  # two clean
    assert "1 errored" in err  # the timed-out one


def test_run_batch_timeout_error_outranks_gate(
    tmp_path: Path, capsys: pytest.CaptureFixture
):
    """A timed-out item (exit 1) outranks a tripped --fail-on gate (exit 3)."""
    lf = _list_file(tmp_path, 3)

    def side_effect(contract, **kwargs):
        if contract.endswith("c0.sol"):
            time.sleep(2.0)
        return _make_report(contract, gate=True)

    with patch("omen.batch.analyze", side_effect=side_effect):
        exit_code = run_batch(
            str(lf), "sol", "all", timeout=0.2, parallel=3, fail_on="high"
        )

    capsys.readouterr()
    assert exit_code == 1  # error (1) beats gate (3)


def test_run_batch_timeout_composes_with_output_file(tmp_path: Path):
    """--timeout composes with --output-file: surviving items written in order."""
    lf = _list_file(tmp_path, 3)
    out = tmp_path / "report.jsonl"

    def side_effect(contract, **kwargs):
        if contract.endswith("c1.sol"):
            time.sleep(2.0)
        return _make_report(contract)

    with patch("omen.batch.analyze", side_effect=side_effect):
        run_batch(
            str(lf), "sol", "all", timeout=0.2, parallel=3, output_file=str(out)
        )

    lines = [ln for ln in out.read_text().splitlines() if ln.strip()]
    origins = [json.loads(ln)["origin"] for ln in lines]
    assert origins == ["/contracts/c0.sol", "/contracts/c2.sol"]


def test_run_batch_timeout_makes_progress_past_stuck_item_promptly(
    tmp_path: Path, capsys: pytest.CaptureFixture
):
    """The batch returns soon after the budget, not after the stuck scan ends."""
    lf = _list_file(tmp_path, 2)

    def side_effect(contract, **kwargs):
        if contract.endswith("c0.sol"):
            time.sleep(5.0)  # would dominate if we waited on it
        return _make_report(contract)

    start = time.monotonic()
    with patch("omen.batch.analyze", side_effect=side_effect):
        run_batch(str(lf), "sol", "all", timeout=0.2, parallel=2)
    elapsed = time.monotonic() - start

    capsys.readouterr()
    # We waited the budget for c0, not its full 5s sleep; allow generous slack.
    assert elapsed < 2.0


def test_run_batch_timeout_single_worker_blocks_queue(
    tmp_path: Path, capsys: pytest.CaptureFixture
):
    """With the default single worker, a stuck item blocks the items behind it.

    This pins the honest semantic: --timeout bounds the driver's *wait* per
    item, but a single shared worker thread can only run one scan at a time, so
    a contract that stalls the lone worker also times out the contracts queued
    behind it. The "make progress past a stuck contract" guarantee needs a free
    worker — i.e. pairing --timeout with --parallel >= 2.
    """
    lf = _list_file(tmp_path, 3)

    def side_effect(contract, **kwargs):
        if contract.endswith("c0.sol"):
            time.sleep(2.0)
        return _make_report(contract)

    with patch("omen.batch.analyze", side_effect=side_effect):
        exit_code = run_batch(str(lf), "sol", "all", timeout=0.2)

    capsys.readouterr()
    # the lone worker is stuck on c0, so c1 and c2 also exceed the budget
    assert exit_code == 1


def test_run_batch_no_timeout_default_unchanged(
    tmp_path: Path, capsys: pytest.CaptureFixture
):
    """Omitting timeout (None) preserves the historical sequential behaviour."""
    lf = _list_file(tmp_path, 3)

    with patch(
        "omen.batch.analyze",
        side_effect=lambda contract, **kw: _make_report(contract),
    ):
        exit_code = run_batch(str(lf), "sol", "all")

    out = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
    origins = [json.loads(ln)["origin"] for ln in out]
    assert origins == [f"/contracts/c{i}.sol" for i in range(3)]
    assert exit_code == 0


def test_run_batch_bad_timeout_raises(tmp_path: Path):
    """An invalid timeout value surfaces as a ValueError before any scan."""
    lf = _list_file(tmp_path, 2)
    with pytest.raises(ValueError, match="positive number"):
        run_batch(str(lf), "sol", "all", timeout=0)


# --- config-file key --------------------------------------------------------


def test_config_accepts_timeout_float(tmp_path: Path):
    """omen.toml may set `timeout` as a positive float."""
    from omen.config import load_config

    cfg_file = tmp_path / "omen.toml"
    cfg_file.write_text("timeout = 2.5\n")
    cfg = load_config(str(cfg_file))
    assert cfg["timeout"] == 2.5


def test_config_accepts_timeout_int_coerced_to_float(tmp_path: Path):
    """A TOML int timeout is accepted and coerced to float."""
    from omen.config import load_config

    cfg_file = tmp_path / "omen.toml"
    cfg_file.write_text("timeout = 30\n")
    cfg = load_config(str(cfg_file))
    assert cfg["timeout"] == 30.0
    assert isinstance(cfg["timeout"], float)


def test_config_timeout_non_positive_rejected(tmp_path: Path):
    """A non-positive `timeout` value is a file-named ConfigError."""
    from omen.config import ConfigError, load_config

    cfg_file = tmp_path / "omen.toml"
    cfg_file.write_text("timeout = 0\n")
    with pytest.raises(ConfigError, match="timeout"):
        load_config(str(cfg_file))


def test_config_timeout_bool_rejected(tmp_path: Path):
    """A boolean `timeout` value is rejected (TOML true is not a budget)."""
    from omen.config import ConfigError, load_config

    cfg_file = tmp_path / "omen.toml"
    cfg_file.write_text("timeout = true\n")
    with pytest.raises(ConfigError, match="timeout"):
        load_config(str(cfg_file))


def test_config_timeout_string_rejected(tmp_path: Path):
    """A string `timeout` value is rejected (must be a number)."""
    from omen.config import ConfigError, load_config

    cfg_file = tmp_path / "omen.toml"
    cfg_file.write_text('timeout = "soon"\n')
    with pytest.raises(ConfigError, match="timeout"):
        load_config(str(cfg_file))


# --- CLI surface ------------------------------------------------------------


def test_cli_help_includes_timeout():
    text = build_parser().format_help()
    assert "--timeout" in text


def test_cli_timeout_parses_into_namespace():
    args = build_parser().parse_args(
        ["--batch", "/tmp", "--input-type", "sol", "--timeout", "2.5"]
    )
    assert args.timeout == 2.5


def test_cli_timeout_default_is_none():
    args = build_parser().parse_args(["--batch", "/tmp", "--input-type", "sol"])
    assert args.timeout is None


def test_cli_timeout_zero_is_exit_2():
    """A non-positive --timeout is an argparse-style usage error (exit 2)."""
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "omen.cli",
            "--batch",
            "/tmp",
            "--input-type",
            "sol",
            "--timeout",
            "0",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2
    assert "--timeout" in proc.stderr


def test_cli_timeout_noop_in_single_contract_mode(tmp_path: Path):
    """--timeout is accepted but a no-op for a single --contract scan."""
    bin_file = tmp_path / "c.bin"
    bin_file.write_text("0x6080604052ff")
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "omen.cli",
            "--contract",
            str(bin_file),
            "--input-type",
            "bytecode",
            "--check",
            "all",
            "--timeout",
            "5",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    parsed = json.loads(proc.stdout)
    assert parsed["tool"] == "omen"


def test_cli_timeout_batch_end_to_end(tmp_path: Path):
    """A real --batch --timeout run over .bin files needs no compiler/network."""
    paths = []
    for i in range(4):
        b = tmp_path / f"c{i}.bin"
        b.write_text("0x6080604052ff")
        paths.append(str(b))
    lf = tmp_path / "list.txt"
    lf.write_text("\n".join(paths) + "\n")

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "omen.cli",
            "--batch",
            str(lf),
            "--input-type",
            "bytecode",
            "--check",
            "suicidal",
            "--timeout",
            "30",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    assert len(lines) == 4
    origins = [json.loads(ln)["origin"] for ln in lines]
    assert origins == paths  # input order preserved
