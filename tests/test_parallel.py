"""Tests for the --parallel batch concurrency flag (POST_V01).

The bounty workflow --batch exists for is scanning a whole program scope —
dozens to hundreds of contracts. R2.11 (--ignore) scoped *which* files a batch
visits and R2.12 (--batch-summary) summarised the result; --parallel speeds the
scan itself by analyzing several contracts concurrently. Each ``analyze`` call
is independent and its wall time is dominated by the solc/vyper compiler
subprocess (which releases the GIL), so a thread pool gives a real speedup
without multiprocessing's pickling/import-state hazards.

The defining invariant: concurrency must never reorder the result. The JSONL
stream, the --fail-on gate (the OR across items), the error count, and the
--batch-summary roll-up are all assembled in deterministic *input order*, so a
``--parallel N`` run is byte-for-byte identical to the sequential run — only
faster. These tests cover the parse_parallel value primitive, the run_batch
ordering/equivalence invariants (mocked analyze, so they run with no compiler),
the config-file key, and the CLI surface (help + exit-2 on a bad value + a
bytecode end-to-end run that needs no compiler/network).
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from omen.batch import parse_parallel, run_batch
from omen.cli import build_parser


# --- parse_parallel: the value parser ---------------------------------------


def test_parse_parallel_none_is_one():
    """The flag default (None) means no concurrency — one worker."""
    assert parse_parallel(None) == 1


def test_parse_parallel_one():
    assert parse_parallel(1) == 1


def test_parse_parallel_int():
    assert parse_parallel(8) == 8


def test_parse_parallel_decimal_string():
    """A decimal string (config/CLI raw value) is accepted."""
    assert parse_parallel("4") == 4


def test_parse_parallel_zero_rejected():
    with pytest.raises(ValueError, match="positive integer"):
        parse_parallel(0)


def test_parse_parallel_negative_rejected():
    with pytest.raises(ValueError, match="positive integer"):
        parse_parallel(-3)


def test_parse_parallel_bool_rejected():
    """bool is an int in Python but never a sensible worker count."""
    with pytest.raises(ValueError, match="positive integer"):
        parse_parallel(True)


def test_parse_parallel_non_numeric_string_rejected():
    with pytest.raises(ValueError, match="positive integer"):
        parse_parallel("lots")


# --- run_batch: ordering and equivalence invariants (mocked analyze) --------


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


def test_run_batch_parallel_preserves_input_order(
    tmp_path: Path, capsys: pytest.CaptureFixture
):
    """Parallel output lines appear in input order regardless of finish order.

    The mocked analyze sleeps *longer for earlier* items, so if the loop emitted
    in completion order the lines would come out reversed. They must not.
    """
    lf = _list_file(tmp_path, 5)

    def side_effect(contract, **kwargs):
        # earlier items (lower trailing index) finish later
        idx = int(contract.rsplit("c", 1)[1].split(".")[0])
        time.sleep(0.02 * (5 - idx))
        return _make_report(contract)

    with patch("omen.batch.analyze", side_effect=side_effect):
        exit_code = run_batch(str(lf), "sol", "all", parallel=4)

    out = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
    origins = [json.loads(ln)["origin"] for ln in out]
    assert origins == [f"/contracts/c{i}.sol" for i in range(5)]
    assert exit_code == 0


def test_run_batch_parallel_matches_sequential_byte_for_byte(
    tmp_path: Path, capsys: pytest.CaptureFixture
):
    """The same batch run sequentially and in parallel yields identical stdout."""
    lf = _list_file(tmp_path, 6)

    def side_effect(contract, **kwargs):
        return _make_report(contract)

    with patch("omen.batch.analyze", side_effect=side_effect):
        run_batch(str(lf), "sol", "all", parallel=1)
    seq = capsys.readouterr().out

    with patch("omen.batch.analyze", side_effect=side_effect):
        run_batch(str(lf), "sol", "all", parallel=4)
    par = capsys.readouterr().out

    assert par == seq


def test_run_batch_parallel_actually_concurrent(
    tmp_path: Path, capsys: pytest.CaptureFixture
):
    """With parallel>1 more than one analyze runs at once (true concurrency)."""
    lf = _list_file(tmp_path, 4)
    active = 0
    peak = 0
    lock = threading.Lock()

    def side_effect(contract, **kwargs):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        time.sleep(0.05)
        with lock:
            active -= 1
        return _make_report(contract)

    with patch("omen.batch.analyze", side_effect=side_effect):
        run_batch(str(lf), "sol", "all", parallel=4)

    capsys.readouterr()
    assert peak >= 2  # at least two analyses overlapped


def test_run_batch_parallel_gate_is_or_across_items(
    tmp_path: Path, capsys: pytest.CaptureFixture
):
    """The --fail-on gate trips (exit 3) if ANY item trips, even in parallel."""
    lf = _list_file(tmp_path, 4)

    def side_effect(contract, **kwargs):
        # only c2 trips the gate
        gate = contract.endswith("c2.sol")
        return _make_report(contract, gate=gate)

    with patch("omen.batch.analyze", side_effect=side_effect):
        exit_code = run_batch(str(lf), "sol", "all", parallel=4, fail_on="high")

    capsys.readouterr()
    assert exit_code == 3


def test_run_batch_parallel_error_outranks_gate(
    tmp_path: Path, capsys: pytest.CaptureFixture
):
    """A per-item failure (exit 1) still outranks a tripped gate in parallel."""
    lf = _list_file(tmp_path, 4)

    def side_effect(contract, **kwargs):
        if contract.endswith("c1.sol"):
            raise RuntimeError("boom")
        return _make_report(contract, gate=True)

    with patch("omen.batch.analyze", side_effect=side_effect):
        exit_code = run_batch(str(lf), "sol", "all", parallel=4, fail_on="high")

    err = capsys.readouterr().err
    assert exit_code == 1  # error (1) beats gate (3)
    assert "boom" in err


def test_run_batch_parallel_error_count_in_summary(
    tmp_path: Path, capsys: pytest.CaptureFixture
):
    """--batch-summary counts errors and scanned contracts correctly in parallel."""
    lf = _list_file(tmp_path, 5)

    def side_effect(contract, **kwargs):
        if contract.endswith(("c1.sol", "c3.sol")):
            raise RuntimeError("nope")
        return _make_report(contract)

    with patch("omen.batch.analyze", side_effect=side_effect):
        run_batch(str(lf), "sol", "all", parallel=4, batch_summary=True)

    err = capsys.readouterr().err
    # 3 scanned cleanly, 2 errored
    assert "3 scanned" in err
    assert "2 errored" in err


def test_run_batch_parallel_output_file_ordered(tmp_path: Path):
    """--parallel composes with --output-file: JSONL written in input order."""
    lf = _list_file(tmp_path, 5)
    out = tmp_path / "report.jsonl"

    def side_effect(contract, **kwargs):
        idx = int(contract.rsplit("c", 1)[1].split(".")[0])
        time.sleep(0.01 * (5 - idx))
        return _make_report(contract)

    with patch("omen.batch.analyze", side_effect=side_effect):
        run_batch(str(lf), "sol", "all", parallel=4, output_file=str(out))

    lines = [ln for ln in out.read_text().splitlines() if ln.strip()]
    origins = [json.loads(ln)["origin"] for ln in lines]
    assert origins == [f"/contracts/c{i}.sol" for i in range(5)]


def test_run_batch_parallel_single_item_uses_sequential_path(
    tmp_path: Path, capsys: pytest.CaptureFixture
):
    """A 1-item batch with --parallel still works (pool would be overhead)."""
    lf = _list_file(tmp_path, 1)

    with patch(
        "omen.batch.analyze",
        side_effect=lambda contract, **kw: _make_report(contract),
    ):
        exit_code = run_batch(str(lf), "sol", "all", parallel=8)

    out = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
    assert len(out) == 1
    assert exit_code == 0


def test_run_batch_parallel_default_is_sequential(
    tmp_path: Path, capsys: pytest.CaptureFixture
):
    """Omitting parallel (None) preserves the historical sequential behaviour."""
    lf = _list_file(tmp_path, 3)

    with patch(
        "omen.batch.analyze",
        side_effect=lambda contract, **kw: _make_report(contract),
    ):
        exit_code = run_batch(str(lf), "sol", "all")

    out = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
    origins = [json.loads(ln)["origin"] for ln in out]
    assert origins == ["/contracts/c0.sol", "/contracts/c1.sol", "/contracts/c2.sol"]
    assert exit_code == 0


def test_run_batch_bad_parallel_raises(tmp_path: Path):
    """An invalid parallel value surfaces as a ValueError before any scan."""
    lf = _list_file(tmp_path, 2)
    with pytest.raises(ValueError, match="positive integer"):
        run_batch(str(lf), "sol", "all", parallel=0)


# --- config-file key --------------------------------------------------------


def test_config_accepts_parallel_key(tmp_path: Path):
    """omen.toml may set `parallel` as a positive int."""
    from omen.config import load_config

    cfg_file = tmp_path / "omen.toml"
    cfg_file.write_text("parallel = 8\n")
    cfg = load_config(str(cfg_file))
    assert cfg["parallel"] == 8


def test_config_parallel_non_positive_rejected(tmp_path: Path):
    """A non-positive `parallel` value is a file-named ConfigError."""
    from omen.config import ConfigError, load_config

    cfg_file = tmp_path / "omen.toml"
    cfg_file.write_text("parallel = 0\n")
    with pytest.raises(ConfigError, match="parallel"):
        load_config(str(cfg_file))


def test_config_parallel_bool_rejected(tmp_path: Path):
    """A boolean `parallel` value is rejected (TOML true is not a worker count)."""
    from omen.config import ConfigError, load_config

    cfg_file = tmp_path / "omen.toml"
    cfg_file.write_text("parallel = true\n")
    with pytest.raises(ConfigError, match="parallel"):
        load_config(str(cfg_file))


# --- CLI surface ------------------------------------------------------------


def test_cli_help_includes_parallel():
    text = build_parser().format_help()
    assert "--parallel" in text


def test_cli_parallel_parses_into_namespace():
    args = build_parser().parse_args(
        ["--batch", "/tmp", "--input-type", "sol", "--parallel", "4"]
    )
    assert args.parallel == 4


def test_cli_parallel_default_is_none():
    args = build_parser().parse_args(["--batch", "/tmp", "--input-type", "sol"])
    assert args.parallel is None


def test_cli_parallel_zero_is_exit_2():
    """A non-positive --parallel is an argparse-style usage error (exit 2)."""
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "omen.cli",
            "--batch",
            "/tmp",
            "--input-type",
            "sol",
            "--parallel",
            "0",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2
    assert "--parallel" in proc.stderr


def test_cli_parallel_noop_in_single_contract_mode(tmp_path: Path):
    """--parallel is accepted but a no-op for a single --contract scan (bytecode)."""
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
            "--parallel",
            "4",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    parsed = json.loads(proc.stdout)
    assert parsed["tool"] == "omen"


def test_cli_parallel_batch_end_to_end(tmp_path: Path):
    """A real --batch --parallel run over .bin files needs no compiler/network."""
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
            "--parallel",
            "3",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    assert len(lines) == 4
    origins = [json.loads(ln)["origin"] for ln in lines]
    assert origins == paths  # input order preserved
