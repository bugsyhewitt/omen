"""Tests for omen batch scanning (--batch flag).

Covers:
- Directory scanning via glob (mocked filesystem)
- Address-list file parsing (reads lines correctly)
- Comment line skipping (#-prefixed)
- Blank line skipping
- JSONL output format (one valid JSON dict per line)
- Each JSONL line contains expected keys
- Item-level errors written to stderr, batch continues
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from omen.batch import _iter_items, run_batch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_report(origin: str = "test.sol", gate_triggered: bool = False) -> MagicMock:
    """Return a minimal mock AnalysisReport whose to_dict() is stable.

    ``gate_triggered`` mirrors the real AnalysisReport attribute (POST_V01
    Rotation 2, R2.5): run_batch reads it to decide whether the --fail-on gate
    tripped, so the mock must expose a concrete bool (a bare MagicMock attribute
    is always truthy and would spuriously trip the gate).
    """
    report = MagicMock()
    report.gate_triggered = gate_triggered
    report.to_dict.return_value = {
        "tool": "omen",
        "version": "0.1.0",
        "input_type": "sol",
        "origin": origin,
        "checks": ["suicidal"],
        "finding_count": 0,
        "findings": [],
    }
    return report


# ---------------------------------------------------------------------------
# _iter_items — directory mode
# ---------------------------------------------------------------------------


def test_iter_items_directory_finds_sol_files(tmp_path: Path) -> None:
    """Directory input yields all .sol files recursively."""
    (tmp_path / "a.sol").write_text("// sol a")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "b.sol").write_text("// sol b")
    (tmp_path / "ignored.bin").write_text("0x")  # not a .sol — should be skipped

    items = list(_iter_items(str(tmp_path), "sol"))
    # Two .sol files found, .bin ignored
    assert len(items) == 2
    assert all(item.endswith(".sol") for item in items)


def test_iter_items_directory_no_sol_files(tmp_path: Path) -> None:
    """Directory with no .sol files yields nothing."""
    (tmp_path / "readme.txt").write_text("not solidity")
    items = list(_iter_items(str(tmp_path), "sol"))
    assert items == []


# ---------------------------------------------------------------------------
# _iter_items — file / list mode
# ---------------------------------------------------------------------------


def test_iter_items_file_reads_lines(tmp_path: Path) -> None:
    """File input yields each non-blank non-comment line."""
    list_file = tmp_path / "addrs.txt"
    list_file.write_text(
        "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
        "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n"
    )
    items = list(_iter_items(str(list_file), "address"))
    assert items == [
        "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    ]


def test_iter_items_skips_comment_lines(tmp_path: Path) -> None:
    """Lines starting with # are skipped."""
    list_file = tmp_path / "list.txt"
    list_file.write_text(
        "# this is a comment\n"
        "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
        "# another comment\n"
    )
    items = list(_iter_items(str(list_file), "address"))
    assert len(items) == 1
    assert items[0].startswith("0x")


def test_iter_items_skips_blank_lines(tmp_path: Path) -> None:
    """Blank lines (empty or whitespace-only) are skipped."""
    list_file = tmp_path / "list.txt"
    list_file.write_text(
        "\n"
        "   \n"
        "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
        "\n"
    )
    items = list(_iter_items(str(list_file), "address"))
    assert len(items) == 1


def test_iter_items_strips_whitespace_from_lines(tmp_path: Path) -> None:
    """Leading and trailing whitespace is stripped from each line."""
    list_file = tmp_path / "list.txt"
    list_file.write_text("  0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  \n")
    items = list(_iter_items(str(list_file), "address"))
    assert items == ["0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]


def test_iter_items_missing_path_raises() -> None:
    """A path that is neither a file nor a directory raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError, match="neither a directory nor a regular file"):
        list(_iter_items("/nonexistent/path/does/not/exist", "sol"))


# ---------------------------------------------------------------------------
# run_batch — JSONL output
# ---------------------------------------------------------------------------


def test_run_batch_emits_jsonl_per_contract(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """run_batch emits exactly one JSON line per contract."""
    # Two .sol files in a directory
    (tmp_path / "a.sol").write_text("// a")
    (tmp_path / "b.sol").write_text("// b")

    reports = [_make_report("a.sol"), _make_report("b.sol")]

    with patch("omen.batch.analyze", side_effect=reports):
        exit_code = run_batch(str(tmp_path), "sol", "all")

    captured = capsys.readouterr()
    lines = [ln for ln in captured.out.splitlines() if ln.strip()]
    assert len(lines) == 2
    assert exit_code == 0


def test_run_batch_output_is_valid_json_dicts(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """Each line of JSONL output is a valid JSON dict."""
    (tmp_path / "c.sol").write_text("// c")
    report = _make_report("c.sol")

    with patch("omen.batch.analyze", return_value=report):
        run_batch(str(tmp_path), "sol", "suicidal")

    captured = capsys.readouterr()
    lines = [ln for ln in captured.out.splitlines() if ln.strip()]
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert isinstance(parsed, dict)


def test_run_batch_jsonl_has_expected_keys(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """Each JSONL dict contains the expected top-level keys."""
    (tmp_path / "d.sol").write_text("// d")
    report = _make_report("d.sol")

    with patch("omen.batch.analyze", return_value=report):
        run_batch(str(tmp_path), "sol", "all")

    captured = capsys.readouterr()
    lines = [ln for ln in captured.out.splitlines() if ln.strip()]
    parsed = json.loads(lines[0])

    for key in ("tool", "version", "input_type", "origin", "checks", "finding_count", "findings"):
        assert key in parsed, f"JSONL dict missing key: {key}"


# ---------------------------------------------------------------------------
# run_batch — error handling
# ---------------------------------------------------------------------------


def test_run_batch_item_error_continues_and_returns_1(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """An error on one item is written to stderr; batch continues; exit code is 1."""
    (tmp_path / "good.sol").write_text("// good")
    (tmp_path / "bad.sol").write_text("// bad")

    good_report = _make_report("good.sol")

    def side_effect(contract, input_type, check, rpc_url, **kwargs):
        if "bad" in contract:
            raise RuntimeError("simulated analysis failure")
        return good_report

    with patch("omen.batch.analyze", side_effect=side_effect):
        exit_code = run_batch(str(tmp_path), "sol", "all")

    captured = capsys.readouterr()
    # One good line on stdout
    lines = [ln for ln in captured.out.splitlines() if ln.strip()]
    assert len(lines) == 1
    # Error on stderr
    assert "bad.sol" in captured.err
    # Non-zero exit because one item failed
    assert exit_code == 1


def test_run_batch_all_success_returns_0(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """Exit code 0 when all items succeed."""
    (tmp_path / "ok.sol").write_text("// ok")
    report = _make_report("ok.sol")

    with patch("omen.batch.analyze", return_value=report):
        exit_code = run_batch(str(tmp_path), "sol", "all")

    assert exit_code == 0


# ---------------------------------------------------------------------------
# CLI integration — --batch in help and mutual exclusion
# ---------------------------------------------------------------------------


def test_cli_help_includes_batch() -> None:
    """--batch appears in the CLI help text."""
    from omen.cli import build_parser

    text = build_parser().format_help()
    assert "--batch" in text


def test_cli_batch_and_contract_mutually_exclusive() -> None:
    """Providing both --batch and --contract causes argparse to error (exit 2)."""
    import subprocess

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "omen.cli",
            "--batch",
            "/tmp",
            "--contract",
            "0x" + "00" * 20,
            "--input-type",
            "sol",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2


def test_cli_requires_either_contract_or_batch() -> None:
    """Providing neither --batch nor --contract causes argparse to error (exit 2)."""
    import subprocess

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "omen.cli",
            "--input-type",
            "sol",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2
