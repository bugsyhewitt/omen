"""Tests for the -o/--output-file flag (POST_V01 Rotation 2, R2.9).

R2.1–R2.8 built the full triage pipeline (list -> filter -> sort -> cap -> gate
-> render) and closed the --check input axis from both directions. R2.9 closes
the *destination* axis: write the rendered report to a file instead of stdout,
composing with every existing --format (json/text/h1md/sarif) and with --batch
JSONL. Omitting the flag is the historical stdout behaviour, unchanged.

These tests use the synthetic bytecode fixture so they run with no solc/vyper
dependency.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from omen.cli import build_parser, main, write_output


# ---------------------------------------------------------------------------
# write_output — the pure helper
# ---------------------------------------------------------------------------


def test_write_output_none_goes_to_stdout(capsys):
    write_output("hello world", None)
    out = capsys.readouterr().out
    assert out == "hello world\n"


def test_write_output_writes_file_with_trailing_newline(tmp_path):
    target = tmp_path / "report.json"
    write_output('{"a": 1}', str(target))
    assert target.read_text(encoding="utf-8") == '{"a": 1}\n'


def test_write_output_is_atomic_no_tmp_left_behind(tmp_path):
    target = tmp_path / "report.json"
    write_output("payload", str(target))
    # The sibling .tmp must have been renamed away, not left lying around.
    assert not (tmp_path / "report.json.tmp").exists()
    assert target.read_text(encoding="utf-8") == "payload\n"


def test_write_output_creates_parent_directories(tmp_path):
    target = tmp_path / "nested" / "deep" / "report.json"
    write_output("x", str(target))
    assert target.read_text(encoding="utf-8") == "x\n"


def test_write_output_overwrites_existing_file(tmp_path):
    target = tmp_path / "report.json"
    target.write_text("STALE", encoding="utf-8")
    write_output("FRESH", str(target))
    assert target.read_text(encoding="utf-8") == "FRESH\n"


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def test_help_lists_output_file():
    assert "--output-file" in build_parser().format_help()


def test_default_output_file_is_none():
    args = build_parser().parse_args(
        ["--contract", "x.bin", "--input-type", "bytecode"]
    )
    assert args.output_file is None


def test_long_flag_parsed():
    args = build_parser().parse_args(
        ["--contract", "x.bin", "--input-type", "bytecode", "--output-file", "r.json"]
    )
    assert args.output_file == "r.json"


def test_short_flag_parsed():
    args = build_parser().parse_args(
        ["--contract", "x.bin", "--input-type", "bytecode", "-o", "r.json"]
    )
    assert args.output_file == "r.json"


# ---------------------------------------------------------------------------
# main() single-contract mode (in-process, no solc)
# ---------------------------------------------------------------------------


def _scan_args(fixtures_dir: Path, *extra: str) -> list[str]:
    return [
        "--contract",
        str(fixtures_dir / "mixed-confidence.bin"),
        "--input-type",
        "bytecode",
        "--check",
        "all",
        *extra,
    ]


def test_main_writes_report_to_file_not_stdout(fixtures_dir, tmp_path, capsys):
    target = tmp_path / "report.json"
    code = main(_scan_args(fixtures_dir, "-o", str(target)))
    assert code == 0
    # Nothing went to stdout...
    assert capsys.readouterr().out == ""
    # ...the full JSON report landed in the file.
    report = json.loads(target.read_text(encoding="utf-8"))
    assert report["tool"] == "omen"
    assert "findings" in report


def test_main_file_matches_stdout_byte_for_byte(fixtures_dir, tmp_path, capsys):
    # The file content (sans the trailing newline write_output adds) must equal
    # what the same scan prints to stdout — the redirect changes destination,
    # never content.
    code_stdout = main(_scan_args(fixtures_dir))
    assert code_stdout == 0
    stdout = capsys.readouterr().out.rstrip("\n")

    target = tmp_path / "report.json"
    code_file = main(_scan_args(fixtures_dir, "-o", str(target)))
    assert code_file == 0
    file_text = target.read_text(encoding="utf-8").rstrip("\n")
    assert file_text == stdout


def test_main_output_file_composes_with_format_text(fixtures_dir, tmp_path, capsys):
    target = tmp_path / "report.txt"
    code = main(_scan_args(fixtures_dir, "--format", "text", "-o", str(target)))
    assert code == 0
    assert capsys.readouterr().out == ""
    text = target.read_text(encoding="utf-8")
    # text format is not JSON; just assert it's non-empty human output.
    assert text.strip()
    with pytest.raises(json.JSONDecodeError):
        json.loads(text)


def test_main_output_file_composes_with_format_sarif(fixtures_dir, tmp_path, capsys):
    target = tmp_path / "report.sarif"
    code = main(_scan_args(fixtures_dir, "--format", "sarif", "-o", str(target)))
    assert code == 0
    sarif = json.loads(target.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"


def test_output_file_does_not_change_fail_on_exit_code(fixtures_dir, tmp_path, capsys):
    # The gate trips identically whether the report goes to a file or stdout.
    target = tmp_path / "report.json"
    code = main(_scan_args(fixtures_dir, "--fail-on", "high", "-o", str(target)))
    assert code == 3
    # Report still written despite the non-zero gate exit.
    report = json.loads(target.read_text(encoding="utf-8"))
    assert report["gate_triggered"] is True


# ---------------------------------------------------------------------------
# batch forwarding — JSONL stream to a file
# ---------------------------------------------------------------------------


def test_batch_writes_jsonl_to_file(fixtures_dir, tmp_path, capsys):
    from omen.batch import run_batch

    list_file = tmp_path / "targets.txt"
    bin_path = str(fixtures_dir / "mixed-confidence.bin")
    list_file.write_text(f"{bin_path}\n{bin_path}\n")
    target = tmp_path / "out.jsonl"

    code = run_batch(
        path=str(list_file),
        input_type="bytecode",
        check="all",
        output_file=str(target),
    )
    assert code == 0
    # Nothing streamed to stdout when redirected.
    assert capsys.readouterr().out == ""
    lines = [ln for ln in target.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == 2
    for line in lines:
        assert json.loads(line)["tool"] == "omen"


def test_batch_default_still_streams_stdout(fixtures_dir, tmp_path, capsys):
    from omen.batch import run_batch

    list_file = tmp_path / "targets.txt"
    bin_path = str(fixtures_dir / "mixed-confidence.bin")
    list_file.write_text(f"{bin_path}\n")

    code = run_batch(
        path=str(list_file),
        input_type="bytecode",
        check="all",
    )
    assert code == 0
    lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
    assert len(lines) == 1
    assert json.loads(lines[0])["tool"] == "omen"


def test_batch_output_file_preserves_gate_exit(fixtures_dir, tmp_path, capsys):
    from omen.batch import run_batch

    list_file = tmp_path / "targets.txt"
    bin_path = str(fixtures_dir / "mixed-confidence.bin")
    list_file.write_text(f"{bin_path}\n")
    target = tmp_path / "out.jsonl"

    code = run_batch(
        path=str(list_file),
        input_type="bytecode",
        check="all",
        fail_on="high",
        output_file=str(target),
    )
    assert code == 3
    line = target.read_text(encoding="utf-8").strip()
    assert json.loads(line)["gate_triggered"] is True


# ---------------------------------------------------------------------------
# end-to-end subprocess — real file written by a real process
# ---------------------------------------------------------------------------


def test_subprocess_writes_file(fixtures_dir, tmp_path):
    target = tmp_path / "report.json"
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
            "--format",
            "json",
            "-o",
            str(target),
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    report = json.loads(target.read_text(encoding="utf-8"))
    assert report["tool"] == "omen"
