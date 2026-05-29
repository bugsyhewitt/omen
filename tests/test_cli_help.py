"""CLI surface tests: --help and --version (criterion 2)."""

from __future__ import annotations

import subprocess
import sys

import pytest

from omen.cli import build_parser


def _help_text() -> str:
    parser = build_parser()
    return parser.format_help()


def test_help_lists_required_flags():
    text = _help_text()
    for token in (
        "--contract",
        "--batch",
        "--input-type",
        "--check",
        "--rpc-url",
        "--format",
    ):
        assert token in text, f"--help missing {token}"


def test_help_lists_input_type_choices():
    text = _help_text()
    for choice in ("sol", "vyper", "bytecode", "address"):
        assert choice in text


def test_help_lists_check_choices():
    text = _help_text()
    for choice in ("prodigal", "suicidal", "greedy", "reentrancy", "all"):
        assert choice in text


def test_help_lists_format_choices():
    text = _help_text()
    assert "json" in text and "h1md" in text and "sarif" in text
    # text format (POST_V01 Rotation 2, R2.6) is a scan output choice too.
    assert "text" in text
    # gha format (POST_V01 R3.5): GitHub Actions workflow-command annotations.
    assert "gha" in text


def test_text_format_scan_runs_end_to_end():
    # Bytecode mode needs no compiler, so --format text is exercisable in CI.
    from pathlib import Path

    fixtures = Path(__file__).parent / "fixtures"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "omen.cli",
            "--contract",
            str(fixtures / "compiled.bin"),
            "--input-type",
            "bytecode",
            "--check",
            "suicidal",
            "--format",
            "text",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    # text output is the compact terminal view, not JSON.
    assert not out.lstrip().startswith("{")
    assert out.startswith("omen ")
    assert "findings:" in out
    assert "suicidal" in out
    assert "HIGH" in out


def test_gha_format_scan_runs_end_to_end():
    # Bytecode mode needs no compiler, so --format gha is exercisable in CI.
    from pathlib import Path

    fixtures = Path(__file__).parent / "fixtures"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "omen.cli",
            "--contract",
            str(fixtures / "compiled.bin"),
            "--input-type",
            "bytecode",
            "--check",
            "suicidal",
            "--format",
            "gha",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    # gha output is one workflow command per line (or a single ::notice when
    # there are no findings) — never JSON.
    assert not out.lstrip().startswith("{")
    for line in out.splitlines():
        assert line.startswith("::"), f"non-command line in gha output: {line!r}"


def test_cli_help_runs_as_subprocess():
    # The installed entry point must print usage and exit 0.
    proc = subprocess.run(
        [sys.executable, "-m", "omen.cli", "--help"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    assert "--contract" in proc.stdout


def test_address_mode_requires_rpc_url():
    # argparse error path -> exit code 2.
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "omen.cli",
            "--contract",
            "0x" + "00" * 20,
            "--input-type",
            "address",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2
    assert "rpc-url" in (proc.stderr.lower())
