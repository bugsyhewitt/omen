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
        "--input-type",
        "--check",
        "--rpc-url",
        "--format",
    ):
        assert token in text, f"--help missing {token}"


def test_help_lists_input_type_choices():
    text = _help_text()
    for choice in ("sol", "bytecode", "address"):
        assert choice in text


def test_help_lists_check_choices():
    text = _help_text()
    for choice in ("prodigal", "suicidal", "greedy", "reentrancy", "all"):
        assert choice in text


def test_help_lists_format_choices():
    text = _help_text()
    assert "json" in text and "h1md" in text


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
