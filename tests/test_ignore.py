"""Tests for the --ignore batch path/pattern exclusion (POST_V01 Rotation 2, R2.11).

R2.7/R2.8 scoped a scan by *vulnerability class* (--check / --exclude-check);
R2.11 scopes a --batch scan by *path*. ``--ignore PATTERN[,PATTERN...]`` is a
comma-separated list of fnmatch-style globs; any contract path/address a batch
scan would otherwise visit that matches one is skipped before analysis. The
motivating case is a whole-repo scan that should not pull in vendored/third-party
code (``node_modules``, ``lib``, an OpenZeppelin import tree) — ``--ignore
node_modules,lib,test`` drops those without hand-pruning the input.

These tests cover the shared parse_ignore primitive, the _is_ignored matching
rules (full path, single component, sub-path, globs), the _iter_items filtering
in both directory and list-file modes, run_batch forwarding (mocked analyze),
the config-file key, and the CLI surface (help + exit-2 on an all-blank value +
single-contract no-op).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from omen.batch import _is_ignored, _iter_items, parse_ignore, run_batch
from omen.cli import build_parser


# --- parse_ignore: the value parser -----------------------------------------


def test_parse_ignore_none_is_empty():
    """The flag default (None) yields no patterns — no exclusion."""
    assert parse_ignore(None) == []


def test_parse_ignore_single_pattern():
    assert parse_ignore("node_modules") == ["node_modules"]


def test_parse_ignore_comma_list():
    assert parse_ignore("node_modules,lib,test") == ["node_modules", "lib", "test"]


def test_parse_ignore_strips_whitespace_around_patterns():
    """Whitespace around comma-separated patterns is stripped."""
    assert parse_ignore("node_modules, lib , test") == [
        "node_modules",
        "lib",
        "test",
    ]


def test_parse_ignore_drops_empty_entries_among_real_ones():
    """Empty entries between real patterns are dropped (trailing comma is fine)."""
    assert parse_ignore("lib,,test,") == ["lib", "test"]


def test_parse_ignore_all_blank_raises():
    """A non-empty value with no usable patterns is a usage error, not silent."""
    with pytest.raises(ValueError, match="no usable patterns"):
        parse_ignore(",, ")


def test_parse_ignore_empty_string_is_empty():
    """An empty string yields no patterns (equivalent to the None default)."""
    assert parse_ignore("") == []


# --- _is_ignored: the matching rules ----------------------------------------


def test_is_ignored_empty_patterns_never_matches():
    assert _is_ignored("anything/at/all.sol", []) is False


def test_is_ignored_matches_single_path_component():
    """A bare directory name excludes any path containing it as a component."""
    assert _is_ignored("repo/node_modules/Foo.sol", ["node_modules"]) is True


def test_is_ignored_no_match_for_unrelated_path():
    assert _is_ignored("repo/src/Token.sol", ["node_modules"]) is False


def test_is_ignored_matches_full_path_glob():
    assert _is_ignored("repo/test/A.t.sol", ["*.t.sol"]) is True


def test_is_ignored_subpath_pattern_with_separator():
    """A pattern containing '/' matches anywhere in the path (sub-path)."""
    assert _is_ignored(
        "repo/lib/openzeppelin/Foo.sol", ["lib/openzeppelin"]
    ) is True


def test_is_ignored_question_mark_glob():
    assert _is_ignored("repo/V1.sol", ["V?.sol"]) is True


def test_is_ignored_seq_glob():
    assert _is_ignored("repo/Mock1.sol", ["Mock[0-9].sol"]) is True


def test_is_ignored_any_of_multiple_patterns():
    """A path is ignored if it matches ANY pattern (OR semantics)."""
    patterns = ["node_modules", "lib", "test"]
    assert _is_ignored("repo/lib/X.sol", patterns) is True
    assert _is_ignored("repo/src/X.sol", patterns) is False


def test_is_ignored_matches_address_in_list():
    """List-file items (addresses) are matched too, not just paths."""
    addr = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    assert _is_ignored(addr, [addr]) is True
    assert _is_ignored(addr, ["0xBBB*"]) is False


# --- _iter_items: directory mode filtering ----------------------------------


def test_iter_items_directory_excludes_ignored_dir(tmp_path: Path):
    """A recursive directory scan skips files under an ignored component."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Token.sol").write_text("// token")
    nm = tmp_path / "node_modules"
    nm.mkdir()
    (nm / "Vendor.sol").write_text("// vendor")

    items = list(_iter_items(str(tmp_path), "sol", ["node_modules"]))
    names = [Path(i).name for i in items]
    assert names == ["Token.sol"]


def test_iter_items_directory_no_ignore_keeps_all(tmp_path: Path):
    """Without ignore patterns, behaviour is unchanged (all .sol files)."""
    (tmp_path / "a.sol").write_text("// a")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "b.sol").write_text("// b")

    items = list(_iter_items(str(tmp_path), "sol"))
    assert len(items) == 2


def test_iter_items_directory_multiple_ignores(tmp_path: Path):
    """Several ignored trees are all dropped in one scan."""
    for d in ("src", "lib", "test"):
        (tmp_path / d).mkdir()
        (tmp_path / d / "C.sol").write_text("// c")

    items = list(_iter_items(str(tmp_path), "sol", ["lib", "test"]))
    names = [str(Path(i).parent.name) for i in items]
    assert names == ["src"]


# --- _iter_items: list-file mode filtering ----------------------------------


def test_iter_items_list_file_excludes_ignored_paths(tmp_path: Path):
    """A list file of paths drops ignored entries."""
    list_file = tmp_path / "list.txt"
    list_file.write_text(
        "contracts/src/Token.sol\n"
        "contracts/lib/Vendor.sol\n"
        "contracts/src/Vault.sol\n"
    )
    items = list(_iter_items(str(list_file), "sol", ["lib"]))
    assert items == ["contracts/src/Token.sol", "contracts/src/Vault.sol"]


def test_iter_items_list_file_excludes_ignored_addresses(tmp_path: Path):
    """A list file of addresses drops ignored entries by glob."""
    keep = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    drop = "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    list_file = tmp_path / "addrs.txt"
    list_file.write_text(f"{keep}\n{drop}\n")
    items = list(_iter_items(str(list_file), "address", [drop]))
    assert items == [keep]


# --- run_batch: forwarding (mocked analyze) ---------------------------------


def _make_report(origin: str = "test.sol") -> MagicMock:
    report = MagicMock()
    report.gate_triggered = False
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


def test_run_batch_skips_ignored_files(
    tmp_path: Path, capsys: pytest.CaptureFixture
):
    """run_batch analyzes only the non-ignored files (one JSONL line each)."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Keep.sol").write_text("// keep")
    nm = tmp_path / "node_modules"
    nm.mkdir()
    (nm / "Skip.sol").write_text("// skip")

    analyzed: list[str] = []

    def side_effect(contract, **kwargs):
        analyzed.append(contract)
        return _make_report(contract)

    with patch("omen.batch.analyze", side_effect=side_effect):
        exit_code = run_batch(
            str(tmp_path), "sol", "all", ignore="node_modules"
        )

    # analyze called once, only for the kept file
    assert len(analyzed) == 1
    assert Path(analyzed[0]).name == "Keep.sol"
    assert exit_code == 0

    lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
    assert len(lines) == 1


def test_run_batch_ignore_none_is_no_op(
    tmp_path: Path, capsys: pytest.CaptureFixture
):
    """Default ignore=None preserves the historical "scan everything" behaviour."""
    (tmp_path / "a.sol").write_text("// a")
    (tmp_path / "b.sol").write_text("// b")

    with patch("omen.batch.analyze", side_effect=lambda contract, **kw: _make_report(contract)):
        exit_code = run_batch(str(tmp_path), "sol", "all")

    lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
    assert len(lines) == 2
    assert exit_code == 0


def test_run_batch_ignore_all_blank_raises(tmp_path: Path):
    """An all-blank --ignore value surfaces as a ValueError before any scan."""
    (tmp_path / "a.sol").write_text("// a")
    with pytest.raises(ValueError, match="no usable patterns"):
        run_batch(str(tmp_path), "sol", "all", ignore=",,")


# --- config-file key --------------------------------------------------------


def test_config_accepts_ignore_key(tmp_path: Path):
    """omen.toml may set `ignore` as a comma-list string."""
    from omen.config import load_config

    cfg_file = tmp_path / "omen.toml"
    cfg_file.write_text('ignore = "node_modules,lib"\n')
    cfg = load_config(str(cfg_file))
    assert cfg["ignore"] == "node_modules,lib"


def test_config_ignore_non_string_rejected(tmp_path: Path):
    """A non-string `ignore` value is a file-named ConfigError."""
    from omen.config import ConfigError, load_config

    cfg_file = tmp_path / "omen.toml"
    cfg_file.write_text("ignore = 42\n")
    with pytest.raises(ConfigError, match="ignore"):
        load_config(str(cfg_file))


# --- CLI surface ------------------------------------------------------------


def test_cli_help_includes_ignore():
    """--ignore appears in the CLI help text."""
    text = build_parser().format_help()
    assert "--ignore" in text


def test_cli_ignore_parses_into_namespace():
    """argparse accepts --ignore and stores the raw comma-list string."""
    args = build_parser().parse_args(
        ["--batch", "/tmp", "--input-type", "sol", "--ignore", "lib,test"]
    )
    assert args.ignore == "lib,test"


def test_cli_ignore_default_is_none():
    args = build_parser().parse_args(
        ["--batch", "/tmp", "--input-type", "sol"]
    )
    assert args.ignore is None


def test_cli_ignore_all_blank_is_exit_2():
    """A --ignore value with no usable patterns is an argparse-style usage error."""
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "omen.cli",
            "--batch",
            "/tmp",
            "--input-type",
            "sol",
            "--ignore",
            ",, ",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2
    assert "no usable patterns" in proc.stderr


def test_cli_ignore_noop_in_single_contract_mode(tmp_path: Path):
    """--ignore is accepted but a no-op for a single --contract scan (bytecode mode)."""
    bin_file = tmp_path / "c.bin"
    bin_file.write_text("0x6080604052")
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
            "--ignore",
            "node_modules",
        ],
        capture_output=True,
        text=True,
    )
    # Bytecode mode needs no compiler/network; --ignore must not break the scan.
    assert proc.returncode == 0
    parsed = json.loads(proc.stdout)
    assert parsed["tool"] == "omen"
