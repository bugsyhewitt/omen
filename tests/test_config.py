"""Tests for the --config TOML config-file flag (POST_V01 Rotation 2, R2.10).

R2.1–R2.9 grew omen to ~a dozen flags. --config loads a TOML file that sets
*default* values for those flags so a repo can commit one omen.toml and shrink
every invocation. The contract under test:

  - A flat name->value map under [omen] or at the top level.
  - Keys are flag names (dashes or underscores both accepted); 'o' aliases
    output_file.
  - Values validated against the same choices the CLI enforces.
  - CLI flags always override the file; the file overrides built-in defaults.

These tests use the synthetic bytecode fixture and the pure config loader, so
they run with no solc/vyper dependency.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from omen.cli import build_parser, main
from omen.config import ConfigError, load_config


# ---------------------------------------------------------------------------
# load_config — the pure loader
# ---------------------------------------------------------------------------


def _write(tmp_path: Path, text: str, name: str = "omen.toml") -> str:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return str(p)


def test_load_toplevel_keys(tmp_path):
    cfg = load_config(_write(tmp_path, 'min_severity = "high"\nsort = "none"\n'))
    assert cfg == {"min_severity": "high", "sort": "none"}


def test_load_omen_table(tmp_path):
    cfg = load_config(_write(tmp_path, '[omen]\nformat = "sarif"\nlimit = 5\n'))
    assert cfg == {"format": "sarif", "limit": 5}


def test_dashed_keys_normalized_to_underscore(tmp_path):
    cfg = load_config(_write(tmp_path, '"min-confidence" = "high"\n"fail-on" = "high"\n'))
    assert cfg == {"min_confidence": "high", "fail_on": "high"}


def test_o_alias_maps_to_output_file(tmp_path):
    cfg = load_config(_write(tmp_path, 'o = "report.json"\n'))
    assert cfg == {"output_file": "report.json"}


def test_output_file_dashed_key(tmp_path):
    cfg = load_config(_write(tmp_path, '"output-file" = "r.json"\n'))
    assert cfg == {"output_file": "r.json"}


def test_omen_table_wins_over_toplevel(tmp_path):
    # When an [omen] table exists, top-level keys outside it are ignored, so a
    # shared config file's other tables/keys don't bleed in.
    cfg = load_config(
        _write(tmp_path, 'sort = "severity"\n[omen]\nsort = "none"\n')
    )
    assert cfg == {"sort": "none"}


def test_empty_file_is_empty_map(tmp_path):
    assert load_config(_write(tmp_path, "")) == {}


def test_nested_other_tool_table_ignored_at_toplevel(tmp_path):
    cfg = load_config(
        _write(tmp_path, 'min_severity = "low"\n[othertool]\nfoo = "bar"\n')
    )
    assert cfg == {"min_severity": "low"}


def test_missing_file_raises(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(str(tmp_path / "nope.toml"))


def test_invalid_toml_raises(tmp_path):
    with pytest.raises(ConfigError, match="invalid TOML"):
        load_config(_write(tmp_path, "this is = = not toml"))


def test_unknown_key_raises(tmp_path):
    with pytest.raises(ConfigError, match="unknown key"):
        load_config(_write(tmp_path, 'bogus = "x"\n'))


def test_bad_choice_value_raises(tmp_path):
    with pytest.raises(ConfigError, match="min_severity must be one of"):
        load_config(_write(tmp_path, 'min_severity = "spicy"\n'))


def test_limit_must_be_positive_int(tmp_path):
    with pytest.raises(ConfigError, match="positive integer"):
        load_config(_write(tmp_path, "limit = 0\n"))


def test_limit_rejects_bool(tmp_path):
    with pytest.raises(ConfigError, match="positive integer"):
        load_config(_write(tmp_path, "limit = true\n"))


def test_limit_rejects_string(tmp_path):
    with pytest.raises(ConfigError, match="positive integer"):
        load_config(_write(tmp_path, 'limit = "5"\n'))


def test_choice_value_must_be_string(tmp_path):
    with pytest.raises(ConfigError, match="must be a string"):
        load_config(_write(tmp_path, "sort = 3\n"))


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def test_help_lists_config():
    assert "--config" in build_parser().format_help()


def test_default_config_is_none():
    args = build_parser().parse_args(
        ["--contract", "x.bin", "--input-type", "bytecode"]
    )
    assert args.config is None


# ---------------------------------------------------------------------------
# main() — config supplies defaults, CLI overrides
# ---------------------------------------------------------------------------


def _scan_args(fixtures_dir: Path, *extra: str) -> list[str]:
    return [
        "--contract",
        str(fixtures_dir / "mixed-confidence.bin"),
        "--input-type",
        "bytecode",
        *extra,
    ]


def test_config_supplies_fail_on_gate(fixtures_dir, tmp_path, capsys):
    # The fixture surfaces a high finding; a config-set fail_on=high must trip
    # the gate (exit 3) with no --fail-on on the command line.
    cfg = _write(tmp_path, 'fail_on = "high"\n')
    code = main(_scan_args(fixtures_dir, "--config", cfg))
    capsys.readouterr()
    assert code == 3


def test_cli_flag_overrides_config(fixtures_dir, tmp_path, capsys):
    # Config says fail on high, but the CLI explicitly says never — CLI wins,
    # so the run is clean (exit 0).
    cfg = _write(tmp_path, 'fail_on = "high"\n')
    code = main(_scan_args(fixtures_dir, "--config", cfg, "--fail-on", "never"))
    capsys.readouterr()
    assert code == 0


def test_config_supplies_output_file(fixtures_dir, tmp_path, capsys):
    target = tmp_path / "out.json"
    cfg = _write(tmp_path, f'output_file = "{target}"\ncheck = "all"\n')
    code = main(_scan_args(fixtures_dir, "--config", cfg))
    assert code == 0
    assert capsys.readouterr().out == ""
    report = json.loads(target.read_text(encoding="utf-8"))
    assert report["tool"] == "omen"


def test_config_supplies_format_text(fixtures_dir, tmp_path, capsys):
    cfg = _write(tmp_path, 'format = "text"\ncheck = "all"\n')
    code = main(_scan_args(fixtures_dir, "--config", cfg))
    assert code == 0
    out = capsys.readouterr().out
    # text format is human output, not JSON.
    with pytest.raises(json.JSONDecodeError):
        json.loads(out)


def test_config_supplies_contract_and_input_type(fixtures_dir, tmp_path, capsys):
    # A config file can drive the whole scan: target + input type from the file,
    # nothing but --config on the command line.
    bin_path = fixtures_dir / "mixed-confidence.bin"
    cfg = _write(
        tmp_path,
        f'contract = "{bin_path}"\ninput_type = "bytecode"\ncheck = "all"\n',
    )
    code = main(["--config", cfg])
    out = capsys.readouterr().out
    assert code in (0, 3)  # clean or gated; both mean it ran
    assert json.loads(out)["tool"] == "omen"


def test_bad_config_value_is_usage_error(fixtures_dir, tmp_path, capsys):
    cfg = _write(tmp_path, 'min_severity = "spicy"\n')
    with pytest.raises(SystemExit) as exc:
        main(_scan_args(fixtures_dir, "--config", cfg))
    assert exc.value.code == 2
    assert "min_severity" in capsys.readouterr().err


def test_missing_config_is_usage_error(fixtures_dir, tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        main(_scan_args(fixtures_dir, "--config", str(tmp_path / "nope.toml")))
    assert exc.value.code == 2
    assert "not found" in capsys.readouterr().err


def test_config_check_validated_after_merge(fixtures_dir, tmp_path, capsys):
    # A bad category in the config's `check` is caught by the same resolve_checks
    # path a bad CLI --check hits — exit 2, not a runtime crash.
    cfg = _write(tmp_path, 'check = "not-a-category"\n')
    with pytest.raises(SystemExit) as exc:
        main(_scan_args(fixtures_dir, "--config", cfg))
    assert exc.value.code == 2


# ---------------------------------------------------------------------------
# end-to-end subprocess — a real omen.toml drives a real process
# ---------------------------------------------------------------------------


def test_subprocess_config_drives_scan(fixtures_dir, tmp_path):
    bin_path = fixtures_dir / "mixed-confidence.bin"
    out = tmp_path / "report.json"
    cfg = tmp_path / "omen.toml"
    cfg.write_text(
        "[omen]\n"
        f'contract = "{bin_path}"\n'
        'input_type = "bytecode"\n'
        'check = "all"\n'
        'format = "json"\n'
        f'output_file = "{out}"\n',
        encoding="utf-8",
    )
    proc = subprocess.run(
        [sys.executable, "-m", "omen.cli", "--config", str(cfg)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode in (0, 3), proc.stderr
    assert proc.stdout == ""
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["tool"] == "omen"
