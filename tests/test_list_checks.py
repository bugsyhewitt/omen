"""Tests for `--list-checks` detector catalog introspection.

POST_V01 Rotation 2, Rank 1. The catalog is pure introspection of omen's
in-code data structures, so these tests need no slither / solc / vyper / RPC —
they run fast and offline like the --help tests.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from omen import CATEGORIES
from omen.catalog import (
    BYTECODE_SUPPORTED_CATEGORIES,
    build_catalog,
    render,
    to_json,
    to_text,
)
from omen.detectors import CATEGORY_TO_SLITHER, VYPER_SUPPORTED_CATEGORIES
from omen.findings import DEFAULT_SEVERITY


def test_catalog_covers_every_category_exactly_once():
    catalog = build_catalog()
    listed = [c["category"] for c in catalog["checks"]]
    assert listed == list(CATEGORIES)
    assert catalog["check_count"] == len(CATEGORIES)


def test_catalog_severity_matches_default_severity():
    catalog = build_catalog()
    for entry in catalog["checks"]:
        assert (
            entry["default_severity"]
            == DEFAULT_SEVERITY[entry["category"]].value
        )


def test_catalog_slither_detectors_match_mapping():
    catalog = build_catalog()
    for entry in catalog["checks"]:
        assert (
            entry["slither_detectors"]
            == CATEGORY_TO_SLITHER[entry["category"]]
        )


def test_catalog_modes_reflect_language_and_bytecode_support():
    catalog = build_catalog()
    for entry in catalog["checks"]:
        cat = entry["category"]
        modes = entry["modes"]
        # Every category is reachable through Solidity source mode.
        assert modes[0] == "sol"
        assert ("vyper" in modes) == (cat in VYPER_SUPPORTED_CATEGORIES)
        has_bytecode = cat in BYTECODE_SUPPORTED_CATEGORIES
        assert ("bytecode" in modes) == has_bytecode
        assert ("address" in modes) == has_bytecode


def test_bytecode_supported_set_matches_analyzer():
    # Guard against drift: the categories the catalog claims run in bytecode
    # mode must be exactly the ones _analyze_bytecode actually branches on.
    assert BYTECODE_SUPPORTED_CATEGORIES == frozenset(
        {"suicidal", "prodigal", "greedy", "reentrancy"}
    )


def test_text_render_has_header_and_every_category():
    text = to_text(build_catalog())
    assert "CATEGORY" in text and "SEVERITY" in text and "SLITHER DETECTORS" in text
    for cat in CATEGORIES:
        assert cat in text
    # The non-obvious mappings should be discoverable in the listing.
    assert "protected-vars" in text  # access-control maps here, not "access-control"
    assert "weak-prng" in text


def test_json_render_is_valid_and_structured():
    payload = json.loads(to_json(build_catalog()))
    assert payload["tool"] == "omen"
    assert payload["check_count"] == len(CATEGORIES)
    assert isinstance(payload["checks"], list)
    assert {"category", "default_severity", "slither_detectors", "modes"} <= set(
        payload["checks"][0]
    )


def test_render_rejects_unknown_format():
    with pytest.raises(ValueError):
        render("xml")


def test_render_dispatches_text_and_json():
    assert render("text") == to_text(build_catalog())
    assert render("json") == to_json(build_catalog())


# --- CLI integration -------------------------------------------------------


def test_cli_list_checks_text_default():
    proc = subprocess.run(
        [sys.executable, "-m", "omen.cli", "--list-checks"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    assert "CATEGORY" in proc.stdout
    assert "prodigal" in proc.stdout


def test_cli_list_checks_json():
    proc = subprocess.run(
        [sys.executable, "-m", "omen.cli", "--list-checks", "--format", "json"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert payload["check_count"] == len(CATEGORIES)


def test_cli_list_checks_runs_without_target_or_input_type():
    # The whole point: no --contract, no --input-type, no compiler needed.
    proc = subprocess.run(
        [sys.executable, "-m", "omen.cli", "--list-checks"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    assert proc.stderr == ""


def test_cli_list_checks_rejects_scan_only_format():
    proc = subprocess.run(
        [sys.executable, "-m", "omen.cli", "--list-checks", "--format", "sarif"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2
    assert "text or json" in proc.stderr


def test_cli_scan_still_requires_target():
    proc = subprocess.run(
        [sys.executable, "-m", "omen.cli", "--input-type", "sol"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2
    assert "--contract or --batch is required" in proc.stderr


def test_cli_scan_still_requires_input_type():
    proc = subprocess.run(
        [sys.executable, "-m", "omen.cli", "--contract", "foo.sol"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2
    assert "--input-type is required" in proc.stderr
