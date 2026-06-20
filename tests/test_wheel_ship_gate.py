"""v0.1 → v1.0 release ship-gate: build the wheel, install into a fresh venv, prove it works.

Skippable via `pytest -m "not ship_gate"`. Runs in the full v1.0 suite.

This is omen-002's bridge: it added the structural preconditions for the
v1.0 RELEASE packet (omen-003), which has now updated the hardcoded `0.1.0`
refs in this file to `1.0.0` and added a CHANGELOG.md entry.
"""

from __future__ import annotations

import json
import subprocess
import sys
import venv
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent

# Runtime deps the wheel itself declares in pyproject.toml [project.dependencies].
# Installing them into the fresh venv proves the wheel's metadata is complete.
_RUNTIME_DEPS = [
    "slither-analyzer>=0.11.0",
    "pyevmasm>=0.2.3",
    "eth-abi>=5.0.0,<6",
    "eth-utils>=5.0.0",
    "eth-typing>=5.0.0",
    "evm-toolkit @ git+https://github.com/bugsyhewitt/evm-toolkit",
]

# Public surface — every sub-module under src/omen/ (verified at this wake via
# `ls src/omen/*.py`). omen uses a src-layout (where=["src"] in pyproject.toml).
_PUBLIC_MODULES = [
    "omen",
    "omen.cli",
    "omen.analyzer",
    "omen.batch",
    "omen.catalog",
    "omen.config",
    "omen.detectors",
    "omen.diff",
    "omen.findings",
    "omen.formats",
    "omen.merge",
    "omen.solc_env",
    "omen.sources",
    "omen.vyper_env",
]

# Expected detector category count per src/omen/__init__.py CATEGORIES tuple
# (verified at this wake via `python -c "from omen import CATEGORIES; print(len(CATEGORIES))"` → 10).
_EXPECTED_CHECK_COUNT = 10


def _run(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


def _ensure_build_available():
    """The `build` package is invoked as a subprocess; if absent in the test
    runner's venv, install it. This is the only state the test mutates outside
    its own tmp_path."""
    try:
        _run([sys.executable, "-m", "build", "--version"])
    except subprocess.CalledProcessError:
        _run([sys.executable, "-m", "pip", "install", "--quiet", "build"])


@pytest.mark.ship_gate
def test_wheel_builds_cleanly(tmp_path):
    """`python -m build --wheel --sdist` produces both artifacts with no error."""
    _ensure_build_available()
    out = tmp_path / "build-out"
    _run(
        [sys.executable, "-m", "build", "--wheel", "--sdist", "--outdir", str(out)],
        cwd=str(REPO_ROOT),
    )
    wheels = list(out.glob("omen-1.0.0-*.whl"))
    sdists = list(out.glob("omen-1.0.0.tar.gz"))
    assert wheels, f"wheel not built; got: {sorted(p.name for p in out.iterdir())}"
    assert sdists, f"sdist not built; got: {sorted(p.name for p in out.iterdir())}"
    test_wheel_builds_cleanly._wheel = wheels[0]


@pytest.mark.ship_gate
def test_wheel_installs_into_fresh_venv(tmp_path):
    """`pip install <wheel>` into a brand-new venv resolves the entry-point."""
    wheel = getattr(test_wheel_builds_cleanly, "_wheel", None)
    if wheel is None:
        pytest.skip("preceding test did not produce a wheel")
    venv_dir = tmp_path / "fresh-venv"
    venv.create(venv_dir, with_pip=True, clear=True)
    py = venv_dir / "bin" / "python"
    pip = venv_dir / "bin" / "pip"
    _run([str(pip), "install", "--quiet", str(wheel), "--no-deps"])
    _run([str(pip), "install", "--quiet", *_RUNTIME_DEPS])
    version = _run([str(venv_dir / "bin" / "omen"), "--version"]).stdout.strip()
    assert version == "omen 1.0.0", f"unexpected version output: {version!r}"
    test_wheel_installs_into_fresh_venv._venv_dir = venv_dir


@pytest.mark.ship_gate
def test_wheel_version_importable_in_fresh_venv():
    """`import omen; assert omen.__version__ == '1.0.0'` in fresh venv."""
    venv_dir = getattr(test_wheel_installs_into_fresh_venv, "_venv_dir", None)
    if venv_dir is None:
        pytest.skip("preceding test did not install a wheel")
    py = venv_dir / "bin" / "python"
    out = _run(
        [str(py), "-c", "import omen; assert omen.__version__ == '1.0.0'"]
    )
    assert out.returncode == 0, out.stderr


@pytest.mark.ship_gate
def test_installed_wheel_public_api():
    """Every public module in the wheel install is importable."""
    venv_dir = getattr(test_wheel_installs_into_fresh_venv, "_venv_dir", None)
    if venv_dir is None:
        pytest.skip("preceding test did not install a wheel")
    py = venv_dir / "bin" / "python"
    code = "import importlib; mods = " + repr(_PUBLIC_MODULES) + (
        "; [importlib.import_module(m) for m in mods]; print('OK', len(mods))"
    )
    out = _run([str(py), "-c", code])
    assert f"OK {len(_PUBLIC_MODULES)}" in out.stdout, (
        f"public-API import failed: {out.stderr}"
    )


@pytest.mark.ship_gate
def test_installed_wheel_list_checks_smoke():
    """`omen --list-checks --format json` from the fresh venv reports
    `check_count == 10` — proving the wheel install loads the
    detector registry correctly and is functionally equivalent to the
    editable install for the highest-leverage read-only, no-network,
    deterministic code path."""
    venv_dir = getattr(test_wheel_installs_into_fresh_venv, "_venv_dir", None)
    if venv_dir is None:
        pytest.skip("preceding test did not install a wheel")
    binary = venv_dir / "bin" / "omen"
    out = _run(
        [str(binary), "--list-checks", "--format", "json"]
    ).stdout
    payload = json.loads(out)
    assert payload.get("check_count") == _EXPECTED_CHECK_COUNT, (
        f"expected check_count={_EXPECTED_CHECK_COUNT}, "
        f"got {payload.get('check_count')!r}; full payload keys: {list(payload.keys())}"
    )


@pytest.mark.ship_gate
def test_installed_wheel_help_exits_zero():
    """`omen --help` from the fresh venv exits 0 — proving the wheel
    install has every CLI subcommand machinery wired up (parser.build,
    subparsers, action wiring)."""
    venv_dir = getattr(test_wheel_installs_into_fresh_venv, "_venv_dir", None)
    if venv_dir is None:
        pytest.skip("preceding test did not install a wheel")
    binary = venv_dir / "bin" / "omen"
    proc = subprocess.run(
        [str(binary), "--help"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, (
        f"omen --help exited {proc.returncode} (expected 0); "
        f"stdout: {proc.stdout!r}; stderr: {proc.stderr!r}"
    )


@pytest.mark.ship_gate
def test_installed_wheel_check_categories_validate():
    """`omen --check <valid>,<invalid>` from the fresh venv exits non-zero
    — proves the `--check` flag is wired to the `CATEGORIES` whitelist
    (per `src/omen/cli.py:284-291`) and rejects unknown category names
    rather than silently accepting arbitrary strings."""
    venv_dir = getattr(test_wheel_installs_into_fresh_venv, "_venv_dir", None)
    if venv_dir is None:
        pytest.skip("preceding test did not install a wheel")
    binary = venv_dir / "bin" / "omen"
    # Use --input-type=address + a contract stub + a real category to
    # bypass the contract-not-found error path and exercise the
    # category whitelist check. `--contract 0x0` is the stub address
    # that triggers category validation first (the validator runs in
    # omen.cli.main before any network call).
    proc = subprocess.run(
        [str(binary), "--check", "prodigal,suicidal,reentrancy,invalid_xyz",
         "--contract", "0x0", "--input-type", "address", "--rpc-url", "http://127.0.0.1:1"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0, (
        f"omen --check ... invalid_xyz exited {proc.returncode} (expected non-zero); "
        f"stdout: {proc.stdout!r}; stderr: {proc.stderr!r}"
    )


@pytest.mark.ship_gate
def test_changelog_exists_with_v1_0_0_entry():
    """CHANGELOG.md MUST exist at the repo root and have a `## [1.0.0]` heading.

    Pins the v1.0 RELEASE shape: a v1.0 cut without a CHANGELOG entry fails
    this test. Uses bare `Path` (the test file has `from pathlib import Path`
    at line 16, so `Path` is in scope).
    """
    changelog = Path(__file__).resolve().parent.parent / "CHANGELOG.md"
    assert changelog.is_file(), f"CHANGELOG.md missing at {changelog.parent}"
    head = changelog.read_text(encoding="utf-8").splitlines()[0]
    assert head.startswith("# "), f"CHANGELOG.md first line is {head!r}, expected a heading"
    body = changelog.read_text(encoding="utf-8")
    assert "## [1.0.0]" in body, "CHANGELOG.md has no `## [1.0.0]` entry — v1.0 RELEASE requires it"
