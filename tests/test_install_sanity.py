"""v0.1 editable-install ship-gate: the dev venv's .pth must resolve to a real src/.

Three checks:
  1. The editable-install .pth file points to an existing directory.
  2. `import omen` from the dev venv resolves to <REPO>/src/omen/__init__.py.
  3. `pip install -e . --no-deps` repairs a stale .pth in place.

Skippable via `pytest -m "not install_sanity"`. Runs in the full v0.1 suite.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"


def _find_editable_pth() -> Path | None:
    """Locate the .pth file omen's editable install wrote."""
    # setuptools >=64 writes __editable__.<name>-<version>.pth; older writes a
    # plain .pth. Check both shapes.
    site = (
        Path(sys.prefix)
        / "lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
    )
    candidates = list(site.glob("__editable__*omen*.pth")) + list(
        site.glob("omen*.pth")
    )
    # Prefer the editable-form one (it's the modern shape and is what the
    # project's pyproject.toml produces).
    editable = [p for p in candidates if "__editable__" in p.name]
    return (editable or candidates)[0] if candidates else None


@pytest.mark.install_sanity
def test_editable_install_pth_points_to_existing_src():
    """The .pth file written by `pip install -e .` must point to a real directory
    that contains the `omen/` package."""
    pth = _find_editable_pth()
    if pth is None:
        pytest.skip("omen not installed in this venv (run `pip install -e .`)")
    target = Path(pth.read_text().strip())
    assert target.is_dir(), (
        f"editable-install .pth points to missing dir: {target} "
        f"(run `pip install -e .` from {REPO_ROOT} to repair)"
    )
    assert (target / "omen" / "__init__.py").is_file(), (
        f".pth target {target} exists but does not contain omen/__init__.py — "
        f"the editable install is wired to the wrong tree"
    )


@pytest.mark.install_sanity
def test_editable_install_imports_resolve_to_repo_src():
    """`import omen` from this venv must resolve to a file under REPO_ROOT/src/."""
    import omen  # noqa: F401  (this is the test)

    src_file = Path(omen.__file__).resolve()
    assert src_file.is_relative_to(SRC / "omen"), (
        f"import omen resolved to {src_file}, not under {SRC}/omen — "
        f"the editable install is pointing at the wrong tree"
    )
    assert omen.__version__ == "0.1.0", (
        f"__version__ is {omen.__version__!r}, expected '0.1.0' — "
        f"pyproject.toml and src/omen/__init__.py disagree"
    )


@pytest.mark.install_sanity
def test_pip_install_e_refreshes_stale_pth():
    """If the .pth is stale, `pip install -e . --no-deps` from REPO_ROOT
    must repair it in place. Proves the recovery step works without
    requiring the executor to debug Python's site machinery."""
    pth = _find_editable_pth()
    if pth is None:
        pytest.skip("omen not installed in this venv (run `pip install -e .`)")
    target = Path(pth.read_text().strip())
    if target.is_dir():
        pytest.skip(".pth already points to a real directory")
    # Stale .pth detected — repair it and re-check.
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "-e", ".", "--quiet", "--no-deps"],
        check=True,
        cwd=str(REPO_ROOT),
    )
    target_after = Path(pth.read_text().strip())
    assert target_after.is_dir(), (
        f"`pip install -e .` did not repair the .pth: still points to {target_after}"
    )
    assert target_after.resolve() == SRC.resolve(), (
        f".pth now points to {target_after}, expected {SRC}"
    )
