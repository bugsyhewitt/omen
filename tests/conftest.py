"""pytest fixtures and helpers for omen tests."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def _solc_present() -> bool:
    return shutil.which("solc") is not None


def _vyper_present() -> bool:
    return shutil.which("vyper") is not None


# Source-mode tests need solc on PATH. If it's missing, skip those tests
# with a clear reason rather than failing the suite. Bytecode/address tests
# never need solc and always run.
requires_solc = pytest.mark.skipif(
    not _solc_present(),
    reason="source-mode tests need a `solc` on PATH (solc-select install/use)",
)

# Vyper source-mode tests need the `vyper` binary on PATH (pip install vyper).
# They skip cleanly when it is absent, just like the solc-gated tests.
requires_vyper = pytest.mark.skipif(
    not _vyper_present(),
    reason="vyper source-mode tests need a `vyper` on PATH (pip install vyper)",
)


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES
