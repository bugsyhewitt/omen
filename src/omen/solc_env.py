"""solc environment management for source-mode analysis.

Source-mode analysis compiles Solidity, which requires a `solc` binary on
PATH. omen depends on solc-select (pulled in transitively by slither) to
provide and select solc versions.

[Worker decision: omen does NOT bundle a solc binary (criterion: "no solc
runtime dependency for v0.1 *tests*" applies to bytecode mode, not source
mode). Source mode requires the user to have a solc available. omen makes
this ergonomic: if solc-select has a version installed/selected, omen uses
it; otherwise it raises a clear, actionable error. Bytecode and address
modes never touch solc.]

solc discovery now lives in the shared `evm-toolkit` library (shared with
oracle). This module is a thin, omen-named adapter so existing imports
(`from omen.solc_env import require_solc, SolcUnavailableError`) keep working.
"""

from __future__ import annotations

from dataclasses import dataclass

# SolcUnavailableError is re-exported from evm_toolkit so that `except
# SolcUnavailableError` callers (analyzer, cli) catch the same class the
# shared discovery raises.
from evm_toolkit import SolcUnavailableError as SolcUnavailableError
from evm_toolkit import find_solc
from evm_toolkit.source import solc_status as _solc_status


@dataclass
class SolcStatus:
    available: bool
    path: str | None


def solc_status() -> SolcStatus:
    """Report whether a `solc` binary is reachable on PATH."""
    status = _solc_status()
    return SolcStatus(available=status.available, path=status.path)


def require_solc() -> str:
    """Return the path to a usable solc, or raise SolcUnavailableError.

    Delegates to evm_toolkit.find_solc, whose error message points the user at
    solc-select (bundled via slither).
    """
    return find_solc()
