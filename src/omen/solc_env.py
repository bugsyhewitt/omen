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
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass


class SolcUnavailableError(RuntimeError):
    """Raised when source-mode analysis is requested but no solc is on PATH."""


@dataclass
class SolcStatus:
    available: bool
    path: str | None


def solc_status() -> SolcStatus:
    """Report whether a `solc` binary is reachable on PATH."""
    path = shutil.which("solc")
    return SolcStatus(available=path is not None, path=path)


def require_solc() -> str:
    """Return the path to a usable solc, or raise SolcUnavailableError.

    The error message tells the user exactly how to fix it using
    solc-select, which ships as a dependency of slither.
    """
    status = solc_status()
    if status.available and status.path is not None:
        return status.path
    raise SolcUnavailableError(
        "source-mode analysis needs a `solc` binary on PATH but none was found.\n"
        "Install and select one with solc-select (bundled via slither):\n"
        "    solc-select install 0.8.19\n"
        "    solc-select use 0.8.19\n"
        "Or analyze EVM bytecode / an on-chain address instead "
        "(--input-type bytecode | address), which needs no solc."
    )
