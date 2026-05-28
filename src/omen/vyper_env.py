"""vyper environment management for Vyper source-mode analysis.

Vyper source-mode analysis (POST_V01 Rank 6) compiles `.vy` files, which
requires a `vyper` binary on PATH. Slither delegates Vyper compilation to
crytic-compile, which shells out to whichever `vyper` it finds on PATH — so
omen's responsibility is purely to detect a missing/usable `vyper` up front
and raise a clear, actionable error instead of letting a deep crytic-compile
stack trace surface.

[Worker decision (R7, POST_V01 Rank 6): omen does NOT bundle or pin a `vyper`
binary. Unlike solc, there is no `solc-select` equivalent shipped transitively
by Slither for Vyper, so omen cannot auto-provision one. The contract is: if a
`vyper` is on PATH, omen uses it; otherwise it raises VyperUnavailableError
pointing the user at `pip install vyper`. Solidity, bytecode, and address modes
never touch `vyper`. The discovery is intentionally a thin stdlib-only
`shutil.which` rather than a new evm-toolkit dependency — evm-toolkit currently
exposes only solc discovery, and adding a Vyper finder there is out of scope
for a single focused omen improvement.]
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass


class VyperUnavailableError(RuntimeError):
    """Raised when Vyper source mode is requested but no `vyper` is on PATH."""


_INSTALL_HINT = (
    "Vyper source mode (--input-type vyper) needs a `vyper` binary on PATH. "
    "Install it with `pip install vyper` (or `pipx install vyper`) and re-run. "
    "Solidity, bytecode, and address modes do not require vyper."
)


@dataclass
class VyperStatus:
    available: bool
    path: str | None


def vyper_status() -> VyperStatus:
    """Report whether a `vyper` binary is reachable on PATH."""
    path = shutil.which("vyper")
    return VyperStatus(available=path is not None, path=path)


def require_vyper() -> str:
    """Return the path to a usable `vyper`, or raise VyperUnavailableError."""
    path = shutil.which("vyper")
    if path is None:
        raise VyperUnavailableError(_INSTALL_HINT)
    return path
