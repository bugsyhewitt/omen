"""Input loading for omen.

Three input modes:
  sol       a path to a .sol source file (analyzed by Slither, needs solc)
  bytecode  a path to a file holding hex EVM runtime bytecode (no solc)
  address   an on-chain contract address; bytecode is fetched via JSON-RPC

Address mode is gated on --rpc-url. omen NEVER submits transactions — it
only ever calls eth_getCode (read-only) to fetch deployed bytecode.

The EVM primitives — hex/bytes parsing, bytecode-file loading, and the
read-only eth_getCode fetch — are delegated to the shared `evm-toolkit`
library, which omen now shares with oracle. evm-toolkit's RPC client is
stdlib-only, so address mode no longer pulls in web3 just to read bytecode.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from evm_toolkit import (
    BytecodeError,
    RpcError,
    eth_get_code,
    is_address,
    load_bytecode_file,
    normalize_address,
)


class InputError(ValueError):
    """Raised when an input cannot be loaded or is malformed."""


@dataclass
class SourceInput:
    """A resolved input ready for analysis."""

    input_type: str  # "sol" | "bytecode" | "address"
    sol_path: str | None = None
    bytecode: bytes | None = None
    address: str | None = None
    origin: str = ""  # human-readable description of where this came from


def load_sol(path: str) -> SourceInput:
    p = Path(path)
    if not p.is_file():
        raise InputError(f"source file not found: {path}")
    if p.suffix.lower() not in (".sol",):
        # not fatal, but warn-by-error in v0.1 to keep modes honest
        raise InputError(f"expected a .sol file for --input-type sol, got: {path}")
    return SourceInput(input_type="sol", sol_path=str(p), origin=str(p))


def load_bytecode(path: str) -> SourceInput:
    try:
        code = load_bytecode_file(path)
    except BytecodeError as exc:
        # evm_toolkit raises a clear message for both missing files and bad
        # hex; re-wrap as omen's InputError to keep the CLI's error handling.
        raise InputError(str(exc)) from exc
    return SourceInput(input_type="bytecode", bytecode=code, origin=str(Path(path)))


def load_address(address: str, rpc_url: str | None) -> SourceInput:
    """Fetch deployed runtime bytecode for an address via JSON-RPC.

    Read-only: uses eth_getCode. Never submits a transaction.
    """
    if not rpc_url:
        raise InputError(
            "address mode requires --rpc-url to fetch the contract bytecode"
        )
    if not is_address(address):
        raise InputError(f"not a valid 0x-prefixed 20-byte address: {address}")

    checksum = normalize_address(address)
    try:
        code = eth_get_code(rpc_url, checksum)
    except RpcError as exc:
        raise InputError(str(exc)) from exc
    return SourceInput(
        input_type="address",
        bytecode=code,
        address=checksum,
        origin=f"{checksum} @ {rpc_url}",
    )


def load_input(
    contract: str, input_type: str, rpc_url: str | None
) -> SourceInput:
    """Dispatch to the right loader based on declared input type."""
    if input_type == "sol":
        return load_sol(contract)
    if input_type == "bytecode":
        return load_bytecode(contract)
    if input_type == "address":
        return load_address(contract, rpc_url)
    raise InputError(f"unknown input type: {input_type}")
