"""Input loading for omen.

Three input modes:
  sol       a path to a .sol source file (analyzed by Slither, needs solc)
  bytecode  a path to a file holding hex EVM runtime bytecode (no solc)
  address   an on-chain contract address; bytecode is fetched via JSON-RPC

Address mode is gated on --rpc-url. omen NEVER submits transactions — it
only ever calls eth_getCode (read-only) to fetch deployed bytecode.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


class InputError(ValueError):
    """Raised when an input cannot be loaded or is malformed."""


_HEX_RE = re.compile(r"^(0x)?[0-9a-fA-F]*$")


def _clean_hex(text: str) -> bytes:
    """Parse a hex string (with optional 0x prefix / whitespace) to bytes."""
    text = "".join(text.split())
    if not text:
        raise InputError("empty bytecode")
    if not _HEX_RE.match(text):
        raise InputError("input is not valid hex bytecode")
    if text.startswith(("0x", "0X")):
        text = text[2:]
    if len(text) % 2 != 0:
        raise InputError("hex bytecode has an odd number of nibbles")
    return bytes.fromhex(text)


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
    p = Path(path)
    if not p.is_file():
        raise InputError(f"bytecode file not found: {path}")
    raw = p.read_text(encoding="utf-8", errors="strict")
    code = _clean_hex(raw)
    return SourceInput(
        input_type="bytecode", bytecode=code, origin=str(p)
    )


def load_address(address: str, rpc_url: str | None) -> SourceInput:
    """Fetch deployed runtime bytecode for an address via JSON-RPC.

    Read-only: uses eth_getCode. Never submits a transaction.
    """
    if not rpc_url:
        raise InputError(
            "address mode requires --rpc-url to fetch the contract bytecode"
        )
    address = address.strip()
    if not re.match(r"^0x[0-9a-fA-F]{40}$", address):
        raise InputError(f"not a valid 0x-prefixed 20-byte address: {address}")

    from web3 import Web3

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    checksum = Web3.to_checksum_address(address)
    code = bytes(w3.eth.get_code(checksum))
    if not code:
        raise InputError(
            f"no bytecode at {address} via {rpc_url} "
            "(is it a contract, and is the RPC reachable?)"
        )
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
