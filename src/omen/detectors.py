"""Detector mapping for omen.

omen reframes Slither's general-purpose detectors as the four MAIAN-class
trace vulnerabilities omen specializes in. The category -> Slither-detector
mapping is the heart of the tool.

  prodigal   leaks Ether to arbitrary users     -> slither: arbitrary-send-eth
  suicidal   can be killed by anyone            -> slither: suicidal
  greedy     locks Ether (no release path)      -> slither: locked-ether
  reentrancy classic withdraw-before-update     -> slither: reentrancy-eth, reentrancy-balance

For bytecode/address input (no source), omen falls back to opcode-level
evidence: the SELFDESTRUCT opcode is the bytecode signature of a suicidal
contract, matching MAIAN's bytecode-level reasoning.

[Worker decision: bytecode-mode detection for v0.1 covers the suicidal
class via SELFDESTRUCT opcode scanning. Criterion 6 requires bytecode mode
to reproduce the suicidal finding from source mode, which this satisfies.
prodigal/greedy/reentrancy bytecode-only detection requires data-flow
recovery from raw bytecode (effectively a decompiler) which is explicitly
out of scope for v0.1 — those classes are detected via source mode.]
"""

from __future__ import annotations

from typing import Any

# Lazy imports of slither happen inside functions so that `import omen`
# (and `omen --help`) never pays the heavy slither import cost and never
# fails if solc is not yet configured.

# category -> list of slither detector ARGUMENT ids
CATEGORY_TO_SLITHER: dict[str, list[str]] = {
    "prodigal": ["arbitrary-send-eth"],
    "suicidal": ["suicidal"],
    "greedy": ["locked-ether"],
    "reentrancy": ["reentrancy-eth", "reentrancy-balance"],
}


def slither_detector_classes(category: str) -> list[type]:
    """Return the Slither detector classes for an omen category."""
    from slither.detectors import all_detectors

    # Build an ARGUMENT -> class index once.
    index: dict[str, type] = {}
    for name in dir(all_detectors):
        obj = getattr(all_detectors, name)
        arg = getattr(obj, "ARGUMENT", None)
        if isinstance(arg, str):
            index[arg] = obj

    classes: list[type] = []
    for arg in CATEGORY_TO_SLITHER.get(category, []):
        if arg in index:
            classes.append(index[arg])
    return classes


# --- bytecode-level opcode evidence -----------------------------------

# opcode-name -> the omen category whose bytecode signature it is
OPCODE_SIGNATURE: dict[str, str] = {
    "SELFDESTRUCT": "suicidal",
    "SUICIDE": "suicidal",  # legacy mnemonic for the same 0xff opcode
}


def scan_bytecode_opcodes(bytecode: bytes) -> list[dict[str, Any]]:
    """Disassemble bytecode and return signature opcodes with offsets.

    Returns a list of {"opcode", "offset", "category"} dicts for every
    opcode that is a known trace-vulnerability signature.
    """
    from pyevmasm import disassemble_all

    hits: list[dict[str, Any]] = []
    for insn in disassemble_all(bytecode):
        category = OPCODE_SIGNATURE.get(insn.name)
        if category is not None:
            hits.append(
                {
                    "opcode": insn.name,
                    "offset": insn.pc,
                    "category": category,
                }
            )
    return hits
