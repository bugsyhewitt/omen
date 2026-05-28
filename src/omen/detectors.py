"""Detector mapping for omen.

omen reframes Slither's general-purpose detectors as the four MAIAN-class
trace vulnerabilities omen specializes in. The category -> Slither-detector
mapping is the heart of the tool.

  prodigal       leaks Ether to arbitrary users     -> slither: arbitrary-send-eth
  suicidal       can be killed by anyone            -> slither: suicidal
  greedy         locks Ether (no release path)      -> slither: locked-ether
  reentrancy     classic withdraw-before-update     -> slither: reentrancy-eth, reentrancy-balance
  access-control missing/incorrect access checks    -> slither: protected-vars, events-access
  tx-origin      tx.origin used for authentication  -> slither: tx-origin

For bytecode/address input (no source), omen falls back to opcode-level
evidence: the SELFDESTRUCT opcode is the bytecode signature of a suicidal
contract, matching MAIAN's bytecode-level reasoning.

[Worker decision: bytecode-mode detection for v0.1 covered only the
suicidal class via SELFDESTRUCT opcode scanning (high confidence). POST_V01
Rank 1 (R3) adds coarse opcode-pattern heuristics for prodigal, greedy, and
reentrancy so that on-chain, source-unverified contracts produce triage
leads instead of silent misses. Those heuristics report at LOW confidence
with an explicit "source-mode is more precise" caveat — they intentionally
trade precision for address-mode recall rather than attempting full
data-flow recovery (a decompiler), which remains out of scope.]
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
    # [Worker decision (R2, POST_V01 Rank 2): the roadmap proposed mapping
    # access-control onto a Slither detector literally named "access-control".
    # No such ARGUMENT exists in slither-analyzer 0.11.x — Slither has no single
    # "access-control" detector; the access-control concept is split across
    # several detectors. The two that flag missing/incorrect access restrictions
    # without overlapping omen's existing categories are:
    #   - protected-vars: state vars that should be protected but are writable
    #     by an unguarded function (the core "missing onlyOwner" signal).
    #   - events-access: admin/access-control changes that fail to emit events.
    # (suicidal — "anyone can destruct" — is itself an access-control failure but
    # is already owned by the `suicidal` category, so it is intentionally not
    # remapped here to avoid duplicate findings.)]
    "access-control": ["protected-vars", "events-access"],
    "tx-origin": ["tx-origin"],
    # [Worker decision (R5, POST_V01 Rank 4): the roadmap proposed mapping the
    # `delegatecall` category onto a Slither detector named
    # "dangerous-delegatecall". No such ARGUMENT exists in slither-analyzer
    # 0.11.x — the canonical detector for an attacker-controlled delegatecall
    # destination is "controlled-delegatecall" (HIGH impact). It is paired with
    # "delegatecall-loop" (HIGH impact: a delegatecall inside a loop that can
    # multiply msg.value usage). The phantom "dangerous-delegatecall" name is
    # intentionally omitted rather than left in as a silent no-op, mirroring the
    # R2 access-control mapping correction. The `upgrade` category maps onto
    # "unprotected-upgrade" (HIGH/HIGH) — an initializable proxy implementation
    # whose initializer can be front-run/called by anyone, the canonical
    # instant-critical on UUPS/Transparent proxy bounty scope.]
    "delegatecall": ["controlled-delegatecall", "delegatecall-loop"],
    "upgrade": ["unprotected-upgrade"],
}


# [Worker decision (R7, POST_V01 Rank 6): Slither's Vyper front-end supports
# only a subset of its Solidity detectors — Vyper's IR/AST does not carry the
# same information several Solidity-specific detectors rely on. POST_V01 Rank 6
# names reentrancy and arbitrary-send (omen's `prodigal`) as the covered
# classes; those map onto Slither detectors that operate on the language-neutral
# IR and run cleanly on Vyper. The remaining omen classes are Solidity-only
# concepts (suicidal/selfdestruct, locked-ether, the NatSpec-keyed
# protected-vars, tx.origin, delegatecall/upgrade proxy patterns) and are
# excluded for Vyper input rather than silently registered as no-ops. Asking
# for an unsupported class on a .vy file is reported as an explicit InputError
# upstream so the user gets a clear message instead of an empty report.]
VYPER_SUPPORTED_CATEGORIES: frozenset[str] = frozenset({"reentrancy", "prodigal"})


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


# --- bytecode-level structural heuristics (POST_V01 Rank 1) -----------
#
# [Worker decision (R3, POST_V01 Rank 1): v0.1 deferred prodigal/greedy/
# reentrancy bytecode detection because precise data-flow recovery from raw
# bytecode is effectively a decompiler. POST_V01 Rank 1's chosen approach is
# coarse opcode-pattern heuristics — not data-flow soundness. They run ONLY in
# bytecode/address mode (source mode keeps Slither's precise analysis) and
# report at confidence "low" with an explicit "source-mode is higher
# precision" caveat. The trade-off is recall over precision: an on-chain,
# source-unverified contract that previously produced zero findings for three
# of the four classes now produces a low-confidence lead a bounty hunter can
# triage, instead of a silent miss.]

# Opcodes that move ether out of the contract — a "release path" for funds.
_VALUE_SENDING_OPCODES = frozenset(
    {"CALL", "CALLCODE", "DELEGATECALL", "SELFDESTRUCT", "SUICIDE"}
)
# Opcodes that end a linear instruction segment.
_TERMINATOR_OPCODES = frozenset({"RETURN", "STOP", "REVERT", "INVALID"})


def _disassemble(bytecode: bytes) -> list[Any]:
    from pyevmasm import disassemble_all

    return list(disassemble_all(bytecode))


def scan_prodigal(bytecode: bytes) -> list[dict[str, Any]]:
    """Heuristic for prodigal (leaks ether to an arbitrary/caller address).

    Pattern: a CALL whose destination is caller-controlled (a CALLDATALOAD
    appears in the recent preceding window) AND whose value argument is
    plausibly non-zero (a non-zero PUSH appears in the same window, and the
    window is not dominated by zero-pushes that would zero the value slot).

    This is deliberately coarse: at the opcode level we cannot prove which
    stack slot a given value flows into. We approximate "caller-controlled
    destination + non-zero value" by requiring, within a short look-back
    window before the CALL, both a CALLDATALOAD and at least one PUSH of a
    non-zero immediate. A window of only zero-pushes (value == 0) is treated
    as a non-leaking call and skipped.
    """
    insns = _disassemble(bytecode)
    window = 12  # opcodes of look-back context before the CALL
    hits: list[dict[str, Any]] = []
    for i, insn in enumerate(insns):
        if insn.name != "CALL":
            continue
        ctx = insns[max(0, i - window) : i]
        has_calldata = any(c.name == "CALLDATALOAD" for c in ctx)
        if not has_calldata:
            continue  # destination not caller-derived
        nonzero_push = any(
            c.name.startswith("PUSH") and getattr(c, "operand", 0) not in (0, None)
            for c in ctx
        )
        if not nonzero_push:
            continue  # no evidence of a non-zero value argument
        hits.append(
            {"opcode": "CALL", "offset": insn.pc, "category": "prodigal"}
        )
    return hits


def scan_greedy(bytecode: bytes) -> list[dict[str, Any]]:
    """Heuristic for greedy (accepts ether but has no path to release it).

    Pattern: the bytecode reads CALLVALUE (a payable signal — it inspects the
    ether sent with the call) but contains NO value-sending opcode at all
    (no CALL / CALLCODE / DELEGATECALL / SELFDESTRUCT). Ether can come in but
    has no way out — MAIAN's "greedy"/locked-ether class.
    """
    insns = _disassemble(bytecode)
    callvalue = next((c for c in insns if c.name == "CALLVALUE"), None)
    if callvalue is None:
        return []  # not payable -> no locked-ether concern
    if any(c.name in _VALUE_SENDING_OPCODES for c in insns):
        return []  # a release path exists
    return [
        {"opcode": "CALLVALUE", "offset": callvalue.pc, "category": "greedy"}
    ]


def scan_reentrancy(bytecode: bytes) -> list[dict[str, Any]]:
    """Heuristic for reentrancy (state write after an external call).

    Pattern: a CALL followed by an SSTORE before the next linear-segment
    terminator (RETURN / STOP / REVERT / INVALID). Writing state after an
    external call is the checks-effects-interactions (CEI) violation that
    enables classic reentrancy. Scanning the linear opcode stream (rather
    than reconstructing the control-flow graph) is coarse but catches the
    common straight-line withdraw-then-update shape.
    """
    insns = _disassemble(bytecode)
    hits: list[dict[str, Any]] = []
    seen_call: Any = None
    for insn in insns:
        if insn.name == "CALL":
            seen_call = insn
        elif insn.name in _TERMINATOR_OPCODES:
            seen_call = None  # segment ends; reset
        elif insn.name == "SSTORE" and seen_call is not None:
            hits.append(
                {"opcode": "SSTORE", "offset": insn.pc, "category": "reentrancy"}
            )
            seen_call = None  # one finding per call/store pair
    return hits
