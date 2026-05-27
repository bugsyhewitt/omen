"""Bytecode-mode heuristic tests for prodigal, greedy, and reentrancy.

POST_V01 Rank 1: v0.1 bytecode/address mode detected only `suicidal` via the
SELFDESTRUCT opcode. These tests cover the three new opcode-level heuristics
that close the address-mode coverage gap for the other MAIAN-adjacent classes.

All synthetic bytecode here is hand-assembled hex chosen to trigger (or
deliberately NOT trigger) one specific structural pattern. The heuristics are
intentionally coarse — they report at confidence "low" — so the assertions
focus on the structural signal, not on full data-flow soundness.

Opcode reference (hex):
  CALLVALUE 0x34  CALLDATALOAD 0x35  SSTORE 0x55  STOP 0x00
  CALL 0xf1  CALLCODE 0xf2  RETURN 0xf3  DELEGATECALL 0xf4
  STATICCALL 0xfa  REVERT 0xfd  SELFDESTRUCT 0xff
  PUSH1 0x60  POP 0x50  DUP1 0x80
"""

from __future__ import annotations

from omen.analyzer import analyze
from omen.detectors import (
    scan_greedy,
    scan_prodigal,
    scan_reentrancy,
)


def _b(hexstr: str) -> bytes:
    return bytes.fromhex(hexstr.replace(" ", ""))


# --- prodigal: CALL with caller-controlled destination + non-zero value ----

# CALLDATALOAD feeds the address; a non-zero PUSH supplies the value; CALL.
# Layout (top of stack first as CALL pops gas,addr,value,...):
#   PUSH1 00          retLength
#   PUSH1 00          retOffset
#   PUSH1 00          argsLength
#   PUSH1 00          argsOffset
#   PUSH1 01          value (non-zero)
#   PUSH1 00 CALLDATALOAD   addr (caller-controlled)
#   GAS               gas (0x5a, not a PUSH)
#   CALL
PRODIGAL_HEX = "6000 6000 6000 6000 6001 6000 35 5a f1 00"

# Same shape but every pushed immediate near the CALL is zero (value slot is
# zero, no non-zero immediate in the look-back window) -> not a value-leaking
# call -> no prodigal hit. gas is supplied by GAS (0x5a), not a PUSH.
PRODIGAL_ZERO_VALUE_HEX = "6000 6000 6000 6000 6000 6000 35 5a f1 00"

# A CALL whose address is a hardcoded PUSH (not calldata-derived) -> not
# caller-controlled -> no prodigal hit even with non-zero value.
PRODIGAL_FIXED_ADDR_HEX = "6000 6000 6000 6000 6001 73deadbeefdeadbeefdeadbeefdeadbeefdeadbeef 60ff f1 00"


def test_scan_prodigal_fires_on_calldata_controlled_call():
    hits = scan_prodigal(_b(PRODIGAL_HEX))
    assert hits, "expected a prodigal hit for calldata-controlled CALL with value"
    assert all(h["category"] == "prodigal" for h in hits)
    assert any(h["opcode"] == "CALL" for h in hits)


def test_scan_prodigal_ignores_zero_value_call():
    assert scan_prodigal(_b(PRODIGAL_ZERO_VALUE_HEX)) == []


def test_scan_prodigal_ignores_fixed_destination():
    assert scan_prodigal(_b(PRODIGAL_FIXED_ADDR_HEX)) == []


# --- greedy: payable signal (CALLVALUE) but no value-sending opcode ---------

# CALLVALUE present, NO CALL/DELEGATECALL/CALLCODE/SELFDESTRUCT -> locked ether.
GREEDY_HEX = "34 6000 55 00"  # CALLVALUE; PUSH1 0; SSTORE; STOP

# CALLVALUE present AND a CALL exists -> has a release path -> not greedy.
GREEDY_HAS_CALL_HEX = "34 6000 6000 6000 6000 6000 6000 60ff f1 00"

# No CALLVALUE at all -> not payable -> no greedy signal.
GREEDY_NO_CALLVALUE_HEX = "6000 6000 55 00"


def test_scan_greedy_fires_on_payable_without_release():
    hits = scan_greedy(_b(GREEDY_HEX))
    assert hits, "expected a greedy hit for payable contract with no release path"
    assert all(h["category"] == "greedy" for h in hits)
    assert any(h["opcode"] == "CALLVALUE" for h in hits)


def test_scan_greedy_ignores_when_release_path_present():
    assert scan_greedy(_b(GREEDY_HAS_CALL_HEX)) == []


def test_scan_greedy_ignores_non_payable():
    assert scan_greedy(_b(GREEDY_NO_CALLVALUE_HEX)) == []


# --- reentrancy: CALL then SSTORE before the next RETURN/STOP/REVERT --------

# CALL ... SSTORE before any terminator -> state write after external call (CEI
# violation pattern).
REENTRANCY_HEX = "6000 6000 6000 6000 6000 6000 60ff f1 6001 6002 55 00"

# SSTORE happens BEFORE the CALL, then STOP -> checks-effects-interactions
# order respected -> no reentrancy hit.
REENTRANCY_CEI_OK_HEX = "6001 6002 55 6000 6000 6000 6000 6000 6000 60ff f1 00"

# A terminator (STOP) sits between the CALL and the SSTORE -> the SSTORE is in a
# different linear segment -> not flagged.
REENTRANCY_TERMINATED_HEX = "6000 6000 6000 6000 6000 6000 60ff f1 00 6001 6002 55 00"


def test_scan_reentrancy_fires_on_state_write_after_call():
    hits = scan_reentrancy(_b(REENTRANCY_HEX))
    assert hits, "expected a reentrancy hit for SSTORE after CALL"
    assert all(h["category"] == "reentrancy" for h in hits)
    assert any(h["opcode"] == "SSTORE" for h in hits)


def test_scan_reentrancy_ignores_cei_compliant_order():
    assert scan_reentrancy(_b(REENTRANCY_CEI_OK_HEX)) == []


def test_scan_reentrancy_ignores_sstore_after_terminator():
    assert scan_reentrancy(_b(REENTRANCY_TERMINATED_HEX)) == []


# --- clean bytecode: no heuristic should fire (false-positive guard) --------

# A trivial constructor-free runtime that just returns: no CALL, no CALLVALUE,
# no SSTORE. None of the three heuristics may fire.
CLEAN_HEX = "6001 6002 01 6000 52 6020 6000 f3"  # add, mstore, RETURN


def test_clean_bytecode_no_false_positives():
    code = _b(CLEAN_HEX)
    assert scan_prodigal(code) == []
    assert scan_greedy(code) == []
    assert scan_reentrancy(code) == []


# --- analyzer wiring: low-confidence findings flow through analyze() --------


def test_analyze_bytecode_prodigal_low_confidence(tmp_path):
    p = tmp_path / "prodigal.bin"
    p.write_text(PRODIGAL_HEX.replace(" ", ""))
    report = analyze(contract=str(p), input_type="bytecode", check="prodigal")
    f = next((f for f in report.findings if f.category == "prodigal"), None)
    assert f is not None, "prodigal heuristic should surface in bytecode mode"
    assert f.confidence == "low"
    assert "source" in f.description.lower()  # the precision caveat note
    assert f.evidence.opcodes


def test_analyze_bytecode_greedy_low_confidence(tmp_path):
    p = tmp_path / "greedy.bin"
    p.write_text(GREEDY_HEX.replace(" ", ""))
    report = analyze(contract=str(p), input_type="bytecode", check="greedy")
    f = next((f for f in report.findings if f.category == "greedy"), None)
    assert f is not None
    assert f.confidence == "low"


def test_analyze_bytecode_reentrancy_low_confidence(tmp_path):
    p = tmp_path / "reentrancy.bin"
    p.write_text(REENTRANCY_HEX.replace(" ", ""))
    report = analyze(contract=str(p), input_type="bytecode", check="reentrancy")
    f = next((f for f in report.findings if f.category == "reentrancy"), None)
    assert f is not None
    assert f.confidence == "low"


def test_analyze_bytecode_all_check_includes_new_heuristics(tmp_path):
    # The greedy fixture only triggers greedy; --check all must still surface it
    # alongside the unchanged suicidal behaviour.
    p = tmp_path / "greedy.bin"
    p.write_text(GREEDY_HEX.replace(" ", ""))
    report = analyze(contract=str(p), input_type="bytecode", check="all")
    cats = {f.category for f in report.findings}
    assert "greedy" in cats


def test_analyze_bytecode_clean_no_findings(tmp_path):
    p = tmp_path / "clean.bin"
    p.write_text(CLEAN_HEX.replace(" ", ""))
    report = analyze(contract=str(p), input_type="bytecode", check="all")
    assert report.findings == []
