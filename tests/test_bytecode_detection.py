"""Bytecode-mode detection tests (criterion 6).

The shipped compiled.bin is the runtime bytecode of vulnerable-suicidal.sol.
Bytecode mode must produce the same suicidal finding source mode produces,
with no solc dependency.
"""

from __future__ import annotations

from omen.analyzer import analyze
from omen.detectors import scan_bytecode_opcodes


def test_compiled_bin_has_selfdestruct(fixtures_dir):
    raw = (fixtures_dir / "compiled.bin").read_text().strip()
    if raw.startswith("0x"):
        raw = raw[2:]
    hits = scan_bytecode_opcodes(bytes.fromhex(raw))
    assert any(h["category"] == "suicidal" for h in hits)


def test_bytecode_suicidal_finding(fixtures_dir):
    report = analyze(
        contract=str(fixtures_dir / "compiled.bin"),
        input_type="bytecode",
        check="suicidal",
    )
    cats = {f.category for f in report.findings}
    assert "suicidal" in cats
    f = next(f for f in report.findings if f.category == "suicidal")
    assert f.severity.value
    # bytecode evidence must carry the offending opcode
    assert any(op.get("opcode") in ("SELFDESTRUCT", "SUICIDE") for op in f.evidence.opcodes)


def test_bytecode_mode_needs_no_solc(fixtures_dir, monkeypatch):
    # Even if solc is entirely absent from PATH, bytecode mode works.
    monkeypatch.setenv("PATH", "")
    report = analyze(
        contract=str(fixtures_dir / "compiled.bin"),
        input_type="bytecode",
        check="suicidal",
    )
    assert any(f.category == "suicidal" for f in report.findings)
