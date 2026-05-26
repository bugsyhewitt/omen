"""Address-mode end-to-end test with a mock RPC (criteria 7 & 8).

No live network: a local mock JSON-RPC server returns the bundled
compiled.bin for eth_getCode. omen fetches it and detects the suicidal class.
"""

from __future__ import annotations

from omen.analyzer import analyze
from omen.sources import InputError

from mock_rpc import MockRpcServer

import pytest

_ADDR = "0x000000000000000000000000000000000000dEaD"


def test_address_mode_end_to_end_with_mock_rpc():
    with MockRpcServer() as server:
        report = analyze(
            contract=_ADDR,
            input_type="address",
            check="suicidal",
            rpc_url=server.url,
        )
    cats = {f.category for f in report.findings}
    assert "suicidal" in cats
    f = next(f for f in report.findings if f.category == "suicidal")
    assert f.contract is not None  # the checksummed address
    assert any(
        op.get("opcode") in ("SELFDESTRUCT", "SUICIDE") for op in f.evidence.opcodes
    )


def test_address_mode_requires_rpc_url():
    with pytest.raises(InputError):
        analyze(
            contract=_ADDR,
            input_type="address",
            check="suicidal",
            rpc_url=None,
        )
