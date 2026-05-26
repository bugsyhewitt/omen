"""A minimal mock Ethereum JSON-RPC server for omen's address-mode tests.

It speaks just enough of the JSON-RPC protocol for web3.py to fetch a
contract's bytecode: it answers web3_clientVersion, net_version, eth_chainId,
and eth_getCode (returning the bundled compiled.bin for any address).

No live network. Bind to 127.0.0.1 on an ephemeral port.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

_FIXTURES = Path(__file__).parent / "fixtures"


def _load_compiled_bin_hex() -> str:
    raw = (_FIXTURES / "compiled.bin").read_text().strip()
    if not raw.startswith("0x"):
        raw = "0x" + raw
    return raw


class _Handler(BaseHTTPRequestHandler):
    bytecode_hex = "0x"

    def log_message(self, *args, **kwargs):  # silence test noise
        pass

    def do_POST(self) -> None:  # noqa: N802 (http.server API)
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            req = json.loads(body)
        except json.JSONDecodeError:
            self._send({"error": {"code": -32700, "message": "parse error"}}, rid=None)
            return

        method = req.get("method")
        rid = req.get("id")

        if method == "web3_clientVersion":
            result = "omen-mock-rpc/0.1.0"
        elif method == "net_version":
            result = "1"
        elif method == "eth_chainId":
            result = "0x1"
        elif method == "eth_getCode":
            result = self.bytecode_hex
        elif method == "eth_blockNumber":
            result = "0x1"
        else:
            self._send({"error": {"code": -32601, "message": f"unknown method {method}"}}, rid=rid)
            return

        self._send({"result": result}, rid=rid)

    def _send(self, payload: dict, rid) -> None:
        payload.setdefault("jsonrpc", "2.0")
        payload["id"] = rid
        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class MockRpcServer:
    """Context-manager mock RPC serving the bundled compiled.bin."""

    def __init__(self, bytecode_hex: str | None = None):
        handler = type(
            "BoundHandler",
            (_Handler,),
            {"bytecode_hex": bytecode_hex or _load_compiled_bin_hex()},
        )
        self._server = HTTPServer(("127.0.0.1", 0), handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self._server.server_address
        return f"http://{host}:{port}"

    def __enter__(self) -> "MockRpcServer":
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._server.shutdown()
        self._server.server_close()
