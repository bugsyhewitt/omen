"""Batch scanning for omen.

Accepts either a directory (recursively finds .sol files) or a newline-delimited
file of contract paths or addresses. Emits one JSON object per contract to stdout
as a JSONL stream (one dict per line).

Usage patterns::

    omen --batch contracts/ --input-type sol --check all
    omen --batch addresses.txt --input-type address --rpc-url $RPC

Each line of output is valid JSON produced by ``json.dumps(report.to_dict())``.
Comment lines (starting with ``#``) and blank lines in list files are skipped.
Per-item errors are written to stderr and do not abort the batch; the exit code
is 1 if any item failed, 0 if all items succeeded.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Generator

from .analyzer import analyze
from .solc_env import SolcUnavailableError
from .sources import InputError
from .vyper_env import VyperUnavailableError


def _iter_items(path: str, input_type: str) -> Generator[str, None, None]:
    """Yield contract targets from *path*.

    If *path* is a directory: yield all ``.sol`` files found recursively.
    If *path* is a file: yield each non-blank, non-comment line.
    """
    p = Path(path)
    if p.is_dir():
        for sol_file in sorted(p.rglob("*.sol")):
            yield str(sol_file)
    elif p.is_file():
        with p.open("r", encoding="utf-8") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line:
                    continue
                if line.startswith("#"):
                    continue
                yield line
    else:
        raise FileNotFoundError(
            f"--batch path {path!r} is neither a directory nor a regular file"
        )


def run_batch(
    path: str,
    input_type: str,
    check: str,
    rpc_url: str | None = None,
    min_confidence: str = "low",
    min_severity: str = "informational",
) -> int:
    """Run analysis on every item under *path* and emit JSONL to stdout.

    *min_confidence* (POST_V01 Rank 8) and *min_severity* (POST_V01 Rotation 2)
    are forwarded to ``analyze`` for each item, so both filters apply uniformly
    across the batch — the common case for suppressing low-confidence
    bytecode-heuristic noise and surfacing only the high-impact leads when
    scanning a whole program scope.

    Returns 0 if all items succeeded, 1 if any item raised an exception.
    """
    any_error = False

    for item in _iter_items(path, input_type):
        try:
            report = analyze(
                contract=item,
                input_type=input_type,
                check=check,
                rpc_url=rpc_url,
                min_confidence=min_confidence,
                min_severity=min_severity,
            )
        except (InputError, SolcUnavailableError, VyperUnavailableError) as exc:
            print(f"omen: batch error [{item}]: {exc}", file=sys.stderr)
            any_error = True
            continue
        except Exception as exc:  # noqa: BLE001
            print(f"omen: batch analysis failed [{item}]: {exc}", file=sys.stderr)
            any_error = True
            continue

        print(json.dumps(report.to_dict()))

    return 1 if any_error else 0
