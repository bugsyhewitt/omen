"""Batch scanning for omen.

Accepts either a directory (recursively finds .sol files) or a newline-delimited
file of contract paths or addresses. Emits one JSON object per contract to stdout
as a JSONL stream (one dict per line).

Usage patterns::

    omen --batch contracts/ --input-type sol --check all
    omen --batch addresses.txt --input-type address --rpc-url $RPC

Each line of output is valid JSON produced by ``json.dumps(report.to_dict())``.
Comment lines (starting with ``#``) and blank lines in list files are skipped.
Per-item errors are written to stderr and do not abort the batch.

Exit code:
    1  at least one item failed (errors take precedence over the gate)
    3  --fail-on gate tripped on at least one (clean) item and nothing failed
    0  all items succeeded and the gate (if set) never tripped
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
    sort: str = "severity",
    limit: int | str | None = None,
    fail_on: str | None = None,
    exclude_check: str | None = None,
) -> int:
    """Run analysis on every item under *path* and emit JSONL to stdout.

    *min_confidence* (POST_V01 Rank 8), *min_severity* (POST_V01 Rotation 2),
    *sort* (POST_V01 Rotation 2, Rank 3), and *limit* (POST_V01 Rotation 2,
    R2.4) are forwarded to ``analyze`` for each item, so both filters, the
    worst-first ordering, and the per-contract top-N cap apply uniformly across
    the batch — the common case for suppressing low-confidence bytecode-
    heuristic noise and surfacing the top high-impact leads per contract when
    scanning a whole program scope. The cap is per-contract (each JSONL line
    shows at most *limit* findings), not a cap on the number of contracts.

    *fail_on* (POST_V01 Rotation 2, R2.5) is the CI exit-code gate, forwarded to
    ``analyze`` for each item. The batch gate is the OR across items: if any
    single contract trips the gate the batch exits 3 (so a pipeline step fails
    even when scanning a whole program scope). A per-item failure still takes
    precedence — errors are exit 1 — because a failed scan is a stronger signal
    than a clean scan that found something.

    *exclude_check* (POST_V01 Rotation 2, R2.8) is the inverse category selector,
    forwarded to ``analyze`` for each item, so the same categories are removed
    from the ``--check`` set uniformly across the batch.

    Returns 1 if any item raised an exception; otherwise 3 if the --fail-on gate
    tripped on any item; otherwise 0.
    """
    any_error = False
    gate_tripped = False

    for item in _iter_items(path, input_type):
        try:
            report = analyze(
                contract=item,
                input_type=input_type,
                check=check,
                rpc_url=rpc_url,
                min_confidence=min_confidence,
                min_severity=min_severity,
                sort=sort,
                limit=limit,
                fail_on=fail_on,
                exclude_check=exclude_check,
            )
        except (InputError, SolcUnavailableError, VyperUnavailableError) as exc:
            print(f"omen: batch error [{item}]: {exc}", file=sys.stderr)
            any_error = True
            continue
        except Exception as exc:  # noqa: BLE001
            print(f"omen: batch analysis failed [{item}]: {exc}", file=sys.stderr)
            any_error = True
            continue

        if report.gate_triggered:
            gate_tripped = True
        print(json.dumps(report.to_dict()))

    if any_error:
        return 1
    if gate_tripped:
        return 3
    return 0
