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

import fnmatch
import json
import sys
from pathlib import Path
from typing import Generator

from .analyzer import analyze
from .solc_env import SolcUnavailableError
from .sources import InputError
from .vyper_env import VyperUnavailableError


def parse_ignore(ignore: str | None) -> list[str]:
    """Parse a ``--ignore`` value into a list of glob patterns.

    *ignore* is a comma-separated list of ``fnmatch``-style glob patterns
    (``*``, ``?``, ``[seq]``). Surrounding whitespace on each pattern is
    stripped and empty entries are dropped, so ``"node_modules, lib"`` and
    ``"node_modules,lib"`` are equivalent. ``None`` (the flag's default) and an
    all-blank value both yield an empty list — no exclusion.

    Raises ``ValueError`` if the value is non-empty but contains only blanks
    around the commas (e.g. ``--ignore ,,``), since that is almost always a
    typo: the user meant to exclude something but supplied no pattern.
    """
    if ignore is None:
        return []
    patterns = [token.strip() for token in ignore.split(",")]
    patterns = [token for token in patterns if token]
    if not patterns and ignore.strip():
        raise ValueError(
            f"--ignore value {ignore!r} contains no usable patterns"
        )
    return patterns


def _is_ignored(item: str, patterns: list[str]) -> bool:
    """Return True if *item* matches any of the ignore *patterns*.

    Matching is permissive and aimed at the common "skip vendored code" case:
    a pattern matches if it matches the full path string OR any individual path
    component (so a bare ``node_modules`` excludes ``a/node_modules/X.sol``
    without the caller needing the ``*/node_modules/*`` boilerplate), and a
    pattern containing a path separator is also tried against the full path with
    an implicit leading ``*`` (so ``lib/forge-std`` matches a deeper prefix).
    All matching is via :func:`fnmatch.fnmatch`, so ``*``/``?``/``[seq]`` work.
    """
    if not patterns:
        return False
    norm = item.replace("\\", "/")
    parts = norm.split("/")
    for pattern in patterns:
        pat = pattern.replace("\\", "/")
        if fnmatch.fnmatch(norm, pat):
            return True
        if any(fnmatch.fnmatch(part, pat) for part in parts):
            return True
        # A pattern with a separator is also matched as a sub-path anywhere in
        # the path (implicit leading "*"), e.g. "lib/openzeppelin" hits
        # "repo/lib/openzeppelin/Foo.sol".
        if "/" in pat and fnmatch.fnmatch(norm, f"*{pat}*"):
            return True
    return False


def _iter_items(
    path: str, input_type: str, ignore: list[str] | None = None
) -> Generator[str, None, None]:
    """Yield contract targets from *path*.

    If *path* is a directory: yield all ``.sol`` files found recursively.
    If *path* is a file: yield each non-blank, non-comment line.

    *ignore* (POST_V01 Rotation 2, R2.11) is a list of glob patterns; any
    yielded item matching one is skipped. This lets a recursive directory scan
    or a list file drop vendored/third-party paths (``node_modules``, ``lib``,
    ``test``, an OpenZeppelin import tree) without hand-pruning the input.
    """
    patterns = ignore or []
    p = Path(path)
    if p.is_dir():
        for sol_file in sorted(p.rglob("*.sol")):
            candidate = str(sol_file)
            if _is_ignored(candidate, patterns):
                continue
            yield candidate
    elif p.is_file():
        with p.open("r", encoding="utf-8") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line:
                    continue
                if line.startswith("#"):
                    continue
                if _is_ignored(line, patterns):
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
    output_file: str | None = None,
    ignore: str | None = None,
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

    *output_file* (POST_V01 Rotation 2, R2.9) redirects the JSONL stream to a
    file instead of stdout. When None (the default) lines are streamed to stdout
    as they are produced — the historical behaviour, unchanged. When a path is
    given the lines are buffered and written atomically at the end via
    ``cli.write_output`` (a sibling .tmp renamed into place), so a crash partway
    through a large batch never leaves a half-written report file in place of a
    previously good one. Per-item errors still go to stderr regardless.

    *ignore* (POST_V01 Rotation 2, R2.11) is a comma-separated list of glob
    patterns; any contract path/address the scan would otherwise visit that
    matches one is skipped before analysis. This drops vendored/third-party
    trees (``node_modules``, ``lib``, an OpenZeppelin import tree) from a
    recursive directory scan or a list file so a whole-repo batch stays scoped
    to first-party code. Ignored items produce no JSONL line and no error.

    Returns 1 if any item raised an exception; otherwise 3 if the --fail-on gate
    tripped on any item; otherwise 0.
    """
    any_error = False
    gate_tripped = False
    buffered: list[str] = []
    ignore_patterns = parse_ignore(ignore)

    for item in _iter_items(path, input_type, ignore_patterns):
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
        line = json.dumps(report.to_dict())
        if output_file is None:
            print(line)
        else:
            buffered.append(line)

    if output_file is not None:
        from .cli import write_output

        write_output("\n".join(buffered), output_file)

    if any_error:
        return 1
    if gate_tripped:
        return 3
    return 0
