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
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Generator

from .analyzer import AnalysisReport, analyze
from .solc_env import SolcUnavailableError
from .sources import InputError
from .vyper_env import VyperUnavailableError


# Severity ordering for the batch aggregate summary (POST_V01 Rotation 2,
# R2.12). Worst-first so the roll-up reads the same direction as the default
# per-contract --sort severity and the --format text summary. Kept local to
# batch.py (a tuple of the string values) so the aggregation primitive imports
# nothing heavy — the summary must work in a fresh checkout with no compiler.
_SUMMARY_SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational")


def summarize_batch(reports: list[dict[str, Any]], errors: int) -> str:
    """Build the aggregate roll-up line(s) for a --batch run (R2.12).

    *reports* is the list of per-contract report dicts (the same dicts emitted
    as JSONL) for the contracts that scanned cleanly; *errors* is the number of
    items that failed. The summary answers the first question a bounty hunter
    asks after scanning a whole program scope: how much did omen cover, how much
    of it had findings, and what is the severity profile across the whole scope —
    without having to pipe the JSONL through ``jq`` and aggregate by hand.

    The roll-up is a small, human-readable block:

      - a header line with the contract/error/finding totals;
      - a worst-first per-severity total line (only severities that occur);
      - up to the five worst-affected contracts (most findings first), each with
        its finding count, so the analyst knows where to look first.

    It is a pure function of its inputs — no I/O, no analysis — so it is unit
    testable in isolation and adds no dependency.
    """
    scanned = len(reports)
    with_findings = 0
    total_findings = 0
    severity_totals: dict[str, int] = {}
    per_contract: list[tuple[str, int]] = []
    gate_tripped = False

    for rep in reports:
        findings = rep.get("findings") or []
        count = len(findings)
        # total_findings (pre-limit) is the honest scope total; fall back to the
        # shown count for older/mocked dicts that lack it.
        scope_count = rep.get("total_findings")
        if not isinstance(scope_count, int):
            scope_count = count
        if scope_count:
            with_findings += 1
        total_findings += scope_count
        per_contract.append((str(rep.get("origin", "?")), scope_count))
        if rep.get("gate_triggered"):
            gate_tripped = True
        for f in findings:
            sev = str(f.get("severity", "")).strip().lower()
            if sev:
                severity_totals[sev] = severity_totals.get(sev, 0) + 1

    lines: list[str] = []
    lines.append("omen batch summary")
    lines.append(
        f"contracts: {scanned} scanned, {with_findings} with findings, "
        f"{errors} errored"
    )

    sev_parts = [
        f"{severity_totals[sev]} {sev}"
        for sev in _SUMMARY_SEVERITY_ORDER
        if severity_totals.get(sev)
    ]
    sev_line = ", ".join(sev_parts) if sev_parts else "none"
    lines.append(f"findings: {total_findings} total  [{sev_line}]")

    # Worst-affected contracts: most findings first, ties keep scan order
    # (sorted is stable on the enumerate index we never expose). Only list
    # contracts that actually had findings, capped at five so the block stays a
    # glance rather than a second report.
    affected = [(origin, n) for origin, n in per_contract if n]
    affected.sort(key=lambda item: -item[1])
    if affected:
        lines.append("top affected:")
        for origin, n in affected[:5]:
            noun = "finding" if n == 1 else "findings"
            lines.append(f"  {n} {noun}  {origin}")

    if gate_tripped:
        lines.append("--fail-on gate: TRIPPED")

    return "\n".join(lines)


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


def parse_parallel(parallel: int | str | None) -> int:
    """Parse a ``--parallel`` value into a worker count (a positive int).

    *parallel* is the number of contracts a ``--batch`` scan analyzes
    concurrently. ``None`` (the flag's default sentinel) and ``1`` both mean
    "no concurrency" — the historical sequential behaviour, unchanged. A value
    of ``2`` or more runs that many analyses at once.

    Mirrors the ``--limit`` validation convention: a positive integer only.
    Accepts an ``int`` directly or a decimal string (so a config-file value or a
    raw CLI string both work). ``0`` and negatives are rejected because a
    zero/negative worker count is meaningless and almost always a typo — omen
    errors loudly instead of silently scanning nothing or falling back. ``bool``
    is rejected (``True``/``False`` are ints in Python but never a sensible
    worker count).

    Returns ``1`` for the no-concurrency case so callers can treat the result
    uniformly as the worker count.
    """
    if parallel is None:
        return 1
    if isinstance(parallel, bool):
        raise ValueError(
            f"--parallel must be a positive integer, got {parallel!r}"
        )
    if isinstance(parallel, int):
        n = parallel
    else:
        try:
            n = int(str(parallel), 10)
        except (TypeError, ValueError):
            raise ValueError(
                f"--parallel must be a positive integer, got {parallel!r}"
            )
    if n <= 0:
        raise ValueError(
            f"--parallel must be a positive integer (>= 1), got {n}"
        )
    return n


def parse_timeout(timeout: float | int | str | None) -> float | None:
    """Parse a ``--timeout`` value into a per-contract second budget (a float).

    *timeout* is the wall-clock budget, in seconds, allowed for a single
    contract's analysis in ``--batch`` mode (POST_V01 R2.14). ``None`` (the
    flag's default sentinel) means "no budget" — the historical behaviour, a
    scan runs until it finishes. A positive value caps each contract: a scan
    that overruns is abandoned and recorded as a per-item error (the same
    ``(None, error)`` shape an exception produces), so one pathological contract
    can't stall a whole-program scan of dozens-to-hundreds of contracts.

    Mirrors the ``--limit`` / ``--parallel`` validation convention but for a
    float (a sub-second or fractional budget like ``2.5`` is sensible, unlike a
    worker count). Accepts a ``float``/``int`` directly or a decimal string (so a
    config-file value or a raw CLI string both work). ``0``, negatives, NaN, and
    infinity are rejected because a zero/negative/non-finite budget is
    meaningless and almost always a typo — omen errors loudly instead of silently
    abandoning every scan or never timing out. ``bool`` is rejected (``True`` /
    ``False`` are ints in Python but never a sensible budget).

    Returns ``None`` for the no-budget case so callers can treat the result
    uniformly as "the budget, or None".
    """
    import math

    if timeout is None:
        return None
    if isinstance(timeout, bool):
        raise ValueError(
            f"--timeout must be a positive number of seconds, got {timeout!r}"
        )
    if isinstance(timeout, (int, float)):
        n = float(timeout)
    else:
        try:
            n = float(str(timeout))
        except (TypeError, ValueError):
            raise ValueError(
                f"--timeout must be a positive number of seconds, got {timeout!r}"
            )
    if not math.isfinite(n) or n <= 0:
        raise ValueError(
            f"--timeout must be a positive number of seconds (> 0), got {n}"
        )
    return n


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


def _analyze_one(
    item: str,
    *,
    input_type: str,
    check: str,
    rpc_url: str | None,
    min_confidence: str,
    min_severity: str,
    sort: str,
    limit: int | str | None,
    fail_on: str | None,
    exclude_check: str | None,
    severity_override: str | None,
) -> tuple[AnalysisReport | None, str | None]:
    """Analyze a single batch *item*; return ``(report, error_message)``.

    Exactly one of the pair is non-None: a successful scan yields
    ``(report, None)``; a failure yields ``(None, "...")`` with a human-readable
    message (the same text the sequential loop wrote to stderr). Pulling the
    per-item work into a pure-ish function lets ``run_batch`` drive it either
    sequentially or across a ``ThreadPoolExecutor`` (POST_V01 — ``--parallel``)
    without duplicating the try/except, while keeping every order-sensitive
    side effect (stdout JSONL, the gate, the summary) in the caller where the
    input order is known.
    """
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
            severity_override=severity_override,
        )
    except (InputError, SolcUnavailableError, VyperUnavailableError) as exc:
        return None, f"omen: batch error [{item}]: {exc}"
    except Exception as exc:  # noqa: BLE001
        return None, f"omen: batch analysis failed [{item}]: {exc}"
    return report, None


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
    batch_summary: bool = False,
    severity_override: str | None = None,
    parallel: int | str | None = None,
    timeout: float | int | str | None = None,
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

    *batch_summary* (POST_V01 Rotation 2, R2.12) prints an aggregate roll-up to
    **stderr** after the JSONL stream when True (default False). It answers the
    first question after a whole-program scan — how much was covered, how much
    had findings, the severity profile across the whole scope, and the
    worst-affected contracts — without piping the JSONL through ``jq``. It goes
    to stderr (never stdout) so the JSONL stream on stdout stays machine-clean
    for tooling, and it is built from the same per-contract report dicts that
    were already streamed, so it adds no extra analysis.

    *severity_override* (org-specific risk tuning) is a comma-separated list of
    ``CATEGORY=SEVERITY`` pairs forwarded to ``analyze`` for each item, so the
    same per-category severity re-stamping applies uniformly across the batch
    (and composes with the per-item ``--min-severity``/``--sort``/``--fail-on``
    pipeline exactly as in single-contract mode).

    *parallel* (POST_V01) is the number of contracts analyzed concurrently.
    ``None``/``1`` (the default) keeps the historical sequential, streaming
    behaviour: each JSONL line is printed as it is produced, in input order. A
    value of ``2`` or more analyzes that many contracts at once via a thread
    pool — the speedup for the real bounty workflow of scanning a whole program
    scope (dozens to hundreds of contracts), where each scan's wall time is
    dominated by the solc/vyper compiler subprocess that releases the GIL.
    Concurrency never reorders the result: output, the ``--fail-on`` gate (the
    OR across items), the error count, and the ``--batch-summary`` roll-up are
    all assembled in deterministic **input order** regardless of which scan
    finishes first, so a parallel run's JSONL stream and exit code are
    byte-for-byte identical to the sequential run's. The trade-off vs. the
    sequential path is memory: a parallel run buffers the ordered results before
    emitting, rather than streaming line by line.

    *timeout* (POST_V01 R2.14) is the per-contract wall-clock budget, in seconds.
    ``None`` (the default) means no budget — each scan runs to completion, the
    historical behaviour. A positive value caps each contract's analysis: a scan
    that overruns is abandoned and recorded as a per-item error (counted toward
    the exit-1 error tally and the ``--batch-summary`` error count, with a
    message to stderr), exactly like a scan that raised — so one pathological
    contract (a compiler that hangs, a symbolic path that blows up) cannot stall
    a whole-program scan of dozens-to-hundreds of contracts. The budget is
    enforced on the existing thread-pool orchestration seam (``--parallel``): the
    item runs in a worker future and the driver waits at most *timeout* seconds
    for it via ``Future.result(timeout=...)``; on overrun the driver moves on.
    Setting a timeout therefore always uses the pool (a single shared worker when
    ``--parallel`` is 1), since the budget can only be enforced by waiting on a
    future from the calling thread. It deliberately does **not** subprocess-wrap
    or kill the in-process Slither analysis (that would change omen's defining
    architecture and violate the Anti-Abstraction / Simplicity gates); the
    abandoned scan's worker thread is left to finish and be reclaimed when the
    pool shuts down, so the budget bounds the batch's *blocking* wait per item,
    which is the bounty-workflow value: progress past a stuck contract. Note the
    budget bounds the *wait*, not the scan: with the default single worker the
    stuck scan still occupies the lone thread, so the items queued behind it also
    exceed their wait and time out — the "make progress past it" guarantee needs
    a free worker, i.e. pairing --timeout with --parallel >= 2. Order is
    preserved exactly as for ``--parallel``: results (whether a report or a
    timeout error) are folded into the run's state in input order. **No effect in
    single --contract mode** (one target, nothing a per-item batch budget bounds).

    Returns 1 if any item raised an exception or timed out; otherwise 3 if the
    --fail-on gate tripped on any item; otherwise 0.
    """
    workers = parse_parallel(parallel)
    budget = parse_timeout(timeout)
    any_error = False
    error_count = 0
    gate_tripped = False
    buffered: list[str] = []
    # Collected per-contract report dicts, kept only when --batch-summary is on
    # (the aggregate is built from them); otherwise we never retain them, so a
    # large sequential batch without the summary keeps its streaming, low-memory
    # behaviour. (A parallel batch always materialises the ordered results.)
    collected: list[dict[str, Any]] = []
    ignore_patterns = parse_ignore(ignore)
    items = list(_iter_items(path, input_type, ignore_patterns))

    def _consume(report: AnalysisReport | None, error: str | None) -> None:
        """Fold one (report, error) result into the run's ordered state.

        Called in input order in both the sequential and parallel paths, so
        every order-sensitive side effect — the stdout JSONL line, the gate OR,
        the error tally, the summary collection — happens deterministically.
        """
        nonlocal any_error, error_count, gate_tripped
        if error is not None:
            print(error, file=sys.stderr)
            any_error = True
            error_count += 1
            return
        assert report is not None
        if report.gate_triggered:
            gate_tripped = True
        report_dict = report.to_dict()
        if batch_summary:
            collected.append(report_dict)
        line = json.dumps(report_dict)
        if output_file is None:
            print(line)
        else:
            buffered.append(line)

    def _run_one(item: str) -> tuple[AnalysisReport | None, str | None]:
        return _analyze_one(
            item,
            input_type=input_type,
            check=check,
            rpc_url=rpc_url,
            min_confidence=min_confidence,
            min_severity=min_severity,
            sort=sort,
            limit=limit,
            fail_on=fail_on,
            exclude_check=exclude_check,
            severity_override=severity_override,
        )

    # A per-item --timeout (R2.14) can only be enforced by waiting on a future
    # from the calling thread, so it forces the pool path even at parallel=1
    # (a single shared worker). With no timeout and no concurrency we keep the
    # historical sequential, streaming, low-memory path.
    use_pool = (workers > 1 or budget is not None) and len(items) > 1

    if not use_pool:
        # Sequential path: analyze and consume one at a time. This preserves the
        # historical streaming behaviour (a line printed as soon as it is ready)
        # and the low-memory profile when --batch-summary and --output-file are
        # both off. Also taken for a 0/1-item batch, where a pool would be pure
        # overhead. When a 1-item batch carries a timeout, the single scan still
        # gets the budget below via the pool path's len(items) > 1 short-circuit
        # being false here — a lone scan has nothing to make progress *past*, so
        # the budget is a no-op rather than a way to abandon the only target.
        for item in items:
            _consume(*_run_one(item))
    elif budget is None:
        # Parallel path (no timeout): submit every item to a bounded thread pool,
        # then consume the results strictly in input order (executor.map
        # preserves submission order), so the JSONL stream / gate / summary are
        # identical to the sequential run — only faster. The wall-clock win comes
        # from the solc/vyper compiler subprocess each scan shells out to, which
        # releases the GIL while it runs.
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for report, error in pool.map(_run_one, items):
                _consume(report, error)
    else:
        # Timeout path (R2.14): submit every item up front, then collect each
        # future strictly in input order, waiting at most *budget* seconds for
        # each. An overrun is folded in as a per-item error (same shape as a
        # raised exception), so the gate/error-count/summary stay deterministic
        # and in input order regardless of which scan finishes first. We do NOT
        # kill the abandoned worker (that would mean subprocess-wrapping the
        # in-process Slither analysis); it is left to finish and be reclaimed at
        # pool shutdown, which we make non-blocking via cancel_futures so the
        # batch returns promptly past a stuck contract.
        from concurrent.futures import TimeoutError as FutureTimeoutError

        pool = ThreadPoolExecutor(max_workers=workers)
        try:
            futures = [pool.submit(_run_one, item) for item in items]
            for item, future in zip(items, futures):
                try:
                    report, error = future.result(timeout=budget)
                except FutureTimeoutError:
                    _consume(
                        None,
                        f"omen: batch timeout [{item}]: analysis exceeded "
                        f"{budget:g}s budget",
                    )
                else:
                    _consume(report, error)
        finally:
            # Don't block shutdown on any still-running (timed-out) worker; let
            # the interpreter reclaim the daemonic pool thread on exit.
            pool.shutdown(wait=False, cancel_futures=True)

    if output_file is not None:
        from .cli import write_output

        write_output("\n".join(buffered), output_file)

    # Aggregate roll-up goes to stderr so the stdout JSONL stream stays clean
    # for `jq`/tooling; it summarises the same dicts that were just streamed.
    if batch_summary:
        print(summarize_batch(collected, error_count), file=sys.stderr)

    if any_error:
        return 1
    if gate_tripped:
        return 3
    return 0
