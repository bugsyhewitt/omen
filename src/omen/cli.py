"""omen command-line interface.

    omen --contract <path-or-address> --input-type {sol,vyper,bytecode,address}
         --check {prodigal,suicidal,greedy,reentrancy,access-control,tx-origin,all}
         [--rpc-url URL] [--format {json,text,h1md,sarif}]
         [--min-confidence {low,medium,high}]
         [--min-severity {informational,low,medium,high,critical}]
         [--sort {severity,none}] [--limit N]
         [--fail-on {never,informational,low,medium,high,critical}]

    omen --batch <dir-or-list-file> --input-type {sol,address}
         --check {...} [--rpc-url URL] [--min-confidence {low,medium,high}]
         [--min-severity {informational,low,medium,high,critical}]
         [--sort {severity,none}] [--limit N]
         [--fail-on {never,informational,low,medium,high,critical}]

Text in, text out. JSON is the default machine-readable format.
Batch mode always emits JSONL (one JSON object per contract).

Exit codes:
    0  ran cleanly (and, if --fail-on was set, nothing reached the threshold)
    1  analysis failed (single mode) / at least one batch item failed
    2  invalid arguments / input error (argparse / address mode missing --rpc-url)
    3  --fail-on gate tripped: a finding reached the chosen severity (CI gate)
"""

from __future__ import annotations

import argparse
import sys

from . import CATEGORIES, __version__


def _positive_int(value: str) -> int:
    """argparse type for --limit: a positive integer (>= 1).

    Rejects 0 and negatives — a zero/negative cap would silently hide every
    finding, which is almost always a mistake; omen errors instead.
    """
    try:
        n = int(value, 10)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"--limit must be a positive integer, got {value!r}"
        )
    if n <= 0:
        raise argparse.ArgumentTypeError(
            f"--limit must be a positive integer (>= 1), got {n}"
        )
    return n


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="omen",
        description=(
            "omen — a bounty-oriented hybrid scanner for Ethereum trace "
            "vulnerabilities (the MAIAN class: prodigal, suicidal, greedy) "
            "plus reentrancy, access-control, and tx-origin misuse. "
            "Analysis only; never submits transactions."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"omen {__version__}"
    )
    parser.add_argument(
        "--list-checks",
        action="store_true",
        help=(
            "print every detection class — its default severity, the input "
            "modes it runs in, and the underlying Slither detector(s) it maps "
            "to — then exit. Honors --format (json|text; text is the default "
            "for this listing). Requires no contract, compiler, or network."
        ),
    )

    # --contract and --batch are mutually exclusive; exactly one is required.
    # (Not required when --list-checks is the requested action; that gate is
    # enforced in main() so the listing can run with no target.)
    target_group = parser.add_mutually_exclusive_group(required=False)
    target_group.add_argument(
        "--contract",
        help="path to a .sol, .vy, or .bin file, OR an on-chain contract address",
    )
    target_group.add_argument(
        "--batch",
        metavar="PATH",
        help=(
            "directory of .sol files (scanned recursively) or a newline-delimited "
            "file of contract addresses / .sol paths. Emits JSONL output "
            "(one JSON object per contract) to stdout."
        ),
    )
    parser.add_argument(
        "--input-type",
        choices=["sol", "vyper", "bytecode", "address"],
        help="how to interpret --contract (required for a scan)",
    )
    parser.add_argument(
        "--check",
        default="all",
        choices=[*CATEGORIES, "all"],
        help="which vulnerability class to check for (default: all)",
    )
    parser.add_argument(
        "--rpc-url",
        default=None,
        help=(
            "JSON-RPC endpoint; required for --input-type address. "
            "Used read-only (eth_getCode) to fetch deployed bytecode."
        ),
    )
    parser.add_argument(
        "--format",
        default=None,
        choices=["json", "h1md", "sarif", "text"],
        help=(
            "output format. For a scan: json (default), text (a compact "
            "human-readable terminal summary), h1md, or sarif (a SARIF 2.1.0 "
            "log for GitHub code scanning / VSCode / CI). For --list-checks: "
            "text (default) or json."
        ),
    )
    parser.add_argument(
        "--min-confidence",
        default="low",
        choices=["low", "medium", "high"],
        help=(
            "suppress findings below this confidence level (default: low, i.e. "
            "keep all). Use 'medium' or 'high' to filter out the "
            "low-confidence bytecode/address heuristics when triaging large "
            "scans."
        ),
    )
    parser.add_argument(
        "--min-severity",
        default="informational",
        choices=["informational", "low", "medium", "high", "critical"],
        help=(
            "suppress findings below this severity level (default: "
            "informational, i.e. keep all). Use 'high' or 'critical' to "
            "surface only the high-impact leads first when triaging a whole "
            "program scope. Composes with --min-confidence."
        ),
    )
    parser.add_argument(
        "--sort",
        default="severity",
        choices=["severity", "none"],
        help=(
            "order findings in the report. 'severity' (default) lists them "
            "worst-first (highest severity, then highest confidence), so the "
            "high-impact leads lead every report; 'none' preserves the raw "
            "detector order. Applies after --min-severity/--min-confidence; "
            "never changes which findings appear, only their order."
        ),
    )
    parser.add_argument(
        "--limit",
        type=_positive_int,
        default=None,
        metavar="N",
        help=(
            "cap the report to at most N findings (default: no limit). Applied "
            "after --sort, so with the default worst-first ordering it keeps "
            "the N highest-impact leads — the 'show me the top N' triage move "
            "on a large scan. The report records the pre-cap total_findings and "
            "a truncated flag. In --batch mode the cap is per-contract."
        ),
    )
    parser.add_argument(
        "--fail-on",
        default="never",
        choices=["never", "informational", "low", "medium", "high", "critical"],
        help=(
            "CI exit-code gate: exit non-zero (code 3) when a finding reaches "
            "this severity. Default 'never' keeps the historical behaviour "
            "(always exit 0 on a clean run). Use e.g. 'high' to fail a pipeline "
            "step when omen surfaces a high/critical lead. Evaluated before "
            "--limit, so a display cap can never hide a finding from the gate; "
            "applies in single-contract and --batch mode."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # --- --list-checks: introspection action, runs with no target/compiler ---
    if args.list_checks:
        from .catalog import render as render_catalog

        # text is the natural default for a human-facing listing; json is
        # available for tooling. The scan-oriented h1md/sarif formats do not
        # apply to a static catalog.
        fmt = args.format or "text"
        if fmt not in ("text", "json"):
            parser.error("--list-checks supports --format text or json")
        print(render_catalog(fmt))
        return 0

    # Beyond here we are running a scan: a target and input type are required.
    if args.contract is None and args.batch is None:
        parser.error("one of --contract or --batch is required")
    if args.contract is not None and args.batch is not None:
        parser.error("--contract and --batch are mutually exclusive")
    if args.input_type is None:
        parser.error("--input-type is required for a scan")

    # h1md and sarif do not apply to batch JSONL; json is the scan default.
    if args.format is None:
        args.format = "json"

    # Validate the address-mode gate early for a clear error.
    if args.input_type == "address" and not args.rpc_url:
        parser.error("--input-type address requires --rpc-url")

    # --- Batch mode ---
    if args.batch is not None:
        from .batch import run_batch

        return run_batch(
            path=args.batch,
            input_type=args.input_type,
            check=args.check,
            rpc_url=args.rpc_url,
            min_confidence=args.min_confidence,
            min_severity=args.min_severity,
            sort=args.sort,
            limit=args.limit,
            fail_on=args.fail_on,
        )

    # --- Single-contract mode ---
    # Import the heavy analysis stack lazily so --help / --version are fast.
    from .analyzer import analyze
    from .formats import render
    from .solc_env import SolcUnavailableError
    from .sources import InputError
    from .vyper_env import VyperUnavailableError

    try:
        report = analyze(
            contract=args.contract,
            input_type=args.input_type,
            check=args.check,
            rpc_url=args.rpc_url,
            min_confidence=args.min_confidence,
            min_severity=args.min_severity,
            sort=args.sort,
            limit=args.limit,
            fail_on=args.fail_on,
        )
    except (InputError, SolcUnavailableError, VyperUnavailableError) as exc:
        print(f"omen: error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - surface analysis errors cleanly
        print(f"omen: analysis failed: {exc}", file=sys.stderr)
        return 1

    print(render(report, args.format))

    # Exit code convention: 0 = ran cleanly. Findings still mean a clean run;
    # callers parse the JSON to act on findings. (Bounty workflows want the
    # report regardless of whether anything was found.) The one exception is
    # the --fail-on CI gate (POST_V01 Rotation 2, R2.5): when it trips, exit 3
    # so a pipeline step fails while staying distinguishable from an input
    # error (2) or an analysis crash (1). The report is still printed first.
    if report.gate_triggered:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
