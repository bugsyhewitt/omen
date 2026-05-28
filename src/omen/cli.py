"""omen command-line interface.

    omen --contract <path-or-address> --input-type {sol,vyper,bytecode,address}
         --check {prodigal,suicidal,greedy,reentrancy,access-control,tx-origin,all}
         [--rpc-url URL] [--format {json,h1md,sarif}]
         [--min-confidence {low,medium,high}]
         [--min-severity {informational,low,medium,high,critical}]

    omen --batch <dir-or-list-file> --input-type {sol,address}
         --check {...} [--rpc-url URL] [--min-confidence {low,medium,high}]
         [--min-severity {informational,low,medium,high,critical}]

Text in, text out. JSON is the default machine-readable format.
Batch mode always emits JSONL (one JSON object per contract).
"""

from __future__ import annotations

import argparse
import sys

from . import CATEGORIES, __version__


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
            "output format. For a scan: json (default), h1md, or sarif (a "
            "SARIF 2.1.0 log for GitHub code scanning / VSCode / CI). For "
            "--list-checks: text (default) or json."
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
    # report regardless of whether anything was found.)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
