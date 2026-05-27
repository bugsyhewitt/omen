"""omen command-line interface.

    omen --contract <path-or-address> --input-type {sol,bytecode,address}
         --check {prodigal,suicidal,greedy,reentrancy,access-control,tx-origin,all}
         [--rpc-url URL] [--format {json,h1md}]

    omen --batch <dir-or-list-file> --input-type {sol,address}
         --check {...} [--rpc-url URL]

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

    # --contract and --batch are mutually exclusive; exactly one is required.
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "--contract",
        help="path to a .sol or .bin file, OR an on-chain contract address",
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
        required=True,
        choices=["sol", "bytecode", "address"],
        help="how to interpret --contract",
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
        default="json",
        choices=["json", "h1md"],
        help="output format (default: json)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

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
        )

    # --- Single-contract mode ---
    # Import the heavy analysis stack lazily so --help / --version are fast.
    from .analyzer import analyze
    from .formats import render
    from .solc_env import SolcUnavailableError
    from .sources import InputError

    try:
        report = analyze(
            contract=args.contract,
            input_type=args.input_type,
            check=args.check,
            rpc_url=args.rpc_url,
        )
    except (InputError, SolcUnavailableError) as exc:
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
