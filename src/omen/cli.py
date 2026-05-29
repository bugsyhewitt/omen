"""omen command-line interface.

    omen [--config PATH] --contract <path-or-address>
         --input-type {sol,vyper,bytecode,address}
         --check CATEGORY[,CATEGORY...]   (a single category, 'all', or a list)
         [--exclude-check CATEGORY[,CATEGORY...]]   (inverse selector; not 'all')
         [--rpc-url URL] [--format {json,text,h1md,sarif}]
         [--min-confidence {low,medium,high}]
         [--min-severity {informational,low,medium,high,critical}]
         [--severity-override CATEGORY=SEVERITY[,...]]
         [--sort {severity,none}] [--limit N]
         [--fail-on {never,informational,low,medium,high,critical}]
         [-o/--output-file PATH]

    omen --batch <dir-or-list-file> --input-type {sol,address}
         --check {...} [--rpc-url URL] [--min-confidence {low,medium,high}]
         [--min-severity {informational,low,medium,high,critical}]
         [--sort {severity,none}] [--limit N]
         [--fail-on {never,informational,low,medium,high,critical}]
         [-o/--output-file PATH]

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
import os
import sys
from pathlib import Path

from . import CATEGORIES, __version__


def write_output(text: str, output_file: str | None) -> None:
    """Emit *text* to *output_file*, or to stdout when *output_file* is None.

    When a path is given the write is atomic: the content goes to a sibling
    ``<name>.tmp`` first and is then ``os.replace``-d into place, so a crash
    mid-write (or a half-finished batch stream) never clobbers a previously
    good report with a truncated one. Parent directories are created on demand.
    A trailing newline is appended (matching ``print``) so the file ends cleanly.
    """
    if output_file is None:
        print(text)
        return
    path = Path(output_file)
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text + "\n", encoding="utf-8")
    os.replace(tmp, path)


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


def _explicitly_set_dests(
    parser: argparse.ArgumentParser, argv: list[str] | None
) -> set[str]:
    """Return the set of argparse dests the user actually passed on *argv*.

    We cannot tell "user typed --sort severity" from "argparse filled the
    default severity" by inspecting the parsed Namespace — both look identical.
    So we re-parse *argv* against a clone of *parser* whose every argument
    defaults to ``argparse.SUPPRESS``; suppressed defaults are omitted from the
    Namespace, so whatever *is* present was set on the command line. This is the
    standard way to distinguish "passed" from "defaulted" without intercepting
    the parse, and it keeps the user-facing parser (help text, error messages)
    completely unchanged.

    Only used to decide which slots a ``--config`` value may fill; CLI flags
    always win over the file.
    """
    sentinel = argparse.ArgumentParser(add_help=False)
    # Recreate every optional/positional action with a suppressed default. Skip
    # the help and version actions (they exit) and any positionals (omen has
    # none). Mutually-exclusive grouping is irrelevant here — we never trigger
    # the group's required check because the sentinel parse mirrors the real one.
    for action in parser._actions:
        if isinstance(
            action, (argparse._HelpAction, argparse._VersionAction)
        ):
            continue
        if not action.option_strings:
            continue
        kwargs: dict[str, Any] = {"dest": action.dest, "default": argparse.SUPPRESS}
        if isinstance(action, argparse._StoreTrueAction):
            kwargs["action"] = "store_true"
        else:
            # Re-accept a value without re-validating type/choices (the real
            # parser already does that); we only care about presence.
            kwargs["nargs"] = "?"
        try:
            sentinel.add_argument(*action.option_strings, **kwargs)
        except argparse.ArgumentError:  # pragma: no cover - defensive
            continue
    ns, _ = sentinel.parse_known_args(argv)
    return set(vars(ns))


def _apply_config(
    args: argparse.Namespace,
    config: dict[str, Any],
    explicit: set[str],
) -> None:
    """Fill *args* slots from *config* that the user did not set on the CLI.

    Precedence (highest first): explicit CLI flag, then config-file value, then
    the argparse default already sitting in *args*. A config key only writes into
    a dest that is **not** in *explicit*, so passing a flag on the command line
    always overrides the file. Keys the parser does not own are ignored here
    (``load_config`` already rejected unknown keys, so this is belt-and-braces).
    """
    for key, value in config.items():
        if key in explicit:
            continue
        if hasattr(args, key):
            setattr(args, key, value)


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
        "--config",
        default=None,
        metavar="PATH",
        help=(
            "load a TOML config file that sets default values for the other "
            "flags (POST_V01 R2.10). Keys are flag names with the leading '--' "
            "dropped (dashes or underscores both work), e.g. min-severity, "
            "output-file, check; values are validated against the same choices "
            "the flags enforce. Keys may live at the top level or under an "
            "[omen] table. CLI flags always override the file, so a committed "
            "omen.toml shrinks repeated invocations while staying overridable "
            "ad hoc. Pure stdlib (tomllib); no dependency."
        ),
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
        metavar="CATEGORY[,CATEGORY...]",
        help=(
            "which vulnerability class(es) to check for (default: all). Accepts "
            "a single category, 'all', or a comma-separated list (e.g. "
            "'access-control,delegatecall,upgrade' to scope a scan to the "
            f"proxy/admin attack cluster). Valid categories: {', '.join(CATEGORIES)}. "
            "'all' must be used alone."
        ),
    )
    parser.add_argument(
        "--exclude-check",
        default=None,
        metavar="CATEGORY[,CATEGORY...]",
        help=(
            "remove one or more categories from the --check set (the inverse "
            "selector). Accepts a single category or a comma-separated list "
            "(not 'all'). Pairs with the default '--check all' to express "
            "'every class except these', e.g. '--exclude-check greedy,prodigal' "
            "to drop the two noisiest bytecode heuristics. Excluding a class "
            "--check did not select is a no-op; excluding every selected class "
            "is an error."
        ),
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
        "--severity-override",
        default=None,
        metavar="CATEGORY=SEVERITY[,...]",
        help=(
            "org-specific risk tuning: pin the severity omen reports for one or "
            "more detection classes to your own risk model, overriding the "
            "built-in defaults (and, in source mode, Slither's per-finding "
            "impact). A comma-separated list of CATEGORY=SEVERITY pairs, e.g. "
            "'--severity-override reentrancy=critical,tx-origin=high'. SEVERITY "
            "is one of informational/low/medium/high/critical. The override is "
            "applied before --min-severity, --sort, --limit, and --fail-on, so a "
            "pinned class surfaces and gates at the configured level (and a class "
            "pinned down can be filtered out as noise). Applies in single and "
            "--batch mode. Only the severity changes; the finding stays traceable."
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
        "-o",
        "--output-file",
        default=None,
        metavar="PATH",
        help=(
            "write the report to PATH instead of stdout (default: stdout). "
            "Composes with every --format: in single-contract mode PATH gets "
            "the rendered json/text/h1md/sarif report; in --batch mode PATH "
            "gets the JSONL stream (one JSON object per contract). The file is "
            "written atomically (a sibling .tmp is renamed into place) so a "
            "partial report never overwrites a good one if the scan crashes "
            "mid-write. Parent directories are created as needed. The --fail-on "
            "exit code is unaffected — the gate trips the same whether the "
            "report went to a file or stdout."
        ),
    )
    parser.add_argument(
        "--ignore",
        default=None,
        metavar="PATTERN[,PATTERN...]",
        help=(
            "in --batch mode, skip contract paths/addresses matching any of "
            "these comma-separated glob patterns (POST_V01 R2.11). A pattern "
            "matches the full path, any single path component, or — when it "
            "contains a '/' — any sub-path, so '--ignore node_modules,lib,test' "
            "drops vendored/third-party trees (e.g. an OpenZeppelin import tree) "
            "from a recursive directory scan or a list file without hand-pruning "
            "the input. Globs support *, ?, and [seq]. Ignored items produce no "
            "output and no error. No effect in single --contract mode."
        ),
    )
    parser.add_argument(
        "--batch-summary",
        action="store_true",
        help=(
            "in --batch mode, print an aggregate roll-up to stderr after the "
            "JSONL stream (POST_V01 R2.12): contracts scanned / with findings / "
            "errored, total findings by severity (worst-first), and the "
            "worst-affected contracts. Answers 'what did the whole-program scan "
            "find, overall?' without piping the JSONL through jq. Goes to stderr "
            "so the stdout JSONL stays machine-clean. No effect in single "
            "--contract mode."
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

    # --- --config: TOML defaults for the other flags (POST_V01 R2.10) ---------
    # Load the file (if any) and fill in only the flags the user did *not* pass
    # on the command line. CLI flags always win; the file is a default source
    # that sits above the built-in defaults. --config's own path can only come
    # from the CLI (a config file cannot set the config path).
    if args.config is not None:
        from .config import ConfigError, load_config

        try:
            cfg = load_config(args.config)
        except ConfigError as exc:
            parser.error(str(exc))
        _apply_config(args, cfg, _explicitly_set_dests(parser, argv))

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

    # Validate --check up front (POST_V01 Rotation 2, R2.7): it accepts a single
    # category, 'all', or a comma-separated list, so argparse `choices` can no
    # longer enforce it. resolve_checks parses/validates the value; surface a bad
    # one as an argparse-style usage error (exit 2) rather than letting it fall
    # through to a runtime analysis error. The import is local so --help/--version
    # stay free of the analysis stack; resolve_checks itself imports nothing heavy.
    from .analyzer import resolve_checks

    try:
        resolve_checks(args.check, args.exclude_check)
    except ValueError as exc:
        parser.error(str(exc))

    # Validate --ignore up front (POST_V01 R2.11): it is a comma-separated glob
    # list, so argparse cannot enforce it. parse_ignore rejects an all-blank
    # value; surface that as a usage error (exit 2) rather than a runtime crash.
    # --ignore only affects --batch input selection; flag it as a no-op (not an
    # error) under --contract so a committed omen.toml carrying it still works
    # for single scans.
    from .batch import parse_ignore

    try:
        parse_ignore(args.ignore)
    except ValueError as exc:
        parser.error(str(exc))

    # Validate --severity-override up front (org-specific risk tuning): it is a
    # comma-separated CATEGORY=SEVERITY list, so argparse cannot enforce it.
    # parse_severity_overrides rejects a malformed pair, an unknown category, or
    # an unknown severity; surface that as a usage error (exit 2) rather than a
    # runtime crash, consistent with --check / --ignore validation above.
    from .findings import parse_severity_overrides

    try:
        parse_severity_overrides(args.severity_override)
    except ValueError as exc:
        parser.error(str(exc))

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
            exclude_check=args.exclude_check,
            output_file=args.output_file,
            ignore=args.ignore,
            batch_summary=args.batch_summary,
            severity_override=args.severity_override,
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
            exclude_check=args.exclude_check,
            severity_override=args.severity_override,
        )
    except (InputError, SolcUnavailableError, VyperUnavailableError) as exc:
        print(f"omen: error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - surface analysis errors cleanly
        print(f"omen: analysis failed: {exc}", file=sys.stderr)
        return 1

    write_output(render(report, args.format), args.output_file)

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
