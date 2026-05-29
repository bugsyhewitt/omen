"""omen command-line interface.

    omen [--config PATH] --contract <path-or-address>
         --input-type {sol,vyper,bytecode,address}
         --check CATEGORY[,CATEGORY...]   (a single category, 'all', or a list)
         [--exclude-check CATEGORY[,CATEGORY...]]   (inverse selector; not 'all')
         [--rpc-url URL] [--format {json,text,h1md,sarif,gha,junit,checkstyle}]
         [--min-confidence {low,medium,high}]
         [--min-severity {informational,low,medium,high,critical}]
         [--severity-override CATEGORY=SEVERITY[,...]]
         [--sort {severity,none}] [--limit N]
         [--fail-on {never,informational,low,medium,high,critical}]
         [-o/--output-file PATH]

    omen --diff <old-report.json> <new-report.json>
         [--format {text,json}] [--fail-on {...}] [-o/--output-file PATH]

    omen --sarif-merge <report.json> [<report.json> ...]
         [--fail-on {...}] [-o/--output-file PATH]

    omen --batch <dir-or-list-file> --input-type {sol,address}
         --check {...} [--rpc-url URL] [--min-confidence {low,medium,high}]
         [--min-severity {informational,low,medium,high,critical}]
         [--sort {severity,none}] [--limit N]
         [--fail-on {never,informational,low,medium,high,critical}]
         [--parallel N] [--timeout SECONDS]
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


def _positive_float(value: str) -> float:
    """argparse type for --timeout: a positive, finite number of seconds.

    Rejects 0, negatives, NaN, and infinity — a non-positive or non-finite
    per-contract budget would either abandon every scan or never trip, which is
    almost always a mistake; omen errors instead. A fractional value (e.g.
    ``2.5``) is allowed, since a sub-second or fractional wall-clock budget is
    sensible (unlike the integer-only --limit / --parallel counts).
    """
    import math

    try:
        n = float(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError(
            f"--timeout must be a positive number of seconds, got {value!r}"
        )
    if not math.isfinite(n) or n <= 0:
        raise argparse.ArgumentTypeError(
            f"--timeout must be a positive number of seconds (> 0), got {n}"
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
        "--diff",
        nargs=2,
        default=None,
        metavar=("OLD", "NEW"),
        help=(
            "compare two previously-saved omen JSON reports and print the delta "
            "— findings added (in NEW, not OLD), removed (in OLD, not NEW), and "
            "the unchanged count (POST_V01 R3.2). The temporal complement to "
            "--baseline: where --baseline suppresses known findings during a live "
            "scan, --diff reports what changed between two already-saved reports, "
            "a pure offline operation needing no contract, compiler, or network. "
            "Each report may be a single-contract JSON, a JSON array of them, or a "
            "--batch JSONL stream. A finding's identity is its fingerprint "
            "(category + detector + contract + location), so a --severity-override "
            "re-stamp or a Slither wording change does not show up as churn. "
            "Honors --format (text default, or json) and --fail-on (which gates on "
            "the *added* findings — exit 3 when a newly-introduced finding reaches "
            "the chosen severity — the 'fail the PR on regressions' CI move). A "
            "missing/unreadable/non-JSON report is a usage error."
        ),
    )
    parser.add_argument(
        "--sarif-merge",
        nargs="+",
        default=None,
        metavar="REPORT",
        help=(
            "consolidate two or more previously-saved omen JSON reports into a "
            "single SARIF 2.1.0 document (POST_V01 R3.4). The spatial complement "
            "to --diff: where --diff reports the delta between two reports, "
            "--sarif-merge unions the findings of N reports into one "
            "code-scanning upload — the fix for a per-module CI matrix or a "
            "sharded scan that emits one report per run but needs one SARIF for "
            "GitHub Advanced Security (which takes one document per upload). Each "
            "REPORT may be a single-contract JSON, a JSON array, or a --batch "
            "JSONL stream. Findings shared across inputs are deduplicated by "
            "fingerprint (category + detector + contract + location, the same "
            "identity --baseline/--diff use), so an overlapping contract is not "
            "double-counted; output is worst-first and deterministic regardless "
            "of input order. A pure offline action needing no contract, compiler, "
            "or network. Output is always SARIF (--format is rejected); honors -o "
            "and --fail-on (which gates on the merged findings — exit 3). A "
            "missing/unreadable/non-JSON report is a usage error."
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
        choices=["json", "h1md", "sarif", "text", "gha", "junit", "checkstyle"],
        help=(
            "output format. For a scan: json (default), text (a compact "
            "human-readable terminal summary), h1md, sarif (a SARIF 2.1.0 "
            "log for GitHub code scanning / VSCode / CI), gha (GitHub "
            "Actions workflow-command annotations — ::error/::warning/::notice "
            "lines the Actions runner turns into inline PR-diff annotations on "
            "every repo for free, no Advanced-Security upload; POST_V01 R3.5), "
            "junit (a JUnit XML test-results report — one failing testcase "
            "per finding, ingested natively by GitHub Actions test reporters, "
            "GitLab CI, Jenkins, CircleCI, Azure DevOps, and TeamCity so omen "
            "findings land in the CI tests tab on any CI; POST_V01 R3.6), "
            "or checkstyle (a Checkstyle XML document — one <error> per finding "
            "grouped under <file> elements, the static-analysis lingua franca "
            "ingested natively by GitLab CI's Code Quality widget, Reviewdog, "
            "SonarQube, and the Jenkins Checkstyle plugin so findings surface "
            "as code-review annotations in the MR/PR diff; POST_V01 R3.7). "
            "For --list-checks: text (default) or json."
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
        "--baseline",
        default=None,
        metavar="PATH",
        help=(
            "suppress findings already present in PATH — a previously-saved omen "
            "JSON report (a single-contract report, or one line / the whole JSONL "
            "stream of a --batch run) used as a known-good baseline (POST_V01). "
            "Only findings *new* relative to the baseline appear in the report, "
            "count toward the totals, and trip the --fail-on gate. This is the "
            "'adopt omen on a legacy codebase' CI move: capture today's findings "
            "with `omen ... -o baseline.json`, commit it, then run with "
            "`--baseline baseline.json --fail-on high` so the pipeline fails only "
            "on issues introduced after the baseline. A finding's identity is its "
            "category + detector + contract + location (severity/wording changes "
            "do not make a known finding look new). Applies in single and --batch "
            "mode; a missing/unreadable/non-JSON baseline is a usage error."
        ),
    )
    parser.add_argument(
        "--sarif-baseline",
        default=None,
        metavar="PATH",
        help=(
            "annotate SARIF output with a per-result baselineState (POST_V01 "
            "R3.3): the SARIF-native, GitHub-code-scanning suppression lever. "
            "PATH is a previously-saved omen JSON report (single-contract, a JSON "
            "array, or a --batch JSONL stream) used as a known-good baseline. "
            "Every SARIF result is tagged baselineState 'unchanged' if its "
            "finding fingerprint (category + detector + contract + location, the "
            "same identity --baseline uses) is already in PATH, or 'new' if it "
            "was introduced since. Unlike --baseline, which *drops* known "
            "findings from the report, --sarif-baseline *keeps* every result so "
            "GitHub Advanced Security can fold the pre-existing ('unchanged') "
            "alerts into its baseline view while surfacing the 'new' ones — the "
            "native suppression a code-scanning workflow expects. Requires "
            "--format sarif and single --contract mode (batch emits JSONL, not "
            "SARIF); a missing/unreadable/non-JSON baseline is a usage error."
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
        "--parallel",
        type=_positive_int,
        default=None,
        metavar="N",
        help=(
            "in --batch mode, analyze up to N contracts concurrently (default: "
            "1, i.e. sequential — the historical behaviour). Use a higher N to "
            "speed up a whole-program scan of dozens-to-hundreds of contracts; "
            "the wall-clock win comes from the solc/vyper compiler each scan "
            "shells out to. Output, the --fail-on gate, the error count, and the "
            "--batch-summary roll-up stay in deterministic input order, so a "
            "parallel run's JSONL and exit code are identical to the sequential "
            "run's — only faster. No effect in single --contract mode."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=_positive_float,
        default=None,
        metavar="SECONDS",
        help=(
            "in --batch mode, give each contract at most SECONDS of wall-clock "
            "analysis time (POST_V01 R2.14; default: no budget). A contract whose "
            "scan overruns is abandoned and recorded as a per-item error (it "
            "counts toward the exit-1 error tally and the --batch-summary error "
            "count, with a message to stderr) so the batch makes progress past "
            "it — one pathological contract (a hanging compiler, a runaway "
            "symbolic path) can't stall a whole-program scan of dozens-to-"
            "hundreds of contracts. Fractional seconds are allowed (e.g. 2.5). "
            "Enforced on the same thread-pool seam as --parallel, so it composes "
            "with it; output, the --fail-on gate, the error count, and the "
            "summary all stay in deterministic input order. No effect in single "
            "--contract mode."
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

    # --- --diff: offline report-to-report delta (POST_V01 R3.2) ---------------
    # Like --list-checks, this runs with no target/compiler/network: it compares
    # two already-saved omen JSON reports. text is the human-facing default; json
    # is available for automation. The scan-oriented h1md/sarif formats do not
    # apply to a report delta. --fail-on gates on the *added* findings so a PR
    # gate can fail only on newly-introduced findings (exit 3), mirroring the scan
    # --fail-on convention; a broken report path is an exit-2 usage error.
    if args.diff is not None:
        from .diff import build_diff, diff_gate_triggered
        from .diff import render as render_diff

        fmt = args.format or "text"
        if fmt not in ("text", "json"):
            parser.error("--diff supports --format text or json")
        old_path, new_path = args.diff
        try:
            diff = build_diff(old_path, new_path)
        except ValueError as exc:
            parser.error(str(exc))
        write_output(render_diff(diff, fmt), args.output_file)
        if diff_gate_triggered(diff, args.fail_on):
            return 3
        return 0

    # --- --sarif-merge: offline multi-run SARIF consolidation (POST_V01 R3.4) --
    # Like --diff/--list-checks, a pure offline action: it unions the findings of
    # N already-saved omen reports into one SARIF document, needing no
    # target/compiler/network. Output is always SARIF (it is in the flag's name),
    # so an explicit --format is a usage error — there is no text/json/h1md
    # analogue of a consolidated code-scanning upload. -o redirects the document;
    # --fail-on gates on the merged, deduplicated findings (exit 3), mirroring the
    # scan/--diff convention. A broken report path is an exit-2 usage error,
    # surfaced before any work, consistent with --diff/--baseline.
    if args.sarif_merge is not None:
        from .merge import build_merged_sarif, merge_gate_triggered

        if args.format is not None and args.format != "sarif":
            parser.error("--sarif-merge always emits SARIF; --format is not allowed")
        try:
            document = build_merged_sarif(args.sarif_merge)
        except ValueError as exc:
            parser.error(str(exc))
        write_output(document, args.output_file)
        if merge_gate_triggered(args.sarif_merge, args.fail_on):
            return 3
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

    # Validate --baseline up front (POST_V01): load the baseline report now so a
    # missing/unreadable/non-JSON file is surfaced as a usage error (exit 2)
    # before any compiler/network work, consistent with the other up-front
    # validations above. The parsed fingerprint set is recomputed inside analyze
    # (it is cheap and keeps analyze a self-contained entry point); this call is
    # purely the early validation gate.
    if args.baseline is not None:
        from .findings import load_baseline_fingerprints

        try:
            load_baseline_fingerprints(args.baseline)
        except ValueError as exc:
            parser.error(str(exc))

    # Validate --sarif-baseline up front (POST_V01 R3.3): it only makes sense for
    # SARIF output in single-contract mode (batch emits JSONL, never a SARIF
    # document, so there is no per-result baselineState to annotate). Surface a
    # misuse as a usage error (exit 2) here, then load the baseline so a
    # missing/unreadable/non-JSON file is also an exit-2 error before any
    # compiler/network work — consistent with --baseline above. The fingerprint
    # set computed here is reused for the render below (single mode).
    sarif_baseline_fps: set[str] | None = None
    if args.sarif_baseline is not None:
        if args.batch is not None:
            parser.error(
                "--sarif-baseline applies to single --contract SARIF output, "
                "not --batch (batch emits JSONL, not a SARIF document)"
            )
        if args.format != "sarif":
            parser.error("--sarif-baseline requires --format sarif")
        from .findings import load_baseline_fingerprints

        try:
            sarif_baseline_fps = load_baseline_fingerprints(args.sarif_baseline)
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
            parallel=args.parallel,
            timeout=args.timeout,
            baseline=args.baseline,
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
            baseline=args.baseline,
        )
    except (InputError, SolcUnavailableError, VyperUnavailableError) as exc:
        print(f"omen: error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - surface analysis errors cleanly
        print(f"omen: analysis failed: {exc}", file=sys.stderr)
        return 1

    write_output(
        render(report, args.format, sarif_baseline=sarif_baseline_fps),
        args.output_file,
    )

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
