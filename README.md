# omen

**omen** is a bounty-oriented hybrid scanner for Ethereum **trace vulnerabilities** — the MAIAN class — with modern EVM support. It is built for web3 bug-bounty work, not as yet-another general-purpose linter.

It detects classes of contract that leak, lock, or surrender funds — plus the two highest-loss authorization bugs, broken access control and `tx.origin` misuse — and reports each finding with reproducibility evidence (source locations or bytecode opcode offsets).

omen builds on [Slither](https://github.com/crytic/slither) for source analysis and on [`pyevmasm`](https://github.com/crytic/pyevmasm) for bytecode disassembly. The trace-vulnerability taxonomy comes from MAIAN (Nikolić et al., 2018) — see [`NOTICE`](./NOTICE).

> **omen performs analysis only. It never submits a transaction — not against a testnet, not against mainnet, not with any flag.** Address mode is strictly read-only (`eth_getCode`).

---

## The detection classes

The four MAIAN trace-vulnerability classes plus reentrancy:

| Class | What it means | omen detects via |
|---|---|---|
| **prodigal** | Leaks Ether to *arbitrary* users who never deposited it | Slither `arbitrary-send-eth` |
| **suicidal** | Can be destroyed (`selfdestruct`) by anyone — the Parity wallet incident | Slither `suicidal`; bytecode `SELFDESTRUCT` opcode |
| **greedy** | Can receive Ether but has no reachable path to release it — funds locked forever | Slither `locked-ether` |
| **reentrancy** | Classic withdraw-before-state-update bug behind the DAO hack | Slither `reentrancy-eth`, `reentrancy-balance` |

Plus the two highest-loss authorization classes (added in R2):

| Class | What it means | omen detects via |
|---|---|---|
| **access-control** | Privileged state/functions missing or misusing access restrictions — OWASP's #1 loss category (Smart Contract Top 10 2025/2026) | Slither `protected-vars`, `events-access` |
| **tx-origin** | `tx.origin` used for authentication, exploitable via a phishing-relay attack | Slither `tx-origin` |

Plus the proxy/upgrade high-severity cluster (added in R5):

| Class | What it means | omen detects via |
|---|---|---|
| **delegatecall** | `delegatecall` to an attacker-influenceable target or function id — the callee runs in this contract's storage/balance context and can overwrite state or destroy the contract (the second Parity multisig freeze) | Slither `controlled-delegatecall`, `delegatecall-loop` |
| **upgrade** | An upgradeable (proxy) implementation whose initialize/upgrade path is unprotected — anyone can initialize it, become owner, and seize the proxy (the Wormhole uninitialized-implementation class) | Slither `unprotected-upgrade` |

> **delegatecall/upgrade note.** Both are **source-mode** checks. Slither's
> `controlled-delegatecall` fires when the delegatecall target *or* its function
> id is influenced by input or mutable state; a `delegatecall` to a
> compile-time-`constant` library with a hardcoded selector is considered safe.
> `unprotected-upgrade` flags an `Initializable` implementation that omits
> `_disableInitializers()` in its constructor. (The roadmap's proposed
> `dangerous-delegatecall` Slither argument does not exist in slither-analyzer
> 0.11.x; the canonical detector is `controlled-delegatecall`.)

Plus the medium-severity completeness cluster (added in R8):

| Class | What it means | omen detects via |
|---|---|---|
| **overflow** | Unsafe arithmetic — most often an integer division performed *before* a multiplication, which truncates and silently loses precision; also tautological comparisons that signal a broken bounds/overflow guard. Solidity 0.8+ reverts on raw overflow by default, so pre-0.8 contracts are the primary target | Slither `divide-before-multiply`, `tautology` |
| **weak-randomness** | On-chain randomness derived from predictable, miner/validator-manipulable values (`block.timestamp`, `blockhash`, `block.number`, `prevrandao`) — an attacker can force a favorable outcome | Slither `weak-prng` |

> **overflow/weak-randomness note.** Both are **source-mode** checks. They are
> medium-severity completeness classes: useful on older or non-financial
> contracts where they may be the root cause, but rarely a standalone critical.
> (The roadmap's proposed `integer-overflow` Slither argument does not exist in
> slither-analyzer 0.11.x — Slither ships no standalone overflow detector since
> 0.8 made raw overflow a revert — so omen maps `overflow` onto the real
> arithmetic-precision detectors `divide-before-multiply` and `tautology`.
> `weak-randomness` maps onto `weak-prng`, which Slither classifies HIGH impact,
> so a weak-PRNG finding surfaces at HIGH severity at runtime even though the
> class default is MEDIUM.)

> **access-control note.** Slither's high-confidence `protected-vars` detector keys off the `@custom:security write-protection="onlyOwner()"` NatSpec annotation on the state variable that gates access: it flags any function that writes that variable *without* going through the named guard. Annotate the variables you intend to protect and omen will catch the missing guard. `events-access` complements it by flagging admin/ownership changes that emit no event.

---

## Install

omen targets **Python 3.13+**.

```bash
git clone https://github.com/bugsyhewitt/omen
cd omen
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

Source mode (`--input-type sol`) compiles Solidity and needs a `solc` binary
on `PATH`. The easiest path is `solc-select`, which is installed for you as a
dependency of Slither:

```bash
solc-select install 0.8.19
solc-select use 0.8.19
```

Vyper source mode (`--input-type vyper`) compiles `.vy` files and needs a
`vyper` binary on `PATH` instead of `solc`:

```bash
pip install vyper        # or: pipx install vyper
```

Bytecode mode (`--input-type bytecode`) and address mode (`--input-type address`)
need **no** compiler at all.

---

## Usage

```
omen [--config PATH] \
     --contract <path-or-address> \
     --input-type {sol,vyper,bytecode,address} \
     --check CATEGORY[,CATEGORY...]   # a category, 'all', or a comma-separated list \
     [--exclude-check CATEGORY[,CATEGORY...]]   # inverse selector; not 'all' \
     [--rpc-url URL] \
     [--format {json,text,h1md,sarif,gha,junit}] \
     [--min-confidence {low,medium,high}] \
     [--min-severity {informational,low,medium,high,critical}] \
     [--severity-override CATEGORY=SEVERITY[,...]]   # org-specific risk tuning \
     [--sort {severity,none}] \
     [--limit N] \
     [--baseline PATH]                # suppress findings already in a known-good baseline \
     [--sarif-baseline PATH]          # tag SARIF results new/unchanged vs a baseline (needs --format sarif) \
     [--fail-on {never,informational,low,medium,high,critical}] \
     [-o/--output-file PATH]

omen --batch <dir-or-list-file> \
     --input-type {sol,address} \
     [--ignore PATTERN[,PATTERN...]]   # skip vendored/third-party paths \
     [--parallel N]                    # analyze N contracts concurrently \
     [--timeout SECONDS]               # per-contract wall-clock budget; abandon overruns \
     [--batch-summary]                 # aggregate roll-up to stderr after the JSONL \
     [--baseline PATH]                 # suppress findings already in a known-good baseline \
     [--check ...] [--rpc-url URL] [--min-confidence ...] [--min-severity ...] \
     [--severity-override CATEGORY=SEVERITY[,...]] \
     [--sort ...] [--limit N] [--fail-on ...] [-o/--output-file PATH]

omen --diff <old-report.json> <new-report.json> \
     [--format {text,json}]            # text (default) or machine-readable json \
     [--fail-on {never,…,critical}]    # gate on the *added* findings (exit 3) \
     [-o/--output-file PATH]

omen --sarif-merge <report.json> [<report.json> ...] \
     [--fail-on {never,…,critical}]    # gate on the merged findings (exit 3) \
     [-o/--output-file PATH]           # always emits SARIF

omen --list-checks [--format {text,json}]
```

- `--config` — load a TOML config file that sets **default** values for the other flags. Lets a repo commit a single `omen.toml` and shrink long, repeated invocations. CLI flags always override the file. Pure stdlib (`tomllib`); no dependency. See [Config files (`omen.toml`)](#config-files-omentoml).
- `--contract` — a path to a `.sol` source file, a path to a `.vy` (Vyper) source file, a path to a `.bin` (hex EVM runtime bytecode) file, or an on-chain contract address.
- `--input-type` — how to interpret `--contract`.
- `--check` — which class(es) to scan for. Accepts a single category, `all` (runs every class), or a **comma-separated list** of categories (e.g. `access-control,delegatecall,upgrade` to scope a scan to the proxy/admin attack cluster). Valid categories: `prodigal`, `suicidal`, `greedy`, `reentrancy`, `access-control`, `tx-origin`, `delegatecall`, `upgrade`, `overflow`, `weak-randomness`. `all` must be used alone. Default: `all`. See [Scoping a scan to specific classes](#scoping-a-scan-to-specific-classes).
- `--exclude-check` — remove one or more categories from the `--check` set (the inverse selector). Accepts a single category or a **comma-separated list** (not `all`). Pairs with the default `--check all` to express "every class except these" — e.g. `--exclude-check greedy,prodigal` to drop the two noisiest bytecode heuristics. Excluding a class `--check` did not select is a no-op; excluding *every* selected class is a usage error (exit `2`). Default: exclude nothing. Applies in single-contract and `--batch` mode alike. See [Excluding classes from a scan](#excluding-classes-from-a-scan).
- `--rpc-url` — JSON-RPC endpoint; **required** for `--input-type address`. Used read-only.
- `--format` — `json` (machine-readable, default), `text` (a compact human-readable terminal summary — a per-severity count line plus one line per finding, worst-first; see [Text output](#text-output)), `h1md` (a HackerOne-style markdown report), `sarif` (a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) log for GitHub code scanning, VSCode, and CI ingestion), `gha` (GitHub Actions [workflow-command](https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions) annotations — `::error`/`::warning`/`::notice` lines the Actions runner turns into inline PR-diff annotations on **every** repo for free, with no Advanced-Security upload; see [GitHub Actions annotations](#github-actions-annotations)), or `junit` (a [JUnit XML](https://github.com/testmoapp/junitxml) test-results report — one failing `<testcase>` per finding under a single `<testsuite>`, the platform-agnostic format ingested natively by GitHub Actions test reporters, GitLab CI, Jenkins, CircleCI, Azure DevOps, and TeamCity so omen findings land in the CI **tests** tab and fail the build on essentially any CI; see [JUnit XML output](#junit-xml-output)).
- `--min-confidence` — suppress findings below this confidence level (`low`, `medium`, or `high`). Default: `low` (keep everything). Use `medium` or `high` to filter out the low-confidence bytecode/address heuristics when triaging large scans. Applies in single-contract and `--batch` mode alike.
- `--min-severity` — suppress findings below this severity level (`informational`, `low`, `medium`, `high`, or `critical`). Default: `informational` (keep everything). Use `high` or `critical` to surface only the high-impact leads first when triaging a whole program scope. Composes with `--min-confidence` (a finding must pass both) and applies in single-contract and `--batch` mode alike.
- `--severity-override` — **org-specific risk tuning**: pin the severity omen reports for one or more detection classes to your own risk model, overriding the built-in defaults (and, in source mode, Slither's per-finding impact). A comma-separated list of `CATEGORY=SEVERITY` pairs, e.g. `--severity-override reentrancy=critical,tx-origin=high`. `SEVERITY` is one of `informational`/`low`/`medium`/`high`/`critical`. The override is applied *before* `--min-severity`, `--sort`, `--limit`, and `--fail-on`, so a pinned class surfaces and gates at the configured level (and a class pinned *down* can be filtered out as noise). Only the severity changes — the finding's category, confidence, evidence, and detector id are preserved, so it stays fully traceable. Applies in single-contract and `--batch` mode alike, and can be set in `omen.toml`. Default: override nothing. See [Overriding severity per class](#overriding-severity-per-class).
- `--sort` — order findings in the report. `severity` (default) lists them worst-first — highest severity, then highest confidence — so the high-impact leads appear at the top of every report; `none` preserves the raw detector order. Sorting runs *after* `--min-severity`/`--min-confidence`, so it never changes which findings appear, only their order. Applies in single-contract and `--batch` mode alike — see [Sorting findings](#sorting-findings).
- `--limit` — cap the report to at most `N` findings (a positive integer). Default: no limit (keep all). Applied *after* `--sort`, so with the default worst-first ordering it keeps the `N` highest-impact leads — the "show me the top N" triage move on a large scan. The report records the pre-cap `total_findings` and a `truncated` flag so a consumer can tell "10 of 47 shown" from "10 of 10". In `--batch` mode the cap is per-contract — see [Limiting findings](#limiting-findings).
- `--baseline` — suppress findings already present in `PATH`, a previously-saved omen JSON report (a single-contract report, or one line / the whole JSONL stream of a `--batch` run) used as a **known-good baseline**. Only findings *new* relative to the baseline appear in the report, count toward the totals, and trip the `--fail-on` gate. This is the "adopt omen on a legacy codebase" CI move: capture today's findings with `omen … -o baseline.json`, commit it, then run with `--baseline baseline.json --fail-on high` so the pipeline fails only on issues introduced *after* the baseline. A finding's identity for matching is its category + detector + contract + location, so a `--severity-override` re-stamp or a Slither wording change does not make a known finding look new. Applies in single-contract and `--batch` mode alike, and can be set in `omen.toml`; a missing/unreadable/non-JSON baseline is a usage error (exit `2`). Default: suppress nothing. See [Suppressing known findings with a baseline](#suppressing-known-findings-with-a-baseline).
- `--sarif-baseline` — annotate SARIF output with a per-result `baselineState` from a known-good baseline `PATH` (a previously-saved omen JSON report, like `--baseline`). Each SARIF result is tagged `baselineState: "unchanged"` if its finding fingerprint (category + detector + contract + location) is already in `PATH`, or `"new"` if it was introduced since. Unlike `--baseline`, which *drops* known findings from the report, `--sarif-baseline` **keeps every result** so GitHub Advanced Security folds the pre-existing (`unchanged`) alerts into its baseline view while surfacing the `new` ones — the SARIF-native, code-scanning way to suppress known noise. Requires `--format sarif` and single-`--contract` mode (`--batch` emits JSONL, not a SARIF document); can be set in `omen.toml`; a missing/unreadable/non-JSON baseline is a usage error (exit `2`). Default: no `baselineState`. See [SARIF-native suppression with a baseline](#sarif-native-suppression-with-a-baseline).
- `--fail-on` — CI exit-code gate: exit non-zero (code `3`) when a finding reaches this severity (`informational`, `low`, `medium`, `high`, or `critical`). Default: `never` (always exit `0` on a clean run, the historical behaviour). Use e.g. `high` to fail a pipeline step when omen surfaces a high/critical lead. Evaluated *before* `--limit`, so a display cap can never hide a finding from the gate; applies in single-contract and `--batch` mode alike — see [Failing CI on findings](#failing-ci-on-findings).
- `-o` / `--output-file` — write the report to `PATH` instead of stdout. Default: stdout (the historical behaviour). Composes with every `--format`: in single-contract mode the file gets the rendered `json`/`text`/`h1md`/`sarif` report; in `--batch` mode it gets the JSONL stream (one JSON object per contract). The write is **atomic** — content goes to a sibling `.tmp` and is renamed into place — so a crash mid-write never clobbers a previously good report with a truncated one. Parent directories are created as needed. The `--fail-on` exit code is unaffected: the gate trips the same whether the report went to a file or stdout. See [Writing the report to a file](#writing-the-report-to-a-file).
- `--ignore` — in `--batch` mode, skip contract paths/addresses matching any of these comma-separated [glob](https://docs.python.org/3/library/fnmatch.html) patterns. A pattern matches the full path, any single path component, or — when it contains a `/` — any sub-path, so `--ignore node_modules,lib,test` drops vendored/third-party trees (e.g. an OpenZeppelin import tree) from a recursive directory scan or a list file without hand-pruning the input. Globs support `*`, `?`, and `[seq]`. Ignored items produce no output and no error. Default: ignore nothing. No effect in single `--contract` mode. See [Excluding paths from a batch scan](#excluding-paths-from-a-batch-scan).
- `--parallel` — in `--batch` mode, analyze up to `N` contracts concurrently (a positive integer). Default: `1` (sequential — the historical behaviour). Use a higher `N` to speed up a whole-program scan of dozens-to-hundreds of contracts; the wall-clock win comes from the `solc`/`vyper` compiler subprocess each scan shells out to. Output, the `--fail-on` gate, the error count, and the `--batch-summary` roll-up stay in deterministic **input order**, so a parallel run's JSONL and exit code are byte-for-byte identical to the sequential run's — only faster. No effect in single `--contract` mode. See [Parallelizing a batch scan](#parallelizing-a-batch-scan).
- `--timeout` — in `--batch` mode, give each contract at most `SECONDS` of wall-clock analysis time (a positive number; fractional values like `2.5` are allowed). Default: no budget (each scan runs to completion, the historical behaviour). A contract whose scan overruns is **abandoned and recorded as a per-item error** — it counts toward the exit-`1` error tally and the `--batch-summary` error count, with a message to stderr — so one pathological contract (a hanging compiler, a runaway symbolic path) can't stall a whole-program scan of dozens-to-hundreds of contracts. Enforced on the same thread-pool seam as `--parallel`, so output, the `--fail-on` gate, the error count, and the summary all stay in deterministic **input order**. To actually make progress *past* a stuck contract, pair it with `--parallel >= 2` (a free worker); with the default single worker the budget still bounds each item but a stuck scan blocks the items queued behind it. No effect in single `--contract` mode. See [Bounding per-contract scan time](#bounding-per-contract-scan-time).
- `--batch-summary` — in `--batch` mode, print an aggregate roll-up to **stderr** after the JSONL stream: how many contracts were scanned / had findings / errored, the total findings broken down by severity (worst-first), and the worst-affected contracts. It answers "what did the whole-program scan find, overall?" without piping the JSONL through `jq`. The roll-up goes to stderr so the stdout JSONL stays machine-clean. No effect in single `--contract` mode. Default: off. See [Summarizing a batch scan](#summarizing-a-batch-scan).
- `--diff` — compare two previously-saved omen JSON reports and print the delta: findings **added** (in `NEW`, not `OLD`), **removed** (in `OLD`, not `NEW`), and the **unchanged** count. The temporal complement to `--baseline`: where `--baseline` *suppresses* known findings during a live scan, `--diff` *reports* what changed between two already-saved reports — a pure offline operation needing no contract, compiler, or network (like `--list-checks`). Each report may be a single-contract JSON, a JSON array of them, or a `--batch` JSONL stream. A finding's identity is its category + detector + contract + location, so a `--severity-override` re-stamp or a Slither wording change does not show up as churn. Honors `--format text` (default) or `--format json`, and `--fail-on` — which gates on the *added* findings (exit `3` when a newly-introduced finding reaches the chosen severity), the "fail the PR on regressions" CI move. A missing/unreadable/non-JSON report is a usage error (exit `2`). See [Diffing two reports](#diffing-two-reports).
- `--sarif-merge` — consolidate two or more previously-saved omen JSON reports into a **single SARIF 2.1.0 document**. The spatial complement to `--diff`: where `--diff` reports the *delta* between two reports, `--sarif-merge` *unions* the findings of `N` reports into one code-scanning upload — the fix for a per-module CI matrix or a sharded scan that emits one report per run but needs one SARIF for GitHub Advanced Security (which takes one document per upload). Each `REPORT` may be a single-contract JSON, a JSON array of them, or a `--batch` JSONL stream. Findings shared across inputs are **deduplicated by fingerprint** (category + detector + contract + location, the same identity `--baseline`/`--diff`/`--sarif-baseline` use), so an overlapping contract is not double-counted; the output is worst-first and deterministic regardless of input order. A pure offline operation needing no contract, compiler, or network (like `--diff`/`--list-checks`). Output is **always SARIF** (an explicit `--format` is a usage error); honors `-o` and `--fail-on` — which gates on the merged, deduplicated findings (exit `3` when one reaches the chosen severity). A missing/unreadable/non-JSON report is a usage error (exit `2`). See [Merging reports into one SARIF upload](#merging-reports-into-one-sarif-upload).
- `--list-checks` — print every detection class (its default severity, the input modes it runs in, and the underlying Slither detector(s) it maps to) and exit. Honors `--format text` (default) or `--format json`. Requires no contract, compiler, or network — see [Listing the detection classes](#listing-the-detection-classes).

### Scoping a scan to specific classes

`--check` accepts a single category, `all`, or a **comma-separated list** of
categories. The list lets you scope a scan to exactly the detection surface a
program needs in one run — instead of either accepting the noise of `all` or
running several single-category scans and merging them.

```bash
# The proxy/admin attack cluster: access control, delegatecall, and upgrade.
omen --contract Proxy.sol --input-type sol \
     --check access-control,delegatecall,upgrade

# Just the two MAIAN value-flow classes.
omen --contract Token.sol --input-type sol --check prodigal,greedy
```

Resolution rules:

- The categories run in the order you list them, and duplicates are removed
  (so `reentrancy,reentrancy` runs `reentrancy` once). The report's `checks`
  field echoes the resolved list.
- Whitespace around items, and empty segments from a trailing or doubled comma,
  are ignored (`reentrancy, suicidal,` is fine).
- Every name must be a known category; an unknown one is a usage error
  (exit code `2`) that names the offender.
- `all` must be used alone — `all,reentrancy` is rejected, because `all`
  already covers every class.

The list composes with everything downstream: `--min-severity`,
`--min-confidence`, `--sort`, `--limit`, and `--fail-on` all apply to the
findings the scoped check surfaces. In `--batch` mode the same `--check` list
applies to every contract.

### Excluding classes from a scan

`--exclude-check` is the inverse of `--check`: it **removes** one or more
categories from whatever `--check` resolved to. Where a comma-separated
`--check` says "scan *these* classes", `--exclude-check` pairs with the default
`--check all` to say "scan *everything except* these" — which is shorter than
enumerating the other eight when you only want to drop a couple.

```bash
# Scan everything except the two noisiest bytecode heuristics.
omen --contract Contract.bin --input-type bytecode \
     --check all --exclude-check greedy,prodigal

# Scope to a cluster, then carve one class back out.
omen --contract Proxy.sol --input-type sol \
     --check access-control,delegatecall,upgrade \
     --exclude-check upgrade
```

Resolution rules:

- The exclusion is applied *after* `--check` resolves, and it preserves the
  `--check` order — the surviving categories run in the same order they would
  have without the exclusion. The report's `checks` field echoes that surviving
  set.
- `--exclude-check` accepts a single category or a comma-separated list, with
  the same whitespace/trailing-comma tolerance and dedupe as `--check`. It does
  **not** accept `all` — excluding every class would scan nothing, so that is a
  usage error.
- Excluding a category that `--check` did not select is a **no-op**, not an
  error, so the same exclude list can be reused across scans with different
  `--check` scopes (`--check reentrancy --exclude-check suicidal` simply runs
  `reentrancy`).
- Excluding *every* selected category leaves nothing to scan — that is a usage
  error (exit code `2`) rather than a silently empty report.
- An unknown category in the exclude list is a usage error (exit code `2`) that
  names the offender.

The surviving set composes with everything downstream exactly as `--check`
does, and in `--batch` mode the same exclusion applies to every contract.

### Excluding paths from a batch scan

Where `--check`/`--exclude-check` scope a scan by *vulnerability class*,
`--ignore` scopes a `--batch` scan by *path*. Point omen at a whole repository
and most of what a recursive `.sol` walk finds is vendored or third-party —
`node_modules`, a Foundry `lib/` tree, OpenZeppelin imports, mocks under
`test/`. Those are not your attack surface, and analyzing them wastes time and
floods the JSONL stream. `--ignore` drops them up front:

```bash
# scan a repo but skip vendored deps and test scaffolding
omen --batch ./contracts --input-type sol \
     --ignore node_modules,lib,test
```

`--ignore` takes a comma-separated list of
[`fnmatch`](https://docs.python.org/3/library/fnmatch.html) glob patterns and
matches each candidate three ways, so the common cases need no boilerplate:

- **a single path component** — `node_modules` excludes
  `contracts/node_modules/Foo.sol` (no `*/…/*` wrapping needed);
- **the full path as a glob** — `*.t.sol` excludes every Foundry test file;
- **a sub-path** (any pattern containing `/`) — `lib/openzeppelin` excludes
  `contracts/lib/openzeppelin/ERC20.sol`.

Globs support `*`, `?`, and `[seq]`. A path is skipped if it matches **any**
pattern (OR semantics). The filter runs over both `--batch` input shapes — a
directory's recursive `.sol` walk and a newline-delimited list file (of paths
*or* addresses) — and an ignored item produces no JSONL line and no error, so
the exit code reflects only the contracts that were actually scanned.

Notes:

- `--ignore` has **no effect in single `--contract` mode** (there is one
  explicit target, nothing to filter). It is accepted there as a no-op so a
  committed `omen.toml` carrying `ignore = "…"` still works for single scans.
- An `--ignore` value with no usable patterns (e.g. `--ignore ,,`) is a usage
  error (exit code `2`) rather than a silent no-op — it almost always means a
  typo where a pattern was intended.
- Like every other flag, `ignore` can be set in `omen.toml` (as a comma-list
  string) and overridden on the command line.

### Summarizing a batch scan

Every other batch lever — `--sort`, `--limit`, `--fail-on`, `--ignore` —
operates *per contract*. After scanning a whole-program scope you still have N
JSONL lines and have to aggregate them by hand (or with `jq`) to answer the
first triage question: *how did the scan go, overall?* `--batch-summary` answers
it directly, printing an aggregate roll-up to **stderr** after the JSONL stream:

```bash
omen --batch ./contracts --input-type sol --check all \
     --ignore node_modules,lib,test --batch-summary > scan.jsonl
```

```text
omen batch summary
contracts: 42 scanned, 7 with findings, 1 errored
findings: 11 total  [1 critical, 4 high, 3 medium, 3 low]
top affected:
  3 findings  contracts/Vault.sol
  2 findings  contracts/Treasury.sol
  2 findings  contracts/Bridge.sol
  1 finding  contracts/Token.sol
  1 finding  contracts/Staking.sol
--fail-on gate: TRIPPED
```

The roll-up reports:

- **contracts:** how many scanned cleanly, how many had at least one finding,
  and how many errored (a per-item error does not abort the batch — it is
  counted here and detailed on stderr).
- **findings:** the total across the whole scope, broken down by severity
  worst-first (only severities that actually occur are listed). The total uses
  each contract's pre-`--limit` count, so a display cap never undercounts the
  scope total.
- **top affected:** up to the five contracts with the most findings, most-first,
  so you know where to look before opening the JSON. Contracts with no findings
  are never listed.
- **--fail-on gate:** a `TRIPPED` line when `--fail-on` was set and at least one
  contract reached the threshold (it mirrors the exit-`3` gate).

It goes to **stderr**, never stdout, so the stdout JSONL stream stays a clean
machine feed for `jq` and other tooling — you can redirect the JSONL to a file
(or a pipe) and still read the human roll-up on your terminal, as in the example
above. `--batch-summary` has no effect in single `--contract` mode (there is one
contract — the per-contract `--format text` view already summarizes it); it is
accepted there as a no-op so a committed `omen.toml` carrying `batch-summary =
true` still works for single scans. Like every other flag it can be set in
`omen.toml`.

### Parallelizing a batch scan

`--batch` exists for the bounty workflow of scanning a whole program scope —
dozens to hundreds of contracts. By default omen scans them one at a time. Each
scan is independent, and its wall time is dominated by the `solc`/`vyper`
compiler subprocess it shells out to (which releases the GIL), so analyzing
several at once is a real speedup. `--parallel N` runs `N` analyses concurrently
via a thread pool:

```bash
omen --batch ./contracts --input-type sol --check all \
     --ignore node_modules,lib,test --parallel 8 > scan.jsonl
```

The defining guarantee is that **concurrency never changes the result** — only
its speed. Output, the `--fail-on` gate (the OR across items), the error count,
and the `--batch-summary` roll-up are all assembled in deterministic **input
order** regardless of which scan finishes first, so a `--parallel N` run's JSONL
stream and exit code are byte-for-byte identical to the sequential run's. You can
develop and triage against a sequential run and turn on `--parallel` in CI for
the speedup without any behavioural surprise.

Notes:

- The default is `1` (sequential), which is the historical streaming behaviour:
  each JSONL line is printed the moment it is ready. A parallel run buffers the
  ordered results before emitting them, so it trades a little memory for the
  wall-clock win.
- `N` must be a positive integer; `0` or a negative value is a usage error
  (exit `2`), mirroring `--limit`.
- A 0- or 1-item batch is run sequentially regardless of `--parallel` (a pool
  would be pure overhead).
- `--parallel` has **no effect in single `--contract` mode** (there is one
  contract); it is accepted there as a no-op so a committed `omen.toml` carrying
  `parallel = 8` still works for single scans. Like every other flag it can be
  set in `omen.toml`.

### Bounding per-contract scan time

`--parallel` protects a whole-program batch's throughput from the *aggregate*
cost of many scans; `--timeout` protects it from the *opposite* hazard: a single
pathological contract whose scan never finishes (a compiler that hangs, a
runaway symbolic path, a degenerate import graph) and would otherwise stall the
entire run. `--timeout SECONDS` gives each contract a wall-clock budget; a scan
that overruns is **abandoned and recorded as a per-item error** so the batch
makes progress:

```bash
omen --batch ./contracts --input-type sol --check all \
     --ignore node_modules,lib,test --parallel 8 --timeout 60 > scan.jsonl
```

A timed-out contract is treated exactly like a scan that raised: a message goes
to stderr (`omen: batch timeout [path]: analysis exceeded 60s budget`), it
counts toward the exit-`1` error tally and the `--batch-summary` error count, and
it produces no JSONL line. The surviving contracts' output, the `--fail-on` gate,
and the summary all stay in deterministic **input order**, exactly as with
`--parallel`. The budget is enforced on the same thread-pool seam, so the two
compose: `--parallel 8 --timeout 60` runs eight contracts at once and abandons
any that overruns a minute.

Notes:

- **Pair `--timeout` with `--parallel >= 2` to actually skip past a stuck
  contract.** The budget bounds how long omen *waits* on each item, not the scan
  itself (it deliberately does not kill the in-process analysis — see below). A
  single worker can only run one scan at a time, so a contract that stalls the
  lone worker also times out the contracts queued behind it. A free worker
  (`--parallel >= 2`) lets the others proceed while the stuck one's budget
  expires.
- `SECONDS` must be a positive, finite number; `0`, a negative, NaN, and infinity
  are usage errors (exit `2`). Fractional values (`2.5`) are allowed, unlike the
  integer-only `--limit`/`--parallel`.
- omen does **not** subprocess-wrap or kill the abandoned scan. Slither runs
  in-process; killing it mid-analysis would mean subprocess-isolating the whole
  analysis path, which would change omen's defining architecture for no
  proportionate gain. The abandoned worker thread is left to finish and is
  reclaimed when the pool shuts down; the budget bounds the batch's *blocking
  wait*, which is the bounty-workflow value — getting past the stuck contract.
- `--timeout` has **no effect in single `--contract` mode** (one target, nothing
  a per-item batch budget bounds); it is accepted there as a no-op so a committed
  `omen.toml` carrying `timeout = 60` still works for single scans. Like every
  other flag it can be set in `omen.toml`.

### Listing the detection classes

Before a scan you can ask omen exactly what it can detect and how each class
maps onto Slither's detectors (those mappings are non-obvious — `access-control`,
for example, is backed by `protected-vars` + `events-access`, because Slither
has no detector literally named `access-control`):

```bash
omen --list-checks
```

```
omen 0.1.0 — 10 detection classes

CATEGORY         SEVERITY  MODES                          SLITHER DETECTORS
---------------------------------------------------------------------------
prodigal         high      sol, vyper, bytecode, address  arbitrary-send-eth
suicidal         high      sol, bytecode, address         suicidal
greedy           medium    sol, bytecode, address         locked-ether
reentrancy       high      sol, vyper, bytecode, address  reentrancy-eth, reentrancy-balance
access-control   high      sol                            protected-vars, events-access
tx-origin        medium    sol                            tx-origin
delegatecall     high      sol                            controlled-delegatecall, delegatecall-loop
upgrade          high      sol                            unprotected-upgrade
overflow         medium    sol                            divide-before-multiply, tautology
weak-randomness  medium    sol                            weak-prng
```

For tooling, `--list-checks --format json` emits the same catalog as a JSON
document (`{tool, version, check_count, checks: [...]}`). The listing runs
offline with no compiler or RPC, so it works in CI and on a fresh checkout.

### One example per class

**prodigal** (source mode):

```bash
omen --contract tests/fixtures/vulnerable-prodigal.sol \
     --input-type sol --check prodigal --format json
```

**suicidal** (source mode):

```bash
omen --contract tests/fixtures/vulnerable-suicidal.sol \
     --input-type sol --check suicidal --format h1md
```

**greedy** (source mode):

```bash
omen --contract tests/fixtures/vulnerable-greedy.sol \
     --input-type sol --check greedy --format json
```

**reentrancy** (source mode):

```bash
omen --contract tests/fixtures/vulnerable-reentrancy.sol \
     --input-type sol --check reentrancy --format json
```

**access-control** (source mode):

```bash
omen --contract tests/fixtures/vulnerable-access-control.sol \
     --input-type sol --check access-control --format h1md
```

**tx-origin** (source mode):

```bash
omen --contract tests/fixtures/vulnerable-tx-origin.sol \
     --input-type sol --check tx-origin --format json
```

**delegatecall** (source mode):

```bash
omen --contract tests/fixtures/vulnerable-delegatecall.sol \
     --input-type sol --check delegatecall --format h1md
```

**upgrade** (source mode):

```bash
omen --contract tests/fixtures/vulnerable-upgrade.sol \
     --input-type sol --check upgrade --format json
```

**overflow** (source mode):

```bash
omen --contract tests/fixtures/vulnerable-overflow.sol \
     --input-type sol --check overflow --format json
```

**weak-randomness** (source mode):

```bash
omen --contract tests/fixtures/vulnerable-weak-randomness.sol \
     --input-type sol --check weak-randomness --format h1md
```

> access-control, tx-origin, delegatecall, upgrade, overflow, and
> weak-randomness are **source-mode** checks (they need Slither's static
> analysis); they are not detectable from raw bytecode alone, so they produce no
> findings in `--input-type bytecode`/`address` mode.

### Bytecode mode (no solc)

The shipped `tests/fixtures/compiled.bin` is the runtime bytecode of the
suicidal fixture. Bytecode mode reproduces the same `suicidal` finding source
mode produces — via the `SELFDESTRUCT` opcode — with no compiler:

```bash
omen --contract tests/fixtures/compiled.bin \
     --input-type bytecode --check suicidal
```

Bytecode/address mode covers all four MAIAN-class checks via opcode-level
analysis:

| Check | Bytecode signal | Confidence |
|---|---|---|
| **suicidal** | `SELFDESTRUCT` opcode present | high |
| **prodigal** | `CALL` with non-zero value to a caller-controlled (`CALLDATALOAD`-derived) destination | low |
| **greedy** | reads `CALLVALUE` (payable) but has no value-sending opcode (`CALL`/`DELEGATECALL`/`CALLCODE`/`SELFDESTRUCT`) | low |
| **reentrancy** | `SSTORE` after a `CALL` before the next `RETURN`/`STOP`/`REVERT` (checks-effects-interactions violation) | low |

> The prodigal/greedy/reentrancy bytecode heuristics are coarse opcode patterns,
> not full data-flow analysis. They report at **`confidence: low`** with an
> explicit caveat in each finding: when source is available, source mode (which
> uses Slither) is more precise. Their purpose is to give a bounty hunter a
> triage lead on source-unverified on-chain contracts instead of a silent miss.

### Filtering by confidence

Every finding carries a `confidence` of `low`, `medium`, or `high`. Slither
sets its own confidence on source-mode findings; the bytecode/address
heuristics for prodigal, greedy, and reentrancy always report at
`confidence: low`. When you scan a whole program scope these low-confidence
triage leads can dominate the output, so `--min-confidence` drops findings
below a chosen threshold:

```bash
# keep only medium- and high-confidence findings
omen --contract 0xYourContract --input-type address --rpc-url $RPC \
     --check all --min-confidence medium

# whole-scope batch, high-confidence only
omen --batch addresses.txt --input-type address --rpc-url $RPC \
     --check all --min-confidence high
```

The default is `--min-confidence low`, which keeps every finding (no change in
behaviour for existing invocations). The filter runs after analysis, so the
serialized `finding_count` always matches the findings you see, and it applies
in every output format and in `--batch` mode.

### Filtering by severity

Every finding also carries a `severity` of `informational`, `low`, `medium`,
`high`, or `critical`. With ten detection classes spanning that whole range,
the first pass over a new program scope is usually "show me the high-impact
leads first." `--min-severity` drops findings below a chosen threshold:

```bash
# only high- and critical-severity findings
omen --contract Token.sol --input-type sol \
     --check all --min-severity high

# whole-scope batch, high severity AND high confidence — the tightest triage
omen --batch addresses.txt --input-type address --rpc-url $RPC \
     --check all --min-severity high --min-confidence high
```

The default is `--min-severity informational`, which keeps every finding. The
two filters **compose**: a finding must clear both the severity and the
confidence threshold to survive. Like the confidence filter, severity filtering
runs after analysis (so `finding_count` always matches what you see) and
applies in every output format and in `--batch` mode.

### Overriding severity per class

omen ships a built-in default severity for each detection class, and in source
mode it inherits Slither's per-finding impact. Your organization may rank a
class differently: a DeFi team that has been burned by reentrancy may treat
**every** reentrancy lead as `critical`; a team scanning a large monorepo may
demote the noisy bytecode `greedy` heuristic to `informational` so it falls out
of a `--min-severity low` triage pass. `--severity-override` is that lever — a
comma-separated list of `CATEGORY=SEVERITY` pairs that re-stamps the severity
omen reports for the named classes:

```bash
# treat any reentrancy or tx.origin lead as our top tier
omen --contract Vault.sol --input-type sol \
     --check all --severity-override reentrancy=critical,tx-origin=high

# demote a noisy class so a low-severity triage pass drops it
omen --batch contracts/ --input-type sol \
     --check all --severity-override greedy=informational --min-severity low
```

The override is applied **before** the rest of the pipeline — `--min-severity`,
`--sort`, `--limit`, and `--fail-on` all act on the tuned severity. That makes
it compose cleanly: pinning `tx-origin=high` both surfaces it under
`--min-severity high` *and* trips a `--fail-on high` CI gate, while pinning a
class down lets `--min-severity` filter it out as noise. Only the severity
changes — the finding's category, confidence, evidence, and detector id are
preserved, so every override stays fully traceable. Unknown categories or
severities are rejected as a usage error (exit `2`). The setting applies in
single-contract and `--batch` mode and can be committed to `omen.toml` as
`severity_override = "reentrancy=critical"`; an explicit CLI flag overrides the
file as usual.

### Sorting findings

Once the filters narrow a scan down, you still read the report top-down. By
default omen orders findings **worst-first** — highest severity, then highest
confidence — so the high-impact leads sit at the top of every report instead of
being scattered through the raw detector-registration order:

```bash
# default: findings are sorted severity-then-confidence (no flag needed)
omen --contract Token.sol --input-type sol --check all

# opt out and keep the raw detector order
omen --contract Token.sol --input-type sol --check all --sort none
```

Sorting is a pure reordering applied *after* `--min-severity`/`--min-confidence`,
so it never adds or drops a finding — `finding_count` is unaffected. Ties (same
severity and confidence) keep their original relative order, so the output stays
deterministic. `--sort` applies in single-contract and `--batch` mode and in
every output format.

### Limiting findings

The filters decide *which* findings survive and `--sort` decides *what order*
they are read in; `--limit N` decides *how many* to read. After the default
worst-first sort, a whole-program scan can still emit dozens of findings, and
the common next triage move is "just show me the top N leads":

```bash
# keep only the 10 highest-impact leads (after the default worst-first sort)
omen --contract Token.sol --input-type sol --check all --limit 10

# combine the full triage stack: high-severity, high-confidence, top 5
omen --contract Token.sol --input-type sol --check all \
     --min-severity high --min-confidence high --limit 5
```

`--limit` runs *after* `--sort`, so with the default ordering the cap keeps the
N most severe (then most confident) findings. Unlike the filters, the cap
**does** change which findings appear, so omen reports it honestly: the JSON
gains a `total_findings` (how many survived filtering before the cap) and a
`truncated` boolean, and the `h1md` report shows `Findings: 10 of 47 (top 10
shown; --limit)`. `N` must be a positive integer (`0` and negatives are
rejected — a zero cap would silently hide every lead). In `--batch` mode the cap
is **per-contract** (each JSONL line shows at most `N` findings), not a cap on
the number of contracts scanned. `--limit` applies in every output format.

### Address mode (read-only, requires --rpc-url)

```bash
omen --contract 0xYourContractAddress \
     --input-type address --check all \
     --rpc-url https://your-node.example/rpc
```

omen fetches the deployed bytecode with `eth_getCode` and runs bytecode-level
detection. It never sends a transaction.

### Vyper source mode (`--input-type vyper`, needs the `vyper` binary)

Many high-TVL DeFi protocols (Curve, Yearn) are written in [Vyper](https://docs.vyperlang.org/).
omen analyzes `.vy` source via Slither's Vyper front-end:

```bash
omen --contract MyContract.vy --input-type vyper --check reentrancy
omen --contract MyContract.vy --input-type vyper --check all
```

Slither's Vyper front-end supports a **subset** of its Solidity detectors, so
omen restricts Vyper input to the classes that map onto language-neutral
detectors:

| Vyper-supported class | Detects |
|---|---|
| **reentrancy** | withdraw-before-state-update (CEI violation) |
| **prodigal** | leaks Ether to an arbitrary/caller-controlled address |

`--check all` on a `.vy` file automatically narrows to that subset. Asking for
a Solidity-only class (e.g. `--check suicidal`, `--check access-control`,
`--check delegatecall`) on Vyper input fails fast with a clear error rather
than returning a silently-empty report.

> **Toolchain note.** Vyper compilation is delegated to whatever `vyper` is on
> `PATH` (there is no `solc-select` equivalent for Vyper, so omen does not
> auto-provision one). Slither's Vyper support tracks specific compiler
> versions; if your installed Slither/crytic-compile cannot compile your
> contract's Vyper version, omen surfaces the compiler error rather than
> masking it.

---

## Example output (JSON)

```json
{
  "tool": "omen",
  "version": "0.1.0",
  "input_type": "sol",
  "origin": "tests/fixtures/vulnerable-suicidal.sol",
  "checks": ["suicidal"],
  "finding_count": 1,
  "total_findings": 1,
  "truncated": false,
  "gate_triggered": false,
  "findings": [
    {
      "category": "suicidal",
      "severity": "high",
      "title": "suicidal contract (suicidal)",
      "description": "VulnerableSuicidal.kill(address) ... allows anyone to destruct the contract",
      "detector": "slither:suicidal",
      "contract": "VulnerableSuicidal",
      "confidence": "high",
      "evidence": { "source_mapping": ["vulnerable-suicidal.sol#16-18"], "opcodes": [] }
    }
  ]
}
```

### Text output

`--format text` emits a compact, human-readable terminal view — the "what did
omen find, at a glance" read for running omen interactively instead of piping it
into another tool. It is a one-line header (origin + checks), a per-severity
count summary, and one line per finding: index, severity, category, confidence,
and where to look (a source location in source mode, or an opcode offset in
bytecode/address mode). Findings come out in the report's order, so under the
default `--sort severity` the worst, most-confident leads sit at the top. The
summary respects `--limit` truncation, showing `top N of M shown` when a cap
dropped findings.

```bash
omen --contract tests/fixtures/compiled.bin \
     --input-type bytecode --check all --format text
```

```text
omen 0.1.0 — tests/fixtures/compiled.bin
input: bytecode  checks: prodigal, suicidal, greedy, reentrancy, access-control, tx-origin, delegatecall, upgrade, overflow, weak-randomness
findings: 2  [2 high]

 1. HIGH          suicidal [high]  @0x3
 2. HIGH          reentrancy [low]  @0x2
```

It is a pure formatter — it never re-orders or re-filters findings — so it
composes with `--min-severity`/`--min-confidence`, `--sort`, and `--limit`
exactly as the other formats do. (In `--batch` mode omen always emits JSONL
regardless of `--format`, so `text` applies to single-contract scans.)

### SARIF output (CI / GitHub code scanning)

`--format sarif` emits a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/)
log. SARIF is the standard ingested by GitHub Advanced Security (code
scanning), VSCode's SARIF Viewer, and most CI systems, so omen findings can be
surfaced as PR annotations and IDE diagnostics alongside other static
analysers' output.

```bash
omen --contract tests/fixtures/vulnerable-suicidal.sol \
     --input-type sol --check suicidal --format sarif > omen.sarif
```

Each omen detection class maps to one SARIF reporting rule
(`omen/<category>`), and each finding becomes one result. Severities map to
SARIF levels (`high`/`critical` → `error`, `medium` → `warning`,
`low`/`informational` → `note`) and carry a GitHub `security-severity` score;
source-mode findings include precise `region` line ranges, while bytecode-mode
findings keep their offending opcode offsets in the result `properties`.

To upload in a GitHub Actions workflow:

```yaml
- run: omen --contract MyContract.sol --input-type sol --check all --format sarif > omen.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: omen.sarif
```

### GitHub Actions annotations

`--format sarif` (above) targets GitHub **Advanced Security** code scanning,
which is a paid feature on private repositories and needs an upload step.
`--format gha` is the free, no-upload complement: it emits GitHub Actions
[workflow commands](https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions)
— one `::error`/`::warning`/`::notice` line per finding — which the Actions
runner reads straight off the step's stdout and turns into **inline annotations
on the PR diff** and the workflow run summary, on every repository, with no
SARIF upload and no Advanced Security.

```bash
omen --contract MyContract.sol --input-type sol --check all --format gha
```

```text
::error file=MyContract.sol,line=42,endLine=48,title=omen high%3A reentrancy [high]::external call before state update
::warning file=MyContract.sol,line=12,title=omen medium%3A tx-origin [medium]::tx.origin used for authorization
```

Severities map to the three workflow-command levels (`high`/`critical` →
`::error`, `medium` → `::warning`, `low`/`informational` → `::notice`), so a
`::error` annotation shows red in the PR. Source-mode findings carry the exact
`file`, `line`, and `endLine` so the annotation pins to the offending lines;
bytecode-mode findings (no source location) emit a command without a `file`
anchor, which still appears in the run log. Each annotation's `title` carries
omen's severity, category, and confidence so it is self-describing in the UI,
and the message is the finding's description. A clean scan emits a single
`::notice` so the step still leaves a visible "omen ran, found nothing" trace.

In a workflow, combine it with [`--fail-on`](#failing-ci-on-findings) to both
annotate the diff and block the PR:

```yaml
- run: omen --contract MyContract.sol --input-type sol --check all --format gha --fail-on high
```

The annotations land inline on the PR, and the step exits `3` (failing the job)
when a high/critical lead is present. Like the other scan formats, `gha` applies
to single-`--contract` mode; a `--batch` run always emits its JSONL stream.

### JUnit XML output

`--format sarif` is GitHub-Advanced-Security-specific and `--format gha` is
GitHub-Actions-specific. `--format junit` is the **platform-agnostic** CI lever:
it emits a [JUnit XML](https://github.com/testmoapp/junitxml) test-results
report, the lingua franca format ingested natively by GitHub Actions test
reporters, GitLab CI, Jenkins, CircleCI, Azure DevOps, and TeamCity. Each finding
becomes one **failing `<testcase>`** (with a `<failure>` carrying the
description), grouped under a single `<testsuite>` named `omen`, so the findings
show up in the CI **tests** tab and fail the build on essentially any CI system —
no upload step and no paid feature.

```bash
omen --contract MyContract.sol --input-type sol --check all --format junit > omen-junit.xml
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="omen" tests="2" failures="2" errors="0">
  <testcase name="1. reentrancy [high] MyContract.sol#42-48" classname="omen.reentrancy">
    <failure type="high" message="external call before state update">severity: high | detector: slither:reentrancy-eth | contract: MyContract
external call before state update</failure>
  </testcase>
  <testcase name="2. tx-origin [medium] MyContract.sol#12" classname="omen.tx-origin">
    <failure type="medium" message="tx.origin used for authorization">severity: medium | detector: slither:tx-origin | contract: MyContract
tx.origin used for authorization</failure>
  </testcase>
</testsuite>
```

Every omen finding is a failure (omen emits findings, never "passes"), so
`failures` always equals `tests`. The testcase `name` carries the finding's
category, confidence, and location (source mapping in source mode, opcode offset
in bytecode mode) so it is scannable in the CI UI; the `classname` is
`omen.<category>` so test-result viewers that group by class bucket findings by
vulnerability class. The omen severity is preserved verbatim in the `<failure>`
`type` and the message body. A clean scan emits a valid suite with one **passing**
testcase (no `<failure>`), so the tests tab shows a green `omen` entry rather than
an absent suite.

In a workflow, combine it with a JUnit reporter (and optionally
[`--fail-on`](#failing-ci-on-findings)) to surface findings as test results:

```yaml
- run: omen --contract MyContract.sol --input-type sol --check all --format junit > omen-junit.xml
- uses: dorny/test-reporter@v1
  if: always()
  with:
    name: omen
    path: omen-junit.xml
    reporter: java-junit
```

Like the other scan formats, `junit` applies to single-`--contract` mode; a
`--batch` run always emits its JSONL stream.

### SARIF-native suppression with a baseline

[`--baseline`](#suppressing-known-findings-with-a-baseline) *drops* known
findings from the report entirely. GitHub code scanning has its own,
SARIF-native way to do this: instead of removing a result, you tag it with a
[`baselineState`](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html#_Toc34317648)
of `new`, `unchanged`, or `absent`, and GitHub folds the `unchanged` ones into
its pre-existing-alert view while surfacing the `new` ones. `--sarif-baseline`
emits exactly that annotation, so omen findings suppress the same way every
other code-scanning tool's do — natively, in the platform, without losing data.

```bash
# 1) Capture today's findings as a known-good baseline (once), as for --baseline.
omen --contract MyContract.sol --input-type sol --check all -o omen-baseline.json
git add omen-baseline.json && git commit -m "omen baseline"

# 2) In CI, emit SARIF with each result tagged new/unchanged against the baseline.
omen --contract MyContract.sol --input-type sol --check all \
     --format sarif --sarif-baseline omen-baseline.json -o omen.sarif
```

Every result in `omen.sarif` now carries a `baselineState`:

- `"unchanged"` — the finding's fingerprint is already in the baseline (a known,
  pre-existing issue). It is still present in the SARIF document; GitHub marks it
  as a pre-existing alert rather than a new one.
- `"new"` — the finding is not in the baseline (introduced since). These are the
  alerts a reviewer sees surfaced on the PR.

The identity used for matching is the **same fingerprint `--baseline` and
`--diff` use** — `category + detector + contract + location` — so a
`--severity-override` re-stamp or a Slither wording change never flips a known
finding from `unchanged` to `new`.

`--sarif-baseline` differs from `--baseline` in two deliberate ways:

- **It does not drop findings.** Every result stays in the SARIF output; the
  suppression happens in GitHub, driven by `baselineState`. (`--baseline`
  removes the finding before it is ever emitted.)
- **It does not change the `--fail-on` gate.** Because nothing is dropped, a
  baselined-`unchanged` high-severity finding still trips `--fail-on high`
  (exit `3`). If you want the *omen* exit code to ignore known findings, use
  `--baseline`; if you want the *platform* to fold them into its baseline view
  while still emitting them, use `--sarif-baseline`. The two are complementary
  and can be combined.

It applies only to `--format sarif` in single-`--contract` mode (a `--batch` run
emits JSONL, not a SARIF document, so there is no per-result `baselineState` to
write) — using it otherwise is a usage error (exit `2`), as is a
missing/unreadable/non-JSON baseline. Like every other flag, `sarif-baseline`
can be set in `omen.toml`, so a committed `sarif-baseline = "omen-baseline.json"`
makes the annotation the default for a code-scanning workflow.

### Failing CI on findings

Uploading SARIF surfaces findings as annotations, but it does not *fail* a
pipeline. `--fail-on <severity>` is the CI gate: omen still prints the full
report, then exits non-zero (code `3`) when at least one finding reaches the
chosen severity. The default `never` keeps the historical always-exit-`0`
behaviour, so existing invocations are unchanged.

```bash
# exit 3 if any high- or critical-severity lead is found; exit 0 otherwise
omen --contract MyContract.sol --input-type sol --check all --fail-on high

# tighten the gate to critical-only
omen --contract MyContract.sol --input-type sol --check all --fail-on critical
```

This is the standard security-scanner pattern (cf. Slither's `--fail-high`,
and the severity gates in semgrep/trivy/bandit). The exit codes are:

| Code | Meaning |
|---|---|
| `0` | ran cleanly (and, if `--fail-on` was set, nothing reached the threshold) |
| `1` | analysis failed (single mode) / at least one `--batch` item failed |
| `2` | invalid arguments / input error (e.g. `--input-type address` with no `--rpc-url`) |
| `3` | `--fail-on` gate tripped — a finding reached the chosen severity |

The gate is evaluated over the findings that survived `--min-severity` /
`--min-confidence` but **before** any `--limit` cap, so a display cap can never
hide a gate-tripping finding from the exit code. A finding that `--min-severity`
filtered out does **not** trip the gate — the two compose, so
`--min-severity high --fail-on high` means "show and gate on high+ only". The
same `gate_triggered` boolean appears in the JSON report so a consumer that
reads stdout sees the same signal the exit code carries. In `--batch` mode the
gate is the OR across items (any one tripping makes the batch exit `3`), and a
per-item failure still takes precedence (`1` outranks `3`).

A GitHub Actions step that should block the PR on a high-severity lead:

```yaml
- run: omen --contract MyContract.sol --input-type sol --check all --fail-on high
```

### Suppressing known findings with a baseline

`--fail-on` is the right gate for new code, but it makes adopting omen on an
*existing* codebase painful: the very first run lights up red on every
pre-existing finding, so teams disable the gate or learn to ignore it.
`--baseline` is the fix — the standard "triage / baseline" move every mature
scanner ships (cf. Slither's `--triage-mode`, semgrep's `--baseline`, trivy's
`.trivyignore`). Capture today's findings once, commit that file, then gate only
on findings introduced *after* it.

```bash
# 1) Capture the current findings as a known-good baseline (once).
omen --contract MyContract.sol --input-type sol --check all -o omen-baseline.json
git add omen-baseline.json && git commit -m "omen baseline"

# 2) In CI, suppress the baselined findings and fail only on NEW ones.
omen --contract MyContract.sol --input-type sol --check all \
     --baseline omen-baseline.json --fail-on high
```

The second run prints and gates on the findings that are *new* relative to the
baseline only: a re-scan of unchanged code surfaces nothing and exits `0`, while
a newly-introduced high-severity bug still trips the gate (exit `3`). The
suppression happens **before** `--min-severity`/`--min-confidence`, `--sort`,
`--limit`, and `--fail-on`, so a baselined finding never appears in the report,
never counts toward `total_findings`, and never trips the gate.

A finding's identity for baseline matching is its **category + detector +
contract + location** (the source line range in source mode, or the opcode
offset in bytecode/address mode). Severity and wording are deliberately *not*
part of the identity, so re-stamping a class with `--severity-override`, or a
Slither release that rewords a detector message, will not make a known finding
look new.

The baseline file is just a saved omen JSON report, so it composes with the rest
of the tooling:

- **Batch mode** works the same way: the baseline is matched per contract, so a
  whole-program `--batch` scan fails only on new findings. A natural batch
  baseline is the JSONL output of a previous batch run (`--baseline` reads either
  a single report object or a JSONL stream of them).
- A **clean baseline** (a scan that found nothing) is valid and suppresses
  nothing — useful as a placeholder you regenerate as the code evolves.
- Like every other flag, `baseline` can be set in `omen.toml`, so a committed
  `baseline = "omen-baseline.json"` makes "fail only on new findings" the default
  for every invocation.
- A missing, unreadable, or non-JSON baseline is a usage error (exit `2`),
  surfaced before any compiler/network work — a broken baseline fails loudly
  rather than silently letting every finding through the gate.

To refresh the baseline after intentionally accepting (or fixing) findings,
re-run step 1 and commit the new file.

### Diffing two reports

`--baseline` answers "fail only on findings *new* since this point" at scan time.
`--diff` answers the related question *after the fact*: given two saved omen
reports, **what changed between them?** It is a pure offline comparison — no
contract, compiler, Slither, or network — so it runs on a fresh checkout in CI
exactly like `--list-checks`:

```bash
# Scan the same scope before and after a change set.
omen --contract Token.sol --input-type sol --check all -o before.json
# … apply a PR / fix / refactor …
omen --contract Token.sol --input-type sol --check all -o after.json

# What did the change introduce or fix?
omen --diff before.json after.json
```

```text
omen 0.1.0 — report diff
old: before.json
new: after.json
changes: +1 added  -1 removed  =3 unchanged

Added (1):
  + HIGH          access-control [medium]  Token.sol#42-48

Removed (1):
  - HIGH          reentrancy [high]  Token.sol#90-104
```

The delta has three parts:

- **added** — findings in the new report but not the old one: the regressions /
  new leads the change introduced. These are what a CI gate cares about.
- **removed** — findings in the old report but not the new one: issues fixed (or
  code deleted) since the old report.
- **unchanged** — findings present in both: carried over (counted, not listed —
  the point of a diff is the delta).

A finding's identity for matching is the **same fingerprint `--baseline` uses** —
category + detector + contract + location — so a `--severity-override` re-stamp or
a Slither wording change does not show up as churn. The diff is deterministic
(ordered by fingerprint) regardless of how either report listed its findings.

`--diff` composes with the rest of the surface:

- **`--format json`** emits a machine-readable delta — a `summary` count object
  plus the full `added`/`removed`/`unchanged` finding lists — for changelog or
  triage automation. `--format text` (the default) is the glanceable summary
  above. The scan-oriented `h1md`/`sarif` formats do not apply to a report delta.
- **`--fail-on`** turns `--diff` into a regression gate: it exits `3` when an
  *added* finding reaches the chosen severity, and `0` otherwise. Only added
  findings are eligible — a removed or unchanged finding never re-trips a gate the
  previous run already accounted for. So `omen --diff before.json after.json
  --fail-on high` is the "fail the PR if it introduces a high/critical finding"
  move, with no need to re-run the scanner.
- **`-o`/`--output-file`** writes the rendered diff to a file (atomically), same
  as a scan report.
- Either report may be a single-contract JSON, a JSON array of reports, or a
  `--batch` JSONL stream — whatever `-o` produced — so a whole-program batch diff
  is `omen --diff batch-before.jsonl batch-after.jsonl`.
- A missing, unreadable, or non-JSON report is a usage error (exit `2`),
  surfaced before any work — a broken diff input fails loudly.

### Merging reports into one SARIF upload

`--diff` compares two reports along the *temporal* axis. `--sarif-merge` is the
*spatial* complement: given `N` saved omen reports, it **unions their findings
into one SARIF 2.1.0 document**. GitHub Advanced Security accepts one SARIF per
upload, so a scan split across runs — a per-module CI matrix, a sharded
`--parallel` sweep saved per shard, or one `-o` report per contract — otherwise
means uploading `N` times (`N` separate "tools" in the code-scanning UI) or
hand-stitching the JSON. `--sarif-merge` produces the single document. Like
`--diff`/`--list-checks` it is a pure offline action — no contract, compiler,
Slither, or network:

```bash
# Each CI shard scans part of the scope and saves its own report.
omen --contract core/Vault.sol  --input-type sol --check all -o shard-core.json
omen --contract token/Token.sol --input-type sol --check all -o shard-token.json
omen --contract proxy/Proxy.sol --input-type sol --check all -o shard-proxy.json

# Consolidate every shard into one SARIF document and upload it once.
omen --sarif-merge shard-core.json shard-token.json shard-proxy.json -o omen.sarif
# … then upload omen.sarif to GitHub code scanning (e.g. github/codeql-action/upload-sarif).
```

The merged document is identical in shape to a single-run `--format sarif`
report — one `tool.driver` (omen), one rule per category, one result per finding
— so it uploads exactly like one. Findings that appear in more than one input
(an overlapping contract scanned by two shards, say) are **deduplicated by the
same fingerprint** `--baseline`/`--diff`/`--sarif-baseline` use — category +
detector + contract + location — so they are not double-counted. The result
order is **worst-first then by fingerprint**, so the document is byte-stable
regardless of input order or how each report listed its findings.

`--sarif-merge` composes with the rest of the surface:

- Output is **always SARIF** — it is in the flag's name — so an explicit
  `--format` is a usage error (there is no text/json/h1md analogue of a
  consolidated code-scanning upload). A redundant `--format sarif` is accepted.
- **`--fail-on`** gates on the merged, deduplicated findings (exit `3` when one
  reaches the chosen severity), mirroring the scan / `--diff` convention — so a
  consolidation step can also fail the build on a high/critical lead anywhere in
  the scope. A finding present in two inputs is counted once.
- **`-o`/`--output-file`** writes the SARIF document to a file (atomically), the
  natural shape for "produce `omen.sarif`, then upload it".
- Each input may be a single-contract JSON, a JSON array of reports, or a
  `--batch` JSONL stream — whatever `-o` produced — so merging a per-directory
  set of batch runs is just `omen --sarif-merge batch-*.jsonl -o omen.sarif`.
- A missing, unreadable, or non-JSON report is a usage error (exit `2`),
  surfaced before any work — a broken input fails loudly.

### Writing the report to a file

By default omen prints the report to stdout, which composes naturally with
shell redirection. `-o` / `--output-file PATH` is the explicit form: omen writes
the rendered report straight to `PATH` and prints nothing to stdout.

```bash
# write the JSON report to a file instead of stdout
omen --contract Token.sol --input-type sol --check all -o report.json

# composes with every --format — e.g. a SARIF log for code scanning upload
omen --contract Token.sol --input-type sol --check all --format sarif -o omen.sarif

# in --batch mode the JSONL stream goes to the file, one object per contract
omen --batch contracts/ --input-type sol --check all -o scan.jsonl

# parent directories are created on demand
omen --contract Token.sol --input-type sol --check all -o reports/2026/token.json
```

The write is **atomic**: content is written to a sibling `PATH.tmp` and then
renamed into place, so a crash partway through a long scan (or a large batch)
never overwrites a previously good report with a half-written one. The redirect
changes only the *destination* — the file content is byte-for-byte what the same
invocation would have printed to stdout, in whatever `--format` was selected.

`-o` is orthogonal to the exit-code conventions: a `--fail-on` gate still trips
(exit `3`) and the report is still written to the file before the process exits,
so a CI step can both fail the build and archive the report artifact in one run.

```yaml
# fail the PR on a high lead AND save the SARIF artifact for code scanning
- run: omen --contract MyContract.sol --input-type sol --check all --fail-on high --format sarif -o omen.sarif
```

### Config files (`omen.toml`)

After a dozen flags grew up around the detector roster, a CI invocation that
scopes a scan, filters confidence, sorts, caps, gates, and redirects output is a
long one-liner that has to be copied into every pipeline step. `--config PATH`
loads a TOML file whose keys set **default** values for those flags, so a repo
can commit one `omen.toml` and shrink every invocation:

```toml
# omen.toml — defaults for this repo's scans
[omen]
input-type   = "sol"
check        = "access-control,delegatecall,upgrade"
min-severity = "high"
sort         = "severity"
fail-on      = "high"
format       = "sarif"
output-file  = "omen.sarif"
```

```bash
# the whole config above, applied — only the target is left on the command line
omen --config omen.toml --contract Token.sol

# a config can even drive the target itself (contract + input-type keys),
# reducing the invocation to just the config
omen --config omen.toml
```

The contract is deliberately small and predictable:

- **Flat name→value map.** All keys live at the top level *or* under an `[omen]`
  table (both accepted; when an `[omen]` table is present its keys are used, so
  `omen.toml` can also be a section inside a shared config without bleed-through).
  No nested sub-tables, no profiles. (Per-class severity tuning is still
  available — as the flat `severity-override` string key, not a sub-table.)
- **Keys are flag names** with the leading `--` dropped; dashes and underscores
  are interchangeable (`min-severity` *or* `min_severity`). `o` is accepted as
  the short alias for `output-file`. Settable keys: `contract`, `batch`,
  `input-type`, `check`, `exclude-check`, `ignore`, `parallel`, `timeout`,
  `batch-summary`, `baseline`, `sarif-baseline`, `rpc-url`, `format`,
  `min-confidence`, `min-severity`, `severity-override`, `sort`, `limit`,
  `fail-on`, `output-file`.
- **Values are validated** against the same choices the CLI enforces, so a typo
  in the file is caught at load time with a clear, file-named error (exit `2`),
  not silently fed into the analyzer.
- **CLI flags always win.** Precedence is: explicit CLI flag > config-file value
  > built-in default. The file only fills slots you did not set on the command
  line, so `--config omen.toml --fail-on never` overrides a `fail-on = "high"` in
  the file ad hoc.

Pure stdlib — `tomllib` ships with Python 3.11+ and omen requires 3.13+ — so
`--config` adds no dependency and runs offline / in CI / on a fresh checkout.

---

## Scope

In scope: the classes above (the four MAIAN classes, reentrancy, access-control,
tx-origin, delegatecall, and upgrade), on Ethereum, from Solidity source / Vyper
source / EVM bytecode / an on-chain address (read-only). access-control,
tx-origin, delegatecall, and upgrade are source-mode only. Vyper input covers
the reentrancy and prodigal subset that Slither's Vyper front-end supports.

Not in scope: a custom symbolic-execution engine (omen uses Slither's), non-
Ethereum chains, DeFi-specific patterns (oracle manipulation, flash loans,
MEV), automated proof-of-concept transaction generation, and any on-chain
transaction submission whatsoever.

---

## Development

```bash
pip install -e ".[dev]"
solc-select install 0.8.19 && solc-select use 0.8.19   # for source-mode tests
pytest
```

Bytecode and address tests run without `solc`; Solidity source-mode tests skip
cleanly if no `solc` is present, and Vyper source-mode tests skip cleanly if no
`vyper` is present (`pip install vyper`).

---

## Ethical use

omen is a tool for **authorized** security testing only: contracts you own,
contracts you are explicitly permitted to assess, or assets in scope of a
published bug-bounty program. Scanning or targeting contracts without
authorization may be illegal. omen never submits transactions and never
interacts with deployed contracts beyond read-only bytecode retrieval. You are
responsible for using it lawfully and within the rules of any program you
participate in.

---

## License & attribution

omen is MIT-licensed (see [`LICENSE`](./LICENSE)). It depends on Slither, which
is AGPL-3.0; see [`NOTICE`](./NOTICE) for prior-art attribution to MAIAN
(Nikolić et al., 2018) and full library credits.
