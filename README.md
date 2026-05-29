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
omen --contract <path-or-address> \
     --input-type {sol,vyper,bytecode,address} \
     --check CATEGORY[,CATEGORY...]   # a category, 'all', or a comma-separated list \
     [--rpc-url URL] \
     [--format {json,text,h1md,sarif}] \
     [--min-confidence {low,medium,high}] \
     [--min-severity {informational,low,medium,high,critical}] \
     [--sort {severity,none}] \
     [--limit N] \
     [--fail-on {never,informational,low,medium,high,critical}]

omen --list-checks [--format {text,json}]
```

- `--contract` — a path to a `.sol` source file, a path to a `.vy` (Vyper) source file, a path to a `.bin` (hex EVM runtime bytecode) file, or an on-chain contract address.
- `--input-type` — how to interpret `--contract`.
- `--check` — which class(es) to scan for. Accepts a single category, `all` (runs every class), or a **comma-separated list** of categories (e.g. `access-control,delegatecall,upgrade` to scope a scan to the proxy/admin attack cluster). Valid categories: `prodigal`, `suicidal`, `greedy`, `reentrancy`, `access-control`, `tx-origin`, `delegatecall`, `upgrade`, `overflow`, `weak-randomness`. `all` must be used alone. Default: `all`. See [Scoping a scan to specific classes](#scoping-a-scan-to-specific-classes).
- `--rpc-url` — JSON-RPC endpoint; **required** for `--input-type address`. Used read-only.
- `--format` — `json` (machine-readable, default), `text` (a compact human-readable terminal summary — a per-severity count line plus one line per finding, worst-first; see [Text output](#text-output)), `h1md` (a HackerOne-style markdown report), or `sarif` (a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) log for GitHub code scanning, VSCode, and CI ingestion).
- `--min-confidence` — suppress findings below this confidence level (`low`, `medium`, or `high`). Default: `low` (keep everything). Use `medium` or `high` to filter out the low-confidence bytecode/address heuristics when triaging large scans. Applies in single-contract and `--batch` mode alike.
- `--min-severity` — suppress findings below this severity level (`informational`, `low`, `medium`, `high`, or `critical`). Default: `informational` (keep everything). Use `high` or `critical` to surface only the high-impact leads first when triaging a whole program scope. Composes with `--min-confidence` (a finding must pass both) and applies in single-contract and `--batch` mode alike.
- `--sort` — order findings in the report. `severity` (default) lists them worst-first — highest severity, then highest confidence — so the high-impact leads appear at the top of every report; `none` preserves the raw detector order. Sorting runs *after* `--min-severity`/`--min-confidence`, so it never changes which findings appear, only their order. Applies in single-contract and `--batch` mode alike — see [Sorting findings](#sorting-findings).
- `--limit` — cap the report to at most `N` findings (a positive integer). Default: no limit (keep all). Applied *after* `--sort`, so with the default worst-first ordering it keeps the `N` highest-impact leads — the "show me the top N" triage move on a large scan. The report records the pre-cap `total_findings` and a `truncated` flag so a consumer can tell "10 of 47 shown" from "10 of 10". In `--batch` mode the cap is per-contract — see [Limiting findings](#limiting-findings).
- `--fail-on` — CI exit-code gate: exit non-zero (code `3`) when a finding reaches this severity (`informational`, `low`, `medium`, `high`, or `critical`). Default: `never` (always exit `0` on a clean run, the historical behaviour). Use e.g. `high` to fail a pipeline step when omen surfaces a high/critical lead. Evaluated *before* `--limit`, so a display cap can never hide a finding from the gate; applies in single-contract and `--batch` mode alike — see [Failing CI on findings](#failing-ci-on-findings).
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
