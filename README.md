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
     --check {prodigal,suicidal,greedy,reentrancy,access-control,tx-origin,delegatecall,upgrade,all} \
     [--rpc-url URL] \
     [--format {json,h1md,sarif}]
```

- `--contract` — a path to a `.sol` source file, a path to a `.vy` (Vyper) source file, a path to a `.bin` (hex EVM runtime bytecode) file, or an on-chain contract address.
- `--input-type` — how to interpret `--contract`.
- `--check` — which class to scan for (`all` runs every class). Default: `all`.
- `--rpc-url` — JSON-RPC endpoint; **required** for `--input-type address`. Used read-only.
- `--format` — `json` (machine-readable, default), `h1md` (a HackerOne-style markdown report), or `sarif` (a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) log for GitHub code scanning, VSCode, and CI ingestion).

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

> access-control, tx-origin, delegatecall, and upgrade are **source-mode**
> checks (they need Slither's static analysis); they are not detectable from raw
> bytecode alone, so they produce no findings in `--input-type bytecode`/
> `address` mode.

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
