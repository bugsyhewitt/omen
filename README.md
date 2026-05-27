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

Bytecode mode (`--input-type bytecode`) and address mode (`--input-type address`)
need **no** `solc`.

---

## Usage

```
omen --contract <path-or-address> \
     --input-type {sol,bytecode,address} \
     --check {prodigal,suicidal,greedy,reentrancy,access-control,tx-origin,all} \
     [--rpc-url URL] \
     [--format {json,h1md}]
```

- `--contract` — a path to a `.sol` source file, a path to a `.bin` (hex EVM runtime bytecode) file, or an on-chain contract address.
- `--input-type` — how to interpret `--contract`.
- `--check` — which class to scan for (`all` runs every class). Default: `all`.
- `--rpc-url` — JSON-RPC endpoint; **required** for `--input-type address`. Used read-only.
- `--format` — `json` (machine-readable, default) or `h1md` (a HackerOne-style markdown report).

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

> access-control and tx-origin are **source-mode** checks (they need Slither's
> static analysis); they are not detectable from raw bytecode alone, so they
> produce no findings in `--input-type bytecode`/`address` mode.

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

---

## Scope

In scope: the classes above (the four MAIAN classes, reentrancy, access-control,
and tx-origin), on Ethereum, from Solidity source / EVM bytecode / an on-chain
address (read-only). access-control and tx-origin are source-mode only.

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

Bytecode and address tests run without `solc`; source-mode tests skip cleanly
if no `solc` is present.

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
