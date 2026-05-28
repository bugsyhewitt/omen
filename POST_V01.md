# omen — Post-v0.1 Improvement Roadmap

> **Rotation 1 research lap.** Current date: 2026-05-26.
> Sources: OWASP Smart Contract Top 10 (2025/2026), Immunefi/HackerOne
> program data, Trail of Bits Slither wiki, published exploit post-mortems
> (Q1 2025 – Q1 2026). Ranked by bounty-hunting impact, not implementation
> complexity. All items are explicitly excluded from v0.1 scope.

---

## Threat-landscape context

| Category | OWASP 2025/2026 tracked losses | Trend |
|---|---|---|
| Access control flaws | $953M | #1, climbing |
| Reentrancy (new forms) | $35.7M | persistent, new ERC-777/callback variants |
| Flash-loan-assisted attacks | $33.8M | 83% of eligible exploits in 2024 |
| Price oracle manipulation | $8.8M | often combined with flash loans |
| Unchecked external calls / logic bugs | smaller but frequent | top triage rejections on Immunefi |

Q1 2026 alone logged $482M in losses across 44 incidents. Access control is
the dominant category; oracle manipulation and flash-loan amplifiers are the
primary delivery mechanism for high-severity claims.

Key observation for omen: the four MAIAN classes (prodigal, suicidal, greedy,
reentrancy) remain live bounty targets. The high-value expansion territory is:
(a) broader bytecode coverage of the existing four classes, and (b) two new
classes — access-control and tx-origin misuse — that now outrank all four
MAIAN classes by loss volume.

---

## Ranked improvements

### 1. Bytecode-mode detection for prodigal, greedy, and reentrancy

**Rank: 1 — highest bounty-leverage per implementation token**

**What:** v0.1 bytecode/address mode detects only `suicidal` (via
`SELFDESTRUCT`). The other three classes return no findings for bytecode input
with a comment in code saying this requires a decompiler. In practice, many
on-chain contracts have no verified source, so address mode currently misses
75% of omen's four-class coverage.

**Approach:**
- `prodigal`: scan for `CALL` opcodes where the destination is loaded from
  `CALLDATALOAD` (caller-controlled destination) with non-zero value —
  pyevmasm can identify this pattern at the opcode level without full
  decompilation. Confidence: "medium" (not all such patterns are exploitable).
- `greedy`: scan for `PAYABLE` functions (constructor or fallback) combined
  with absence of any `CALL`/`DELEGATECALL`/`SELFDESTRUCT` opcodes with
  non-zero value — locked-ether bytecode signal.
- `reentrancy`: scan for `CALL` opcode followed by `SSTORE` before the next
  `RETURN`/`STOP`/`REVERT` in the same basic block — basic CEI violation
  pattern visible in bytecode.

**Caveats:** These heuristics will have higher false-positive rates than
Slither's source-level analysis. They should be reported at `confidence:
"low"` with a note that source-mode analysis provides higher precision.

**Why #1:** Every Immunefi program with a deployed contract is an address-mode
target. Current gap: 75% of detections unavailable for on-chain targets.
Closing this gap immediately multiplies omen's useful surface area.

**Effort estimate:** ~2–3 days. Only touches `detectors.py` and
`analyzer.py`. No new dependencies.

---

### 2. Access-control and tx-origin checks (new fifth and sixth classes)

**Rank: 2 — highest-impact new category by loss volume**

> **STATUS: ✅ IMPLEMENTED (R2, 2026-05-26).** Both classes are wired through
> `CATEGORIES`, `CATEGORY_TO_SLITHER`, `DEFAULT_SEVERITY` (access-control →
> high, tx-origin → medium), the CLI `--check` choices, and the `formats.py`
> remediation table. Fixtures (`vulnerable-access-control.sol`,
> `vulnerable-tx-origin.sol`, `clean-access-control.sol`) and tests
> (`tests/test_access_control_detection.py`, `tests/test_new_categories_wiring.py`)
> ship with it. **Mapping correction:** the Slither argument literally named
> `access-control` does not exist in slither-analyzer 0.11.x; access-control is
> mapped onto `protected-vars` (HIGH/HIGH — the canonical missing-onlyOwner
> signal, keyed off the `@custom:security write-protection` NatSpec annotation)
> plus `events-access` (missing event on admin/ownership change). tx-origin
> maps onto `tx-origin` as planned.

**What:** Add two new detection classes:
- `access-control`: maps to Slither `access-control` (missing function access
  restrictions) and `events-access` (missing events on admin changes).
- `tx-origin`: maps to Slither `tx-origin` (misuse of `tx.origin` as auth).

OWASP 2025/2026 ranks access-control #1 with $953M in tracked losses —
more than all four MAIAN classes combined. `tx.origin` misuse is a persistent
medium-severity finding that appears in almost every Immunefi scope and is
trivially detectable via Slither.

**Implementation:** Extend `CATEGORY_TO_SLITHER` in `detectors.py`:
```python
"access-control": ["access-control", "events-access"],
"tx-origin": ["tx-origin"],
```
Update `CATEGORIES` in `__init__.py`, extend `DEFAULT_SEVERITY`, update
`--check` choices in CLI, add remediation text to `formats.py`, and add
fixture contracts + tests.

**Why #2:** One-to-one mapping onto existing Slither detectors; very low
implementation risk. Dramatically expands omen's usefulness for common bounty
scopes. The tool description already positions omen as bounty-oriented — not
including #1-ranked loss category is a gap.

**Effort estimate:** ~1 day. Mostly plumbing + tests.

---

### 3. Batch-scan mode: scan a directory of .sol files or a list of addresses

**Rank: 3 — workflow multiplier for bounty hunters**

**What:** Add `--batch` flag that accepts either a directory path (recursively
finds `.sol` files) or a newline-delimited file of contract addresses. Emits
a JSONL stream (one JSON object per contract) so the caller can pipe to `jq`
or aggregate tooling.

**Example:**
```bash
omen --batch contracts/ --input-type sol --check all --format jsonl
omen --batch addresses.txt --input-type address --rpc-url $RPC --format jsonl
```

**Why #3:** Real bounty-hunting workflow involves scanning dozens to hundreds
of contracts in a program scope. The current single-contract interface forces
shell loops. Batch mode with JSONL output is the natural fit for this use
case. Trail of Bits' own Slither ships `slither-find-paths` / batch modes;
omen should too.

**Effort estimate:** ~1.5 days. Touches CLI and adds a new `batch.py` module.
No detector changes.

---

### 4. Dangerous-delegatecall and unprotected-upgrade detection

**Rank: 4 — high severity, proxy/upgrade pattern widely deployed**

> **STATUS: ✅ IMPLEMENTED (R5, 2026-05-28).** Both classes are wired through
> `CATEGORIES`, `CATEGORY_TO_SLITHER`, `DEFAULT_SEVERITY` (both → high), the CLI
> `--check` choices, and the `formats.py` remediation table. Fixtures
> (`vulnerable-delegatecall.sol`, `vulnerable-upgrade.sol`,
> `clean-delegatecall.sol`) and tests
> (`tests/test_delegatecall_upgrade_detection.py`,
> `tests/test_delegatecall_upgrade_wiring.py`) ship with it. **Mapping
> correction:** the Slither argument literally named `dangerous-delegatecall`
> does not exist in slither-analyzer 0.11.x; `delegatecall` is mapped onto
> `controlled-delegatecall` (HIGH — caller-influenceable target/function id)
> plus `delegatecall-loop` (HIGH). `upgrade` maps onto `unprotected-upgrade`
> (HIGH) as planned.

**What:** Add two more high-severity Slither detectors as omen classes:
- `delegatecall`: maps to `dangerous-delegatecall`, `controlled-delegatecall`,
  `delegatecall-loop`.
- `upgrade`: maps to `unprotected-upgrade`.

These are critical findings in proxy/upgradeable contracts — a dominant
pattern in all major DeFi protocols (OpenZeppelin Transparent / UUPS). An
unprotected upgrade function is an instant critical on any Immunefi program.

**Why #4:** After access-control, this is the next highest-severity Slither
detector cluster absent from omen. Proxy contracts are ubiquitous in bounty
scope.

**Effort estimate:** ~0.5 days. Pure plumbing like item 2.

---

### 5. Sarif output format

**Rank: 5 — CI/CD and GitHub integration**

**What:** Add `--format sarif` that emits a SARIF 2.1 JSON file. SARIF is
the standard consumed by GitHub Advanced Security (code scanning), VSCode, and
most CI systems. Slither itself can emit SARIF; omen should be able to pipe
its findings into the same ecosystem.

**Why #5:** Bounty hunters who also do formal audits or run omen in CI on
their own contracts want SARIF for IDE annotation and PR decoration. Low
effort, meaningful workflow improvement.

**Effort estimate:** ~1 day. New formatter in `formats.py`, no analysis
changes.

---

### 6. Vyper source support

**Rank: 6 — expanding addressable contract universe**

**What:** Slither supports Vyper (via `--from-vyper`). Many DeFi protocols
(Curve, Yearn) use Vyper. Add `--input-type vyper` that delegates to Slither's
Vyper compilation path. Detection classes available in Slither for Vyper are a
subset, but reentrancy and arbitrary-send are covered.

**Why #6:** Curve (the largest DEX by TVL) uses Vyper. Any bounty program
touching Curve-derived contracts is a Vyper target. omen currently has no Vyper
story.

**Effort estimate:** ~1 day. Mainly input loading + solc-select equivalent for
`vyper` binary, plus conditional skip for Slither detectors not applicable to
Vyper.

---

### 7. Integer-overflow / weak-PRNG detection

**Rank: 7 — medium-severity completeness**

**What:** Add:
- `overflow`: Slither `integer-overflow` (medium).
- `weak-randomness`: Slither `weak-prng` (medium).

Integer overflow has diminished post-Solidity-0.8 (overflow is now a revert by
default), but pre-0.8 contracts still appear in bounty scope. Weak PRNG
(blockhash, block.timestamp as randomness) remains a persistent medium finding.

**Why #7:** Useful for completeness on older contracts. Lower urgency than
items 1–4.

**Effort estimate:** ~0.5 days each.

---

### 8. Confidence-threshold filter flag

**Rank: 8 — false-positive control**

**What:** Add `--min-confidence {low,medium,high}` that suppresses findings
below the threshold. Relevant once item 1 (bytecode heuristics) ships, because
those findings default to `confidence: "low"` and users scanning large batches
will want to filter.

**Why #8:** Hygiene feature. Becomes necessary when item 1 and item 3 both
land.

**Effort estimate:** ~2 hours. Pure CLI + filter logic.

---

## Items explicitly out of scope (never)

- **Custom symbolic execution engine.** Manticore, Mythril, Echidna exist.
  omen is not a symbolic executor.
- **Automated PoC transaction generation.** omen never submits transactions,
  full stop.
- **Non-EVM chains** (Solana, Cosmos, etc). omen is an Ethereum/EVM tool.
- **Oracle manipulation detection.** Requires data-flow across external calls
  and protocol-specific knowledge — not achievable with Slither alone; belongs
  in a separate tool.
- **Flash-loan attack simulation.** Inherently dynamic; requires transaction
  submission.
- **AI/LLM-enhanced analysis.** Out of scope for this tool's design
  philosophy (reproducible, static, no network calls beyond eth_getCode).

---

## Implementation order recommendation

| Sprint | Items | Expected output |
|---|---|---|
| R2 | #2 (access-control, tx-origin) ✅ done | Two new classes, tests pass, README updated |
| R3 | #1 (bytecode heuristics) | Bytecode mode covers all 4+2 classes |
| R4 | #3 (batch mode) | `--batch` flag, JSONL output |
| R5 | #4 (delegatecall/upgrade) | Two more high-sev classes |
| R6 | #5 (SARIF) | SARIF formatter |
| R7 | #6 (Vyper) | `--input-type vyper` |
| R8 | #7 + #8 | overflow/PRNG + confidence filter |
