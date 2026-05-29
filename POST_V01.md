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

> **STATUS: ✅ IMPLEMENTED (R6, 2026-05-28).** `--format sarif` emits a SARIF
> 2.1.0 log document. Wired through the CLI `--format` choices and a new
> `to_sarif()` in `formats.py` (dispatched by `render`). Each omen category
> maps to one SARIF reporting rule (`omen/<category>`); each finding becomes
> one result. Severity maps to SARIF levels (high/critical → error, medium →
> warning, low/informational → note) and carries a GitHub `security-severity`
> score; source-mode findings include `region` line ranges parsed from omen's
> `file#start-end` source mappings, bytecode-mode findings keep opcode offsets
> in the result `properties`. Tests in `tests/test_formats.py`
> (`test_sarif_*`); README "SARIF output" section documents the GitHub Actions
> upload flow. No analysis-path changes — formatter only.

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

> **STATUS: ✅ IMPLEMENTED (R7, 2026-05-28).** `--input-type vyper` analyzes
> `.vy` source via Slither's Vyper front-end. New `vyper` input type wired
> through `sources.py` (`load_vyper`, a `.vy` loader), `analyzer.py`
> (`_analyze_source` now handles both Solidity and Vyper; selects the source
> path and, for Vyper, narrows to the supported subset), the CLI
> `--input-type` choices, and `batch.py`'s error handling. A new `vyper_env.py`
> module mirrors `solc_env.py`: `require_vyper()` / `vyper_status()` /
> `VyperUnavailableError` (stdlib `shutil.which` — no `solc-select` equivalent
> exists for Vyper, so omen does not auto-provision a compiler). **Subset
> decision:** Slither's Vyper front-end supports only a subset of its Solidity
> detectors, so omen restricts Vyper input to `reentrancy` and `prodigal`
> (`VYPER_SUPPORTED_CATEGORIES` in `detectors.py`) — the two POST_V01-named
> covered classes. `--check all` on a `.vy` file silently narrows to that
> subset; an explicit unsupported class (e.g. `suicidal`) raises a clear
> `InputError` instead of returning an empty report. Fixtures
> (`vulnerable-reentrancy.vy`, `clean-reentrancy.vy`, intentionally with no
> `# @version` pragma so they compile on whatever vyper is present) and tests
> (`tests/test_vyper_support.py`) ship with it; the `requires_vyper` skip
> marker in `conftest.py` mirrors `requires_solc`. **Toolchain caveat:**
> crytic-compile's Vyper support tracks specific compiler versions (it fully
> supports vyper 0.3.7); the end-to-end detection tests skip cleanly on a
> slither/crytic-compile↔vyper version mismatch rather than failing, since that
> is a toolchain limitation, not an omen integration defect — omen's job is to
> route the `.vy` file to Slither, which the wiring tests verify it does.

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

> **STATUS: ✅ IMPLEMENTED (R8, 2026-05-28).** Both classes are wired through
> `CATEGORIES`, `CATEGORY_TO_SLITHER`, `DEFAULT_SEVERITY` (both → medium), the
> CLI `--check` choices (auto-derived from `CATEGORIES`), and the `formats.py`
> remediation table. Fixtures (`vulnerable-overflow.sol`,
> `vulnerable-weak-randomness.sol`, `clean-overflow.sol`) and tests
> (`tests/test_overflow_randomness_detection.py`,
> `tests/test_overflow_randomness_wiring.py`) ship with it. **Mapping
> correction:** the Slither argument literally named `integer-overflow` does
> not exist in slither-analyzer 0.11.x — Slither ships no standalone overflow
> detector because Solidity 0.8+ makes raw overflow a revert by default. The
> `overflow` category is therefore mapped onto the real arithmetic-precision
> detectors `divide-before-multiply` (MEDIUM — division before multiplication
> truncating precision) plus `tautology` (MEDIUM/HIGH-confidence — a comparison
> that is always true/false, the symptom of a broken bounds/overflow guard).
> `weak-randomness` maps onto `weak-prng` as planned. **Severity note:** both
> default to MEDIUM per this roadmap's "medium-severity completeness" framing;
> in source mode the analyzer follows Slither's own per-finding impact, so a
> `weak-prng` finding (which Slither classifies HIGH) surfaces at HIGH at
> runtime — the MEDIUM is the documented default/fallback. Both are source-mode
> only (Slither static analysis); they are not in the Vyper-supported subset.

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
| R3 | #1 (bytecode heuristics) ✅ done | Bytecode mode covers all 4+2 classes |
| R4 | #3 (batch mode) ✅ done | `--batch` flag, JSONL output |
| R5 | #4 (delegatecall/upgrade) ✅ done | Two more high-sev classes |
| R6 | #5 (SARIF) ✅ done | SARIF formatter |
| R7 | #6 (Vyper) ✅ done | `--input-type vyper` |
| R8 | #7 + #8 ✅ done | overflow/PRNG + confidence filter |

> **Rotation 1 roadmap exhausted (as of R9, 2026-05-28).** All eight ranked
> items above are implemented and merged. The items below are Rotation 2
> additions — discoverability/UX improvements that fall out of the now-larger
> detector surface. They are appended here rather than in a separate file so
> the roadmap history stays in one place; a full Rotation 2 research lap (new
> threat-landscape scan + re-ranking) is still owed.

---

## Rotation 2 additions

### R2.1. `--list-checks` detector catalog introspection

**Rank: 1 (Rotation 2) — zero-dependency discoverability**

> **STATUS: ✅ IMPLEMENTED (R9, 2026-05-28).** `omen --list-checks` prints every
> detection class with its default severity, the input modes it runs in
> (`sol` / `vyper` / `bytecode` / `address`), and the underlying Slither
> detector(s) it maps to, then exits. Honors `--format text` (default) or
> `--format json`. A new `catalog.py` module assembles the catalog purely by
> introspecting the existing in-code data structures (`CATEGORIES`,
> `CATEGORY_TO_SLITHER`, `DEFAULT_SEVERITY`, `VYPER_SUPPORTED_CATEGORIES`, and a
> `BYTECODE_SUPPORTED_CATEGORIES` set asserted against `_analyze_bytecode` so it
> cannot drift) — it imports no Slither / solc / vyper / network code, so the
> listing is as fast and dependency-free as `--help` and works offline / in CI
> / on a fresh checkout with no compiler installed. `--input-type` is no longer
> argparse-`required` (so the listing can run with no target); the scan-mode
> "target + input-type required" gate moved into `main()`. Tests in
> `tests/test_list_checks.py`; README "Listing the detection classes" section
> documents it.
>
> **Why:** Once the roster grew to 10 classes across four input modes with
> several non-obvious category→detector mappings (`access-control` →
> `protected-vars` + `events-access`; `overflow` → `divide-before-multiply` +
> `tautology`; etc.), that knowledge lived only in source-code comments. A
> bounty hunter pointing omen at a new program scope needs to know, up front,
> which classes apply to a `.vy` file vs. an unverified on-chain address, and
> what each omen category actually checks. `--list-checks` surfaces it directly.

---

### R2.2. `--min-severity` triage filter

**Rank: 2 (Rotation 2) — zero-dependency triage lever**

> **STATUS: ✅ IMPLEMENTED (R10, 2026-05-28).** `omen --min-severity
> {informational,low,medium,high,critical}` suppresses findings whose severity
> ranks below the threshold; the default `informational` keeps every finding
> (no behaviour change for existing invocations). It is the severity-axis
> sibling of the Rank 8 `--min-confidence` filter and is built the same way: a
> `SEVERITY_ORDER` tuple + `severity_rank()` primitive in `findings.py`, a pure
> `_filter_by_severity()` in `analyzer.py` applied after analysis (so the
> serialized `finding_count` always matches what is shown), wired through
> `analyze()`, `run_batch()` (uniform across a batch), and the CLI. The two
> filters **compose** — a finding must clear both the severity and the
> confidence threshold to survive. Tests in `tests/test_min_severity.py` (rank
> primitive, pure filter across the full taxonomy, bytecode-mode integration,
> compose-with-confidence, CLI surface, batch forwarding, subprocess
> end-to-end); README "Filtering by severity" section documents it. Pure
> filter change — no analysis-path, detector, or dependency changes, so it runs
> offline / in CI / on a fresh checkout with no compiler installed.
>
> **Why:** Once the roster grew to ten classes spanning informational..critical,
> a scan of a whole program scope produces a long, severity-mixed finding list.
> The first triage pass a bounty hunter makes is "show me the high-impact leads
> first" — the severity analogue of suppressing low-confidence heuristic noise.
> `--min-confidence` already covered the confidence axis; `--min-severity`
> completes the triage surface on the severity axis, and the two compose for the
> tightest "high-severity, high-confidence only" first pass.

---

### R2.3. `--sort` severity-first finding ordering

**Rank: 3 (Rotation 2) — zero-dependency triage ordering**

> **STATUS: ✅ IMPLEMENTED (R11, 2026-05-28).** `omen --sort {severity,none}`
> orders the findings in a report. The default `severity` lists them worst-first
> — highest severity, then highest confidence as a tie-break — so the
> high-impact leads sit at the top of every report instead of being scattered
> through the raw detector-registration order; `none` preserves that raw order.
> It is the ordering complement to the Rotation 2 filters: where `--min-severity`
> / `--min-confidence` decide *which* findings survive, `--sort` decides *what
> order* the survivors are read in. Built the same zero-dependency way: a pure
> `sort_key()` primitive in `findings.py` (negated `severity_rank` then negated
> `confidence_rank`, so a plain ascending stable sort is worst-first and ties
> preserve detector order) and a pure `_sort_findings()` in `analyzer.py` applied
> *after* the two filters (so the serialized `finding_count` is never affected),
> wired through `analyze()`, `run_batch()` (uniform across a batch), and the CLI.
> It composes with both filters and every output format. Tests in
> `tests/test_sort.py` (sort-key primitive incl. confidence tie-break, pure
> reorder across the full taxonomy, stability within a severity bucket,
> no-add/no-drop/no-mutate invariants, bytecode-mode integration, runs-after-
> filters, CLI surface, batch forwarding, subprocess end-to-end); README
> "Sorting findings" section documents it. Pure ordering change — no
> analysis-path, detector, or dependency changes, so it runs offline / in CI /
> on a fresh checkout with no compiler installed.
>
> **Why:** Rotation 2's first two items grew the triage *filter* surface; this
> closes the triage *presentation* gap. After `--min-severity` narrows a
> whole-program scan to high/critical leads, the analyst still reads the report
> top-down, but findings come out in detector-registration order, which
> interleaves a HIGH suicidal with a MEDIUM greedy with a LOW-confidence
> reentrancy heuristic. Worst-first ordering — on by default because it is the
> order every triage pass wants — means the most exploitable lead is line one of
> every report, JSON, h1md, or SARIF alike. The confidence tie-break is the
> direct payoff of POST_V01 Rank 1: within one severity bucket, the precise
> opcode-signature finding (high confidence) outranks the coarse heuristic (low
> confidence), so the lead a hunter should chase first surfaces first.

---

### R2.4. `--limit` top-N finding cap

**Rank: 4 (Rotation 2) — zero-dependency triage volume control**

> **STATUS: ✅ IMPLEMENTED (R12, 2026-05-28).** `omen --limit N` caps a report to
> at most N findings. It is the third stage of the Rotation 2 triage pipeline:
> the filters (`--min-severity` / `--min-confidence`) decide *which* findings
> survive, `--sort` decides *what order* the survivors are read in, and `--limit`
> decides *how many* to read. The cap runs *after* `--sort`, so with the default
> worst-first ordering it keeps the N highest-impact leads — the "just show me
> the top N" move on a whole-program scan that still emits dozens of findings
> after the filters. Built the same zero-dependency way: a `parse_limit()`
> validation primitive in `findings.py` (positive-int only; `None`/empty = no
> limit; `0`/negatives rejected because a zero cap would silently hide every
> lead) and a pure `_limit_findings()` in `analyzer.py` applied after the two
> filters and the sort, wired through `analyze()`, `run_batch()` (the cap is
> per-contract — each JSONL line shows at most N findings, not a cap on the
> number of contracts), and the CLI (a `_positive_int` argparse type).
> **Honesty note:** unlike the filters and the sort, the cap *does* change which
> findings appear, so `AnalysisReport` now carries a pre-cap `total_findings`
> and `to_dict()` emits `total_findings` and a `truncated` boolean alongside the
> shown `finding_count` (so a consumer can tell "10 of 47 shown" from "10 of
> 10"); the `h1md` formatter renders `Findings: 10 of 47 (top 10 shown;
> --limit)` when truncated. Tests in `tests/test_limit.py` (parse_limit
> primitive incl. zero/negative/bool/string rejection, pure cap step, to_dict
> total/truncated bookkeeping, runs-after-sort, composes-with-filters,
> bytecode-mode integration, string-limit acceptance, CLI surface incl.
> validation rejections, batch per-contract forwarding, h1md truncation line,
> subprocess end-to-end); README "Limiting findings" section documents it. Pure
> ordering/slice change — no analysis-path, detector, or dependency changes, so
> it runs offline / in CI / on a fresh checkout with no compiler installed.
>
> **Why:** Rotation 2's first three items built the triage filter and ordering
> surface, but on a large program scope even a `--min-severity high` scan can
> leave a long list. The natural next zero-dependency triage-UX lever is volume:
> after worst-first sorting, an analyst's first pass is "chase the top handful of
> leads." `--limit` completes the filter → sort → cap pipeline, and pairs
> directly with the R2.3 default sort — the cap is only meaningful because the
> findings are already ordered worst-first, so `--limit N` deterministically
> yields the N most exploitable leads.

---

### R2.5. `--fail-on` CI exit-code gate

**Rank: 5 (Rotation 2) — zero-dependency CI gate**

> **STATUS: ✅ IMPLEMENTED (R13, 2026-05-28).** `omen --fail-on
> {never,informational,low,medium,high,critical}` turns the report into a
> process exit code so omen can fail a CI step. It is the natural fourth stage
> of the Rotation 2 triage pipeline: the filters (`--min-severity` /
> `--min-confidence`) decide *which* findings survive, `--sort` decides *what
> order* they are read in, `--limit` decides *how many* to read, and `--fail-on`
> decides *whether the run passes*. The default `never` keeps the historical
> always-exit-`0` behaviour (a clean run exits 0 regardless of what it found, so
> every existing invocation is unchanged); a severity name makes omen exit `3`
> when at least one finding reaches that severity — the standard
> security-scanner CI pattern (Slither's `--fail-high`, the severity gates in
> semgrep/trivy/bandit). Exit `3` is distinct from the existing `2` (input
> error) and `1` (analysis crash) so a pipeline can tell "found something" from
> "broke." Built the same zero-dependency way: a pure `fail_on_triggered()`
> primitive in `findings.py` (an `any(severity_rank(f) >= threshold)` over the
> findings, with a `FAIL_ON_NEVER` sentinel) and a `gate_triggered` bool on
> `AnalysisReport`, computed in `analyze()` over the filtered findings **before**
> the `--limit` cap (so a display cap can never hide a gate-tripping finding from
> the exit code) and surfaced in `to_dict()` alongside the exit signal. Wired
> through `analyze()`, `run_batch()` (the batch gate is the OR across items; a
> per-item failure's exit `1` still outranks the gate's `3`), and the CLI (which
> maps `report.gate_triggered` onto exit `3` after printing the report). The gate
> composes with the filters — a `--min-severity`-suppressed finding does not trip
> it — and with every output format. Tests in `tests/test_fail_on.py` (gate
> primitive across the full severity taxonomy incl. exact-threshold/above/below
> boundaries, empty set, case-insensitivity, mixed-set any(); to_dict
> bookkeeping; bytecode-mode integration; evaluated-before-limit incl. a
> monkeypatched cannot-hide-a-finding case; composes-with-min-severity; CLI
> surface incl. default `never` and unknown-value rejection; in-process `main()`
> exit codes 0/3; batch OR + error-outranks-gate; subprocess end-to-end exit
> codes); README "Failing CI on findings" section documents it with the exit-code
> table and a GitHub Actions blocking-step example. Pure decision/exit-code change
> — no analysis-path, detector, or dependency changes, so it runs offline / in CI
> / on a fresh checkout with no compiler installed.
>
> **Why:** Rotation 1's Rank 5 added SARIF output, which surfaces findings as
> GitHub code-scanning annotations — but uploading SARIF does not *fail* a build.
> The Rotation 2 triage levers all shape *what the analyst reads*; the missing
> piece for the CI/own-contracts audience (the same audience SARIF targets) is a
> lever that shapes *whether the pipeline passes*. `--fail-on high` is the move
> that makes omen a merge-gating check: run it on a PR, and a newly introduced
> high-severity lead blocks the merge. It completes the
> filter → sort → cap → gate pipeline and pairs directly with the existing SARIF
> story — annotate *and* fail, the two halves of a security check in CI.

---

### R2.6. `--format text` compact terminal output

**Rank: 6 (Rotation 2) — zero-dependency presentation/readability layer**

> **STATUS: ✅ IMPLEMENTED (R14, 2026-05-28).** `omen --format text` renders a
> scan as a compact, human-readable terminal view: a one-line header (tool
> version + origin), an `input:`/`checks:` line, a per-severity count summary
> (worst-first, e.g. `[2 high, 1 medium]`), then one line per finding — index,
> width-padded upper-cased severity, category, confidence in brackets, and where
> to look (the first source mapping in source mode, or `@0x<offset>` in
> bytecode/address mode). It is the presentation complement to the Rotation 2
> *triage pipeline* (filter → sort → cap → gate): once `--min-severity` /
> `--min-confidence` decide which findings survive, `--sort` orders them
> worst-first, and `--limit` caps them, an analyst running omen interactively
> wants a glanceable summary rather than a JSON blob, a HackerOne markdown body,
> or a SARIF document. Built the same zero-dependency way as the R6 SARIF
> formatter: a pure `to_text()` in `formats.py` (plus `_severity_summary()` and
> `_finding_line()` helpers) dispatched by `render`, reusing `SEVERITY_ORDER`
> from `findings.py` for the worst-first summary ordering. It is a pure formatter
> over `report.findings` — it never re-orders or re-filters, so it composes with
> all three triage levers and honours the same `--limit` truncation accounting as
> the h1md format (`findings: N of M (top N shown; --limit)`). The CLI `--format`
> choice list already included `text` (it was the `--list-checks` default); R14
> extends it to scan output, so a scan with `--format text` now renders the
> terminal view instead of being an inert choice. `--batch` mode still always
> emits JSONL regardless of `--format` (unchanged), so `text` applies to
> single-contract scans. Tests in `tests/test_formats.py` (`test_text_*` + the
> `render` dispatch case: header/summary/finding-line shape, bytecode
> opcode-offset display, source-location display, worst-first summary,
> one-line-per-finding in report order, empty-report "none"/"No findings", and
> `--limit` "N of M" truncation) and `tests/test_cli_help.py` (format-choice
> surface + a bytecode end-to-end subprocess run that needs no compiler); README
> "Text output" section documents it with a sample. Pure formatter change — no
> analysis-path, detector, or dependency changes, so it runs offline / in CI / on
> a fresh checkout with no compiler installed.
>
> **Why:** Rotation 2 R2.1–R2.5 built the full triage *logic* surface — list the
> classes, filter by severity/confidence, sort worst-first, cap to top-N, gate
> CI — but omen's three scan output formats were all *machine/handoff* targets:
> JSON for tooling, h1md for a HackerOne submission, SARIF for code-scanning
> ingestion. The one audience left unserved was the analyst at a terminal who
> just ran a scan and wants to read the result *now*, worst-first, without piping
> through `jq` or opening a SARIF viewer. `--format text` closes that gap: it is
> the human-readable read of exactly the findings the triage pipeline produced,
> the presentation sibling to the SARIF/JSON machine formats.

---

### R2.7. Comma-separated `--check` category lists

**Rank: 7 (Rotation 2) — zero-dependency detection-surface selection**

> **STATUS: ✅ IMPLEMENTED (R15, 2026-05-28).** `--check` now accepts a single
> category, the keyword `all`, **or a comma-separated list** of categories (e.g.
> `--check access-control,delegatecall,upgrade` — the proxy/admin attack
> cluster). The categories run in the order listed; duplicates are removed
> preserving first-seen order; whitespace and empty segments from a trailing or
> doubled comma are tolerated; an unknown name is a usage error (exit `2`) that
> names the offender; and `all` must be used alone (`all,reentrancy` is rejected
> because `all` already covers every class). The report's `checks` field echoes
> the resolved list. Built the same zero-dependency way as the rest of Rotation
> 2: the parsing/validation/dedupe logic is a pure extension of the existing
> `resolve_checks()` primitive in `analyzer.py` (no new module, no new
> dependency), and the CLI wires it in by dropping argparse's `choices=` on
> `--check` (which could only validate a single token) and validating the raw
> value through `resolve_checks()` in `main()` before dispatch, surfacing a bad
> value as an argparse-style exit-`2` usage error. **Wiring-test migration:**
> three existing `test_*_wiring.py` tests asserted the new categories appeared in
> `check_action.choices`; since validation moved off argparse `choices`, those
> assertions were rewritten to assert `resolve_checks(cat) == [cat]` — the same
> intent ("the CLI accepts this category") against the new validation mechanism.
> Tests in `tests/test_check_list.py` (resolve_checks: backward-compatible
> single/`all`, two/three-category lists, user-order preservation, dedupe,
> whitespace/trailing-comma tolerance, unknown-member rejection naming the
> offender, empty/only-commas rejection, `all`-alone-in-a-list expansion,
> `all`-combined rejection, every-category-individually, full-list-of-all; CLI
> surface: help advertises the syntax, parser accepts a raw comma list without
> argparse rejection, exit-`2` on a bad member and on `all,other`; bytecode-mode
> end-to-end subprocess runs proving a list scopes the scan to exactly the
> requested classes and *excludes* unrequested ones). README "Scoping a scan to
> specific classes" section documents it; the `--list-checks` footer now mentions
> the list syntax. Pure input-selection change — no analysis-path, detector, or
> dependency changes, and the comma-list resolution imports nothing heavy, so it
> runs offline / in CI / on a fresh checkout with no compiler installed.
>
> **Why (R15 research-lap reasoning):** Rotation 2 R2.1–R2.6 built out the entire
> *output* surface — list the classes (`--list-checks`), filter the findings by
> severity/confidence (`--min-severity`/`--min-confidence`), order them
> worst-first (`--sort`), cap them (`--limit`), gate CI on them (`--fail-on`), and
> render them for a human (`--format text`). Every one of those operates on the
> findings *after* analysis. The one axis the Rotation 2 work never touched is the
> *input* axis: which detectors actually run. `--check` had been single-category
> or `all` since v0.1, so a bounty hunter assessing a specific program scope — say
> an upgradeable proxy, where the relevant surface is exactly
> `access-control,delegatecall,upgrade` — had only two bad options: run `--check
> all` and wade through findings from seven irrelevant classes, or run three
> separate scans and merge the JSON by hand. With the roster now at ten classes,
> the gap between "one class" and "all ten" is wide enough that selecting a subset
> is the natural next zero-dependency lever, and it is *foundational* rather than
> cosmetic: it shapes the detection surface itself, the input-side complement to
> the output-side triage pipeline the rest of Rotation 2 built. Among the
> remaining unshipped candidates (a `--exclude` inverse, per-category severity
> overrides, config files), the comma-list `--check` is the highest
> value-per-token: it reuses the existing `resolve_checks()` seam entirely, adds
> no module and no dependency, is fully backward compatible (a single category and
> `all` behave exactly as before), and directly serves the dominant real workflow
> of scoping a scan to a program's actual attack surface.

---

### R2.8. `--exclude-check` inverse category selector

**Rank: 8 (Rotation 2) — zero-dependency detection-surface selection (inverse)**

> **STATUS: ✅ IMPLEMENTED (R16, 2026-05-29).** `--exclude-check
> CATEGORY[,CATEGORY...]` removes one or more categories from whatever `--check`
> resolved to — the inverse of the R2.7 comma-list. It accepts a single category
> or a comma-separated list (with the same whitespace/trailing-comma tolerance
> and first-seen-order dedupe as `--check`), but **not** the keyword `all`
> (excluding every class would scan nothing, so `--exclude-check all` is a usage
> error). The exclusion is applied *after* `--check` resolves and preserves the
> `--check` order, so the surviving categories run in the same order they would
> have without it; the report's `checks` field echoes the surviving set.
> **Two deliberate semantics:** (a) excluding a category `--check` did not select
> is a **no-op**, not an error (so an exclude list can be reused across scans with
> different `--check` scopes — `--check reentrancy --exclude-check suicidal`
> simply yields `[reentrancy]`); (b) excluding *every* selected category leaves
> nothing to scan, which is a usage error (exit `2`) rather than a silently
> always-empty report. Built the same zero-dependency way as R2.7: the R2.7
> `resolve_checks()` parsing logic was factored into a shared `parse_categories()`
> primitive in `analyzer.py` (parameterised by an `allow_all` flag — `--check`
> allows `all`, `--exclude-check` does not), and `resolve_checks()` gained an
> optional `exclude` argument that parses the exclude spec and subtracts it,
> raising on an empty result. The CLI adds `--exclude-check` (no argparse
> `choices`, mirroring R2.7 — validation runs through `resolve_checks()` in
> `main()` and surfaces a bad value as an exit-`2` usage error) and forwards it
> through `analyze()` and `run_batch()` (uniform across a batch). Tests in
> `tests/test_exclude_check.py` (parse_categories primitive incl. allow_all
> on/off, `all`-rejection on the exclude side, unknown-member and empty
> rejection; resolve_checks subtraction incl. no-exclude backward-compat,
> exclude-one/list-from-all, `--check`-order preservation, no-op on unselected,
> empty-set rejection, exclude-all-from-all rejection, `all`-keyword rejection,
> unknown-member naming; CLI surface incl. help text, argparse acceptance,
> default `None`, exit-`2` on unknown member / on `all` / on excluding every
> selected class; bytecode-mode end-to-end subprocess runs proving an exclusion
> removes exactly the named class and that a no-op exclusion keeps the rest).
> README "Excluding classes from a scan" section documents it; the usage block
> and flag list mention it. Pure input-selection change — no analysis-path,
> detector, or dependency changes, and the comma-list resolution imports nothing
> heavy, so it runs offline / in CI / on a fresh checkout with no compiler
> installed.
>
> **Why (R16 research-lap reasoning):** R2.7 closed the *positive* input axis —
> scope a scan *to* a comma-list of classes. The R15 lap explicitly named the
> `--exclude` inverse as the leading remaining candidate, and it is the natural,
> highest-value-per-token next step: it lives on the same input axis, reuses the
> exact `resolve_checks()` seam (refactored, not duplicated), adds no module and
> no dependency, and is fully backward compatible (omitting it changes nothing).
> The two selectors are complementary across the common real workflows: a
> comma-list `--check` is the right tool when the relevant surface is a small
> named cluster (the proxy/admin trio), and `--exclude-check` is the right tool
> when the relevant surface is "almost everything" — e.g. a whole-program scan
> minus the two low-confidence bytecode heuristics (`greedy`, `prodigal`) that
> dominate triage noise — where enumerating the other eight classes by hand would
> be tedious and error-prone. Together they let a bounty hunter express the
> detection surface from either direction, whichever is shorter for the scope at
> hand. Among the remaining unshipped candidates (per-category severity
> overrides, a config-file form of the now-many flags), the inverse selector is
> the cheapest and the one already flagged as next, so it ships first.

---

### R2.9. `-o` / `--output-file` report destination

**Rank: 9 (Rotation 2) — zero-dependency report destination redirect**

> **STATUS: ✅ IMPLEMENTED (R17, 2026-05-29).** `-o` / `--output-file PATH` writes
> the rendered report straight to `PATH` instead of stdout. Default is unchanged
> (stdout). It composes with **every** `--format`: in single-contract mode the
> file receives the rendered `json`/`text`/`h1md`/`sarif` report; in `--batch`
> mode it receives the JSONL stream (one JSON object per contract). The write is
> **atomic** — content is written to a sibling `PATH.tmp` and `os.replace`-d into
> place — so a crash mid-write (or a half-produced batch stream) never clobbers a
> previously good report with a truncated one; parent directories are created on
> demand. The redirect changes only the *destination*: the file content is
> byte-for-byte what the same invocation prints to stdout (tests assert this
> equality). The `--fail-on` exit code is orthogonal — the gate still trips
> (exit `3`) and the report is still written to the file first, so a CI step can
> both fail the build and archive the report artifact in one run. Implemented as
> a small `write_output(text, output_file)` helper in `cli.py` (stdout when
> `None`, atomic file write otherwise) used by single-contract mode; `run_batch()`
> gained an `output_file` parameter that buffers the JSONL lines and flushes them
> through the same helper at the end (streaming to stdout, line by line, remains
> the default behaviour when no path is given). Tests in
> `tests/test_output_file.py` (write_output primitive: stdout fallback, trailing
> newline, atomicity/no leftover `.tmp`, parent-dir creation, overwrite; CLI
> surface: help text, default `None`, short and long flag parsing; single-mode
> main(): writes to file not stdout, file matches stdout byte-for-byte, composes
> with `--format text`/`sarif`, `--fail-on` exit code unchanged; batch forwarding:
> JSONL to file, default still streams stdout, gate exit preserved; end-to-end
> subprocess writing a real file). README "Writing the report to a file" section
> documents it; the usage block and flag list mention it. Pure plumbing change —
> no analysis-path, detector, format, or dependency changes (stdlib `os`/`pathlib`
> only), so it runs offline / in CI / on a fresh checkout with no compiler.
>
> **Why (R17 research-lap reasoning):** R2.1–R2.8 built the full *output* pipeline
> (list → filter → sort → cap → gate → render) and closed the `--check` *input*
> axis from both directions. The one axis the pipeline never touched is the
> report's *destination* — every prior flag shapes *what* the report contains or
> *how* it reads; none controls *where* it goes. The candidates flagged for this
> lap were `-o/--output-file`, `--config`, `--timeout`, and `--quiet`. `--quiet`
> is nearly a no-op (omen prints only the report to stdout — there is no
> informational chatter to suppress). `--timeout` needs per-check execution
> isolation that Slither does not cleanly expose. `--config` (a `.omenrc`/YAML/TOML
> default-flags file) is the largest lift — it touches every flag, needs a parser
> and precedence rules, and risks the Simplicity Gate (future-proofing against a
> problem omen does not yet have). `-o/--output-file` is the cheapest,
> highest-value-per-token move: it composes with all four output formats and both
> scan modes, adds no module and no dependency, is fully backward compatible
> (omitting it is the historical stdout behaviour), and closes the last untouched
> pipeline axis. The atomic-write detail is the one piece of real engineering —
> it makes the flag safe to point at a long-lived artifact path in CI without the
> "scan crashed and left me a truncated SARIF" failure mode. `--config` remains
> the leading remaining candidate for a future lap.

---

### R2.10. `--config` TOML config-file defaults

**Rank: 10 (Rotation 2) — zero-dependency config-file form of the now-many flags**

> **STATUS: ✅ IMPLEMENTED (R18, 2026-05-29).** `--config PATH` loads a TOML file
> whose keys set **default** values for the other flags, so a repo can commit one
> `omen.toml` and shrink the now-dozen-flag CI invocation to `omen --config
> omen.toml --contract X` (or drive everything — including `contract`/`input-type`
> — from the file). The contract is deliberately small: a **flat name→value map**
> at the top level *or* under an `[omen]` table (when an `[omen]` table is present
> its keys are used, so `omen.toml` can also sit as a section in a shared config
> without bleed-through); **no** nested sub-tables, profiles, or per-category
> overrides — the Simplicity-Gate floor. Keys are flag names with the leading
> `--` dropped, dashes and underscores interchangeable (`min-severity` /
> `min_severity`), with `o` aliased to `output_file`. Settable keys: `contract`,
> `batch`, `input-type`, `check`, `exclude-check`, `rpc-url`, `format`,
> `min-confidence`, `min-severity`, `sort`, `limit`, `fail-on`, `output-file`.
> Values are validated against the **same choices the CLI enforces** (choices for
> the enum flags; positive-int for `limit`; `check`/`exclude-check` run through
> the analyzer's `resolve_checks` on the merged value, exactly as a CLI value
> would), so a typo is a file-named usage error (exit `2`), not a runtime crash.
> **Precedence is explicit CLI flag > config-file value > built-in default**: the
> file only fills slots the user did not pass on the command line, so any flag
> stays overridable ad hoc. Implemented as a small `config.py` (`load_config`
> reads/validates the TOML into a `{flag: value}` map; `ConfigError` carries a
> human, file-named message) plus a `cli.py` merge step — `_explicitly_set_dests`
> re-parses argv against a `SUPPRESS`-default clone of the parser to learn which
> flags were actually typed, and `_apply_config` writes config values only into
> the untyped slots before the existing single/batch dispatch runs unchanged.
> Pure stdlib (`tomllib`, Python 3.11+; omen requires 3.13+) — **no dependency**,
> runs offline / in CI / on a fresh checkout. Tests in `tests/test_config.py` (27
> cases: loader — top-level vs `[omen]` table, dashed/underscore/`o`-alias key
> normalisation, table-wins-over-toplevel, empty file, foreign-table ignore,
> missing-file/invalid-TOML/unknown-key/bad-choice/non-positive-limit/bool-limit/
> string-limit/non-string-choice errors; CLI surface — help lists it, default
> `None`; `main()` — config supplies the gate / output-file / format / contract+
> input-type, CLI flag overrides config, bad config value and missing file are
> exit-2 usage errors, config `check` validated after merge; end-to-end subprocess
> driving a real `omen.toml`). README gains a "Config files (`omen.toml`)" section
> plus a usage-block and flag-list mention. No analysis-path, detector, format, or
> dependency change.
>
> **Why (R18 research-lap reasoning):** R2.9 and the Rotation 2 status note both
> flagged `--config` as "the leading remaining candidate." After R2.1–R2.9 the CLI
> surface is ~a dozen flags; the cost of that expressiveness is invocation length
> — every pipeline step repeats the same long one-liner. `--config` is the one
> remaining axis that addresses *invocation ergonomics* rather than report content
> or destination. The R17 lap deferred it as "the largest lift … risks the
> Simplicity Gate (future-proofing)." That risk is real but avoidable: the lift is
> bounded by keeping the contract a **flat one-flag-per-key map with CLI override**
> — no profiles, no env-var layer, no nested overrides, no new file-discovery
> magic (you pass the path explicitly; omen does not hunt for `.omenrc` up the
> tree). That floor mirrors the existing flags one-for-one, reuses the existing
> validation choices, and adds no dependency (`tomllib` is stdlib). The one piece
> of real engineering is the precedence detection — distinguishing "user typed the
> flag" from "argparse filled the default" via a `SUPPRESS`-default re-parse — so
> the file never surprises someone overriding it on the command line. Remaining
> candidates for a future lap: per-category severity overrides, `--timeout`
> per-check execution isolation (needs Slither subprocess wrapping), `--quiet`.

---

### R2.11. `--ignore` batch path/pattern exclusion

**Rank: 11 (Rotation 2) — zero-dependency batch input-selection axis**

> **STATUS: ✅ IMPLEMENTED (R19, 2026-05-29).** `--ignore PATTERN[,PATTERN...]`
> is a comma-separated list of `fnmatch` glob patterns; in `--batch` mode any
> contract path/address the scan would otherwise visit that matches one is
> skipped before analysis. The motivating case is the whole-repo scan: pointed
> at a real repository, omen's recursive `.sol` walk pulls in vendored and
> third-party code (`node_modules`, a Foundry `lib/` tree, an OpenZeppelin
> import tree, mocks under `test/`) that is not the attack surface, wastes
> analysis time, and floods the JSONL stream. `--ignore node_modules,lib,test`
> drops those up front without hand-pruning the input. Matching is permissive so
> the common cases need no `*/…/*` boilerplate: a pattern matches the full path
> as a glob, **or** any single path component (bare `node_modules` hits
> `repo/node_modules/X.sol`), **or** — when it contains a `/` — any sub-path
> (`lib/openzeppelin` hits `repo/lib/openzeppelin/Foo.sol`). Globs support
> `*`/`?`/`[seq]`; OR semantics across patterns. Applies to both `--batch` input
> shapes — a directory's recursive walk and a newline-delimited list file (paths
> *or* addresses). An ignored item produces no JSONL line and no error, so the
> exit code reflects only the contracts actually scanned. **No effect in single
> `--contract` mode** (one explicit target, nothing to filter) — accepted there
> as a no-op so a committed `omen.toml` carrying `ignore` still works for single
> scans. An all-blank value (`--ignore ,,`) is a usage error (exit `2`), not a
> silent no-op. Implemented entirely in `batch.py` (`parse_ignore` splits/cleans
> the value; `_is_ignored` applies the three match rules; `_iter_items` filters
> at the source so the existing `run_batch` loop is unchanged) plus a `cli.py`
> flag + early `parse_ignore` validation, and an `ignore` key added to
> `config.py`'s settable set. Pure stdlib (`fnmatch`) — **no dependency**, runs
> offline / in CI / on a fresh checkout. Tests in `tests/test_ignore.py` (31
> cases: parser — none/single/comma-list/whitespace/empty-entry/all-blank-raises;
> matcher — empty/component/full-glob/sub-path/`?`/`[seq]`/multi-OR/address;
> `_iter_items` — directory and list-file filtering, no-ignore no-op, multi-
> pattern; `run_batch` — skips ignored files via mocked analyze, none no-op,
> all-blank raises; config — `ignore` key accepted / non-string rejected; CLI —
> help, namespace parse, default `None`, exit-2 on all-blank, single-contract
> no-op end-to-end). README gains an "Excluding paths from a batch scan" section
> plus usage-block, flag-list, and config-key mentions. No analysis-path,
> detector, format, or dependency change.
>
> **Why (R19 research-lap reasoning):** Rotation 2 closed the *output* pipeline
> (R2.1–R2.6), the `--check` *class* axis from both directions (R2.7–R2.8), the
> *destination* axis (R2.9), and *invocation ergonomics* (R2.10 `--config`). The
> R18 status note left three un-ranked candidates: per-category severity
> overrides, `--timeout` per-check isolation, and `--quiet`. `--timeout` is the
> riskiest — the roadmap has flagged twice that Slither "does not cleanly expose"
> per-check execution isolation, so it needs subprocess wrapping that risks the
> Anti-Abstraction and Simplicity gates. `--quiet` is near-vacuous (omen prints
> only the report to stdout). Per-category severity overrides duplicate the
> existing `--min-severity` lever at higher complexity. The untouched axis with
> real value is **batch *input selection by path***: every class/filter flag
> shapes *which findings* or *which classes*, and `--check`/`--exclude-check`
> select classes — but nothing selects *which files* a batch scan visits. On a
> real repo that is the difference between a focused first-party scan and a
> hundred-line JSONL stream of vendored noise. `--ignore` is the cheapest,
> highest-value-per-token move left: zero dependency (`fnmatch` is stdlib),
> bounded scope (it slots into the existing `_iter_items` generator — the
> `run_batch` loop, analyzer, detectors, and formats are untouched), fully
> backward compatible (omitting it is the historical "scan everything"), and it
> mirrors the existing comma-list/validation/config-key conventions one-for-one.
> The one piece of real engineering is the three-way match rule, chosen so the
> 90%-case (`--ignore node_modules`) works without glob boilerplate. Remaining
> candidates for a future lap: `--timeout` (still needs Slither subprocess
> isolation), per-category severity overrides, `--quiet`.

---

### R2.12. `--batch-summary` aggregate batch roll-up

**Rank: 12 (Rotation 2) — zero-dependency batch-aggregate read**

> **STATUS: ✅ IMPLEMENTED (R20, 2026-05-29).** `--batch-summary` prints an
> aggregate roll-up to **stderr** after a `--batch` run's JSONL stream (default
> off). It is the *aggregate* complement to the whole Rotation 2 triage surface:
> every prior lever — `--min-severity`/`--min-confidence`, `--sort`, `--limit`,
> `--fail-on`, `--ignore` — operates **per contract**; none gives a read *across*
> a whole-program scan. After scanning a program scope an analyst still had N
> JSONL lines and had to `jq`-aggregate by hand to answer the first question:
> "how did the scan go, overall?" The roll-up answers it directly — a header line
> (`contracts: N scanned, M with findings, E errored`), a worst-first
> per-severity total line (`findings: T total [1 critical, 4 high, …]`, only
> severities that occur), an "up to five worst-affected contracts, most-first"
> block (so the analyst knows where to look before opening the JSON), and a
> `--fail-on gate: TRIPPED` line mirroring the exit-`3` gate. It goes to **stderr,
> never stdout**, so the stdout JSONL stays a clean machine feed for `jq` — the
> JSONL can be redirected to a file/pipe while the human roll-up still prints to
> the terminal. The total uses each contract's pre-`--limit` `total_findings`, so
> a display cap never undercounts the scope total. Built the same zero-dependency
> way as the rest of Rotation 2: a pure `summarize_batch(reports, errors)`
> primitive in `batch.py` (a `_SUMMARY_SEVERITY_ORDER` tuple + plain dict
> aggregation over the same per-contract report dicts that were already streamed —
> no I/O, no analysis, unit-testable in isolation), wired into `run_batch` (which
> collects the report dicts only when the flag is on, preserving the streaming
> low-memory path otherwise; it also now tracks an `error_count` for the header).
> The CLI adds `--batch-summary` (a plain `store_true`, no-op in single
> `--contract` mode — accepted there so a committed `omen.toml` carrying it still
> works), and `config.py` gains a `_BOOL_KEYS` set so `batch-summary = true` is a
> recognised, bool-validated config key. Tests in `tests/test_batch_summary.py`
> (21 cases: summarize_batch primitive — header counts, worst-first severity
> roll-up, only-present severities, none-found, prefer-total_findings-over-shown,
> top-affected ordering+five-cap, singular/plural noun, gate line, empty batch,
> missing-total_findings fallback; run_batch integration — stderr-not-stdout, off
> by default, error-count reflected, composes-with-output-file; CLI surface —
> help, default False, sets True; config — bool accepted, non-bool/int rejected;
> subprocess end-to-end). README gains a "Summarizing a batch scan" section plus
> usage-block, flag-list, and config-key mentions. Pure presentation/aggregation
> change — no analysis-path, detector, or format change, and `summarize_batch`
> imports nothing heavy, so it runs offline / in CI / on a fresh checkout with no
> compiler installed.
>
> **Why (R20 research-lap reasoning):** R2.1–R2.11 built the full per-contract
> triage surface (list → filter → sort → cap → gate → render), closed the
> `--check` class axis both directions, the output destination, invocation
> ergonomics (`--config`), and batch input-path selection (`--ignore`). The three
> un-ranked candidates the R18/R19 status notes carried forward were `--timeout`,
> per-category severity overrides, and `--quiet`. Each was the wrong next step:
> `--timeout` needs Slither subprocess execution isolation the roadmap has twice
> flagged as not cleanly exposed (Anti-Abstraction / Simplicity risk);
> per-category severity overrides duplicate `--min-severity` at higher
> complexity; `--quiet` is near-vacuous (omen prints only the report). The real
> untouched axis is **batch aggregation**: every Rotation 2 lever shapes a
> *single contract's* findings, but `--batch` — the bounty hunter's whole-program
> workflow — has only ever emitted a raw per-contract JSONL stream with no scope
> roll-up. That is the highest-value-per-token move left: it lives squarely in
> the established Rotation 2 theme (triage/UX over the ten-class roster), reuses
> the existing `run_batch` seam and the per-contract dicts already produced (no
> extra analysis, no new module, no dependency), is fully backward compatible
> (off by default), mirrors the existing config-key/flag conventions, and the
> stderr/stdout split keeps the machine feed clean while serving the human read —
> the exact pairing the `--format text` per-contract view already established, now
> at batch scope. Remaining candidates for a future lap: `--timeout` (still needs
> Slither subprocess isolation), per-category severity overrides, `--quiet`.

---

### R2.14. `--timeout` per-contract batch budget

**Rank: 14 (Rotation 2) — zero-dependency batch resilience**

> **STATUS: ✅ IMPLEMENTED (R23, 2026-05-29).** `--timeout SECONDS` gives each
> contract a per-contract wall-clock budget in `--batch` mode (default: no budget
> — each scan runs to completion, the historical behaviour). A contract whose
> scan overruns is abandoned and recorded as a per-item error (the same
> `(None, error)` shape an exception produces): it counts toward the exit-`1`
> error tally and the `--batch-summary` error count, with an
> `omen: batch timeout [path]: analysis exceeded Ns budget` message to stderr,
> and produces no JSONL line. This protects a whole-program batch's throughput
> from the hazard `--parallel` (R2.13) does not address: a *single* pathological
> contract (a hanging compiler, a runaway symbolic path, a degenerate import
> graph) that never finishes and would otherwise stall the entire
> dozens-to-hundreds-of-contracts run. **The defining design decision is that
> `--timeout` is enforced on the existing `--parallel` thread-pool orchestration
> seam, not by subprocess-isolating Slither.** The roadmap flagged `--timeout`
> five times (R17–R20, and again in the R22/R2.13 reasoning) as the riskiest
> candidate *specifically because* a naive reading — per-check timeout of the
> in-process `slither.run_detectors()` call — needs subprocess wrapping of the
> analysis path that violates the Anti-Abstraction and Simplicity gates and
> changes omen's defining architecture. The unlock is that the **batch** layer
> already runs each `analyze` call in a worker future (R2.13), so the budget can
> be enforced from the driver thread with `Future.result(timeout=...)` —
> abandoning the *wait* on an overrunning item — without touching any analysis
> code, detector, or format, and without killing the in-process scan. Setting a
> timeout therefore always takes the pool path (a single shared worker at
> `--parallel 1`), since the budget can only be enforced by waiting on a future.
> The honest semantic, pinned by a test and documented: the budget bounds the
> *wait*, not the scan — with the default single worker a stuck scan still
> occupies the lone thread, so items queued behind it also time out; **the
> "make progress past a stuck contract" guarantee needs a free worker, i.e.
> pairing `--timeout` with `--parallel >= 2`.** The abandoned worker thread is
> left to finish and is reclaimed at pool shutdown (`shutdown(wait=False,
> cancel_futures=True)` so the batch returns promptly past the stuck item),
> rather than forcibly killed. Order is preserved exactly as for `--parallel`:
> results (report or timeout error) are folded into the run's state in input
> order via the same `_consume` closure, so the JSONL stream, the `--fail-on`
> gate, the error count, and the summary stay deterministic. Built the same
> zero-dependency way as the rest of Rotation 2: a `parse_timeout()` validation
> primitive in `batch.py` (positive **float** — fractional sub-second budgets are
> sensible, unlike integer worker counts; `None` = no budget; `0`, negatives,
> NaN, infinity, and `bool` rejected), wired through `run_batch` (a `timeout`
> parameter; a 0/1-item batch keeps the sequential path) and the CLI (a
> `_positive_float` argparse type, so a non-positive value is an exit-`2` usage
> error like `--limit`/`--parallel`). `config.py` gains a `_FLOAT_KEYS` set with
> `timeout` (accepts `timeout = 2.5` or `timeout = 30`, coerced to float;
> non-finite/non-positive/bool/string rejected at load time). **No effect in
> single `--contract` mode** (one target, nothing a per-item batch budget bounds)
> — accepted there as a no-op so a committed `omen.toml` carrying `timeout = 60`
> still works for single scans. Tests in `tests/test_timeout.py` (31 cases:
> `parse_timeout` primitive incl. zero/negative/NaN/inf/bool/non-numeric
> rejection and int/float/string acceptance; `run_batch` — slow-item
> abandonment, clean-run-unaffected, input-order preservation, summary error
> counting, error-outranks-gate, output-file composition, prompt progress past a
> stuck item, the single-worker-blocks-queue semantic, default-unchanged,
> bad-value raise; config — float/int accepted, non-positive/bool/string
> rejected; CLI — help, namespace parse, default `None`, exit-`2` on `0`,
> single-contract no-op end-to-end, batch end-to-end input-order). README gains a
> "Bounding per-contract scan time" section plus usage-block, flag-list, and
> config-key mentions. Pure orchestration change — no analysis-path, detector, or
> format change, no new dependency (`concurrent.futures` is stdlib), and fully
> backward compatible (default no-budget is the historical behaviour) — so it
> runs offline / in CI / on a fresh checkout with no compiler installed.
>
> **Why (R23 reasoning):** `--timeout` was the leading un-shipped candidate the
> R22 note carried forward, and the only one whose blocker was an architecture
> objection rather than low value. That objection turned out to be against a
> *specific implementation* (subprocess-isolating the in-process Slither analysis
> per check), not against `--timeout` as a feature — and R2.13 had just built the
> exact seam (a thread pool over independent `analyze` futures) that makes the
> feature shippable without that implementation. `Future.result(timeout=...)`
> bounds the batch's blocking wait per contract, which is the real
> bounty-workflow value: a hundred-contract scope must not be held hostage by one
> contract that never compiles. Shipping it on the batch seam keeps every gate
> intact — no abstraction layer over Slither, no subprocess plumbing, no
> dependency, no architecture change — while honestly scoping what the budget
> does (bounds the wait, pair with `--parallel` to skip past). The remaining
> un-shipped Rotation 2 candidate is `--quiet`, which stays near-vacuous (omen
> prints only the report to stdout); per-category severity tuning is already
> covered by `--severity-override` (R21). With R2.14 the batch axis now spans
> *which* files (`--ignore`), *how fast* (`--parallel`), *how long each may take*
> (`--timeout`), and *how the result reads* (`--batch-summary`).

---

### R2.13. `--parallel` batch concurrency

**Rank: 13 (Rotation 2) — zero-dependency batch throughput**

> **STATUS: ✅ IMPLEMENTED (R22, 2026-05-29).** `--parallel N` analyzes up to N
> contracts concurrently in `--batch` mode (default `1` — sequential, the
> historical behaviour). The bounty workflow `--batch` exists for is scanning a
> whole program scope (dozens to hundreds of contracts); each `analyze` call is
> independent and its wall time is dominated by the `solc`/`vyper` compiler
> subprocess it shells out to (which releases the GIL), so a
> `concurrent.futures.ThreadPoolExecutor` over the items gives a real speedup
> without multiprocessing's pickling/import-state hazards. **The defining
> invariant is that concurrency never reorders the result:** output, the
> `--fail-on` gate (the OR across items), the error count, and the
> `--batch-summary` roll-up are all assembled in deterministic **input order**
> regardless of which scan finishes first (the per-item work is folded into the
> run's state via a single `_consume` closure called in input order; the pool
> path uses `executor.map`, which preserves submission order), so a `--parallel
> N` run's JSONL stream and exit code are byte-for-byte identical to the
> sequential run's — only faster. The trade-off vs. the sequential path is
> memory: a parallel run buffers the ordered results before emitting them rather
> than streaming line by line; the sequential default keeps the streaming,
> low-memory profile unchanged. Built the same zero-dependency way as the rest of
> Rotation 2: a `parse_parallel()` validation primitive in `batch.py`
> (positive-int only, mirroring `parse_limit`; `None`/`1` = no concurrency; `0`,
> negatives, and `bool` rejected) and an `_analyze_one()` per-item helper that
> returns a `(report, error)` pair so the try/except is shared between the
> sequential and pool paths, wired through `run_batch` (a `parallel` parameter; a
> 0/1-item batch always takes the sequential path since a pool would be pure
> overhead) and the CLI (`type=_positive_int`, so a non-positive value is an
> exit-`2` usage error, identical to `--limit`). `config.py` gains `parallel` as
> an `_INT_KEYS` member so `parallel = 8` is a recognised, positive-int-validated
> config key. **No effect in single `--contract` mode** (one target, nothing to
> parallelise) — accepted there as a no-op so a committed `omen.toml` carrying
> `parallel = 8` still works for single scans. Tests in `tests/test_parallel.py`
> (27 cases: parse_parallel primitive incl. zero/negative/bool/non-numeric
> rejection; run_batch — input-order preservation under a finish-order-reversing
> mock, byte-for-byte equivalence with the sequential run, true-concurrency
> overlap check, gate OR across items, error-outranks-gate, summary error
> counting, output-file ordering, single-item/default sequential paths, bad-value
> raise; config — `parallel` key accepted / non-positive / bool rejected; CLI —
> help, namespace parse, default `None`, exit-`2` on `0`, single-contract no-op
> end-to-end, batch end-to-end input-order). README gains a "Parallelizing a
> batch scan" section plus usage-block, flag-list, and config-key mentions. Pure
> orchestration change — no analysis-path, detector, or format change, and the
> thread pool imports nothing heavy, so it runs offline / in CI / on a fresh
> checkout with no compiler installed.
>
> **Why (R22 research-lap reasoning):** The suggested item paired `--parallel`
> concurrency with `--timeout` per-check subprocess isolation. `--timeout` has
> been flagged four times across this roadmap (R17/R18/R19/R20) as the riskiest
> candidate — Slither runs in-process (`slither.run_detectors()`), so per-check
> timeout needs subprocess wrapping of the analysis path that violates the
> Anti-Abstraction and Simplicity gates and would change the defining
> architecture. `--parallel`, by contrast, lives entirely in the existing
> `run_batch` orchestration seam: the loop was already `for item in
> _iter_items(...)` over independent `analyze` calls, so swapping the driver for
> a thread pool touches no analysis code, no detector, and no format, adds no
> dependency (`concurrent.futures` is stdlib), and is fully backward compatible
> (default `1` is the historical sequential path). It is the highest-value batch
> lever left after R2.1–R2.12 built the full per-contract triage surface and the
> R2.11/R2.12 batch input-selection and aggregate-roll-up axes: those shaped
> *which* files a batch visits and *how the result reads*, but nothing addressed
> the batch's *throughput* — the literal time a whole-program scan takes, which
> on a hundred-contract scope is the dominant cost. `--timeout` (still needs
> Slither subprocess isolation) and per-category severity overrides
> (`--severity-override` already covers the severity-tuning need as of R21) remain
> the leading un-shipped candidates for a future lap; `--quiet` stays near-vacuous
> (omen prints only the report to stdout).

---

> **Rotation 2 status (as of R18, 2026-05-29).** R2.1–R2.10 shipped. The Rotation 2
> theme has been the triage/UX surface around the now-ten-class detector roster:
> R2.1–R2.6 built the full *output* pipeline (list → filter → sort → cap → gate →
> human-readable render), R2.7–R2.8 closed the *input* axis from both directions
> — scope a scan *to* a comma-list of classes (`--check`) or *exclude* a comma-list
> from it (`--exclude-check`) — R2.9 closed the *destination* axis (`-o` /
> `--output-file` writes the report to a file, atomically, in any format and in
> batch mode) — and R2.10 closed the *invocation-ergonomics* axis (`--config`
> loads a TOML file of flag defaults so a committed `omen.toml` shrinks repeated
> CI one-liners, CLI flags always overriding the file). A fresh full
> threat-landscape re-scan + re-ranking is still owed before Rotation 2 is
> declared complete; remaining un-ranked candidates noted during the R18 lap
> include per-category severity overrides, `--timeout` per-check execution
> isolation, and `--quiet`.

---

## Rotation 3 additions

### R3.1. `--baseline` known-good finding suppression

**Rank: 1 (Rotation 3) — adopt-on-a-legacy-codebase CI lever**

> **STATUS: ✅ IMPLEMENTED (R24, 2026-05-29).** `--baseline PATH` suppresses
> findings already present in a previously-saved omen JSON report (a
> single-contract report, or one line / the whole JSONL stream of a `--batch`
> run), so only findings *new* relative to the baseline appear in the report,
> count toward `total_findings`, and trip the `--fail-on` gate. This is the
> standard "triage / baseline" lever every mature scanner ships (Slither
> `--triage-mode`, semgrep `--baseline`, trivy `.trivyignore`): the first run of
> a scanner on an existing codebase lights up red on every pre-existing finding,
> so the `--fail-on` gate (R2.5) is unusable until a team can say "fail only on
> findings introduced *after* this point." A finding's identity for matching is a
> stable fingerprint — **category + detector + contract + location** (the source
> line range in source mode, the opcode offset in bytecode/address mode) —
> deliberately *excluding* severity, confidence, title, and description, so a
> `--severity-override` (R21) re-stamp or a Slither release rewording a detector
> message does not make a known finding look new. Built the same zero-dependency,
> pure-primitive way as the rest of the triage surface: `finding_fingerprint()`
> (accepts a live `Finding` or its `to_dict()` form so a live finding and one
> read from a baseline file compute the same fingerprint), `load_baseline_
> fingerprints()` (permissive loader: single JSON report object, a JSON array of
> them, or a JSONL batch stream; an empty/clean baseline is valid and suppresses
> nothing; a missing/unreadable/non-JSON file raises `ValueError`), and
> `suppress_baseline()` (drops findings whose fingerprint is in the set; `None`/
> empty is a no-op) — all in `findings.py`. Wired through `analyze` (a `baseline`
> param; suppression runs *after* `apply_severity_overrides` so an override still
> applies to surviving findings, and *before* the `--min-severity`/
> `--min-confidence` filters, `--sort`, `--limit`, and the `--fail-on` gate, so a
> baselined finding never appears, never counts, never gates), `run_batch`/
> `_analyze_one` (forwarded per item, so a whole-program batch fails only on new
> findings; a batch baseline is naturally the JSONL output of a previous batch
> run), and the CLI (`--baseline PATH`, validated up front so a broken baseline
> is an exit-`2` usage error before any compiler/network work, consistent with
> the `--check`/`--ignore`/`--severity-override` validations). `config.py` gains
> `baseline` as a `_PATH_KEYS` member, so a committed `omen.toml` carrying
> `baseline = "omen-baseline.json"` makes "fail only on new findings" the default
> for every invocation. Tests in `tests/test_baseline.py` (33 cases:
> fingerprint — source/bytecode location, order-insensitivity, ignores
> severity/confidence/wording, distinguishes category/location/detector, dict vs
> object symmetry; loader — single report, JSONL stream, JSON array, empty
> findings, empty file, non-dict skip, missing-file raise, non-JSON raise;
> suppress — None/empty no-op, drops-baselined-keeps-new, drops-all; analyze
> integration (bytecode, no solc) — no-baseline keeps all, self-baseline
> suppresses everything, suppresses only known finding, suppresses *before* the
> `--fail-on` gate, new finding still trips the gate, survives a
> `--severity-override`; CLI — help, parse/default, missing/non-JSON usage error;
> config — `baseline` accepted / non-string rejected; subprocess end-to-end —
> capture baseline then re-scan unchanged code with `--baseline --fail-on high`
> exits 0 with zero findings). README gains a "Suppressing known findings with a
> baseline" section plus usage-block, flag-list, and config-key mentions. Pure
> filter-pipeline change — no detector, analysis-path, or format change, and the
> loader imports only stdlib `json`, so it runs offline / in CI / on a fresh
> checkout with no compiler installed.
>
> **Why (R24 research-lap reasoning):** Rotation 2 exhausted the per-contract
> triage surface (R2.1–R2.10) and the batch axes (input selection R2.11/R2.8,
> aggregate roll-up R2.12, throughput R2.13 `--parallel`, per-contract budget
> R2.14 `--timeout`), and R21 added org-specific severity tuning
> (`--severity-override`). What none of those addressed is the *temporal* axis:
> every prior lever filters/orders/caps/gates a *single* scan in isolation, with
> no notion of "what changed since last time." That gap is precisely what blocks
> the highest-value workflow the `--fail-on` gate (R2.5) was built for —
> failing CI on findings — from being usable on any codebase that isn't
> greenfield. A scanner that can only say "there are 47 findings" cannot be wired
> into a PR gate on a legacy contract; one that can say "there is 1 finding *new*
> in this PR" can. `--baseline` is the canonical fix, present in every comparable
> tool, and it fits omen's architecture cleanly: it is one more pure primitive in
> `findings.py` and one more parameter on the existing `analyze`/`run_batch`
> seam, adding no dependency and touching no detector or format. The remaining
> un-shipped candidates after R24 are `--quiet` (still near-vacuous — omen prints
> only the report to stdout) and `--timeout` Slither *subprocess* isolation
> (still violates the Anti-Abstraction / Simplicity gates; the R2.14 batch
> `--timeout` already bounds the per-item *wait*, which is the bounty-workflow
> value).

### R3.2. `--diff` report-to-report delta

**Rank: 2 (Rotation 3) — the temporal complement to `--baseline`**

> **STATUS: ✅ IMPLEMENTED (R25, 2026-05-29).** `--diff OLD NEW` compares two
> previously-saved omen JSON reports and prints the delta: findings **added** (in
> NEW, not OLD), **removed** (in OLD, not NEW), and the **unchanged** count. Where
> `--baseline` (R3.1) *suppresses* known findings during a live scan, `--diff`
> *reports* what changed between two already-saved reports — a pure offline
> operation needing no contract, compiler, Slither, or network, so it runs on a
> fresh checkout / in CI exactly like `--list-checks`. Each report may be a
> single-contract JSON, a JSON array of them, or a `--batch` JSONL stream
> (whatever `-o` produced). A finding's identity for matching is the **same stable
> fingerprint `--baseline` uses** — `finding_fingerprint()`, category + detector +
> contract + location — so a `--severity-override` re-stamp or a Slither wording
> change does not show up as churn; the delta is deterministic (ordered by
> fingerprint) regardless of how either report listed its findings. Built the same
> zero-dependency, pure-primitive way as the rest of the triage surface:
> `load_baseline_findings()` (a sibling of `load_baseline_fingerprints` that keeps
> the full finding dict keyed by fingerprint, so the diff can show *which*
> findings changed, not just how many; same permissive shapes and same
> `ValueError`-on-broken-input loudness) and `diff_findings()` (the pure set delta
> returning sorted `added`/`removed`/`unchanged` lists) in `findings.py`, plus a
> self-contained `diff.py` module (`build_diff`, `diff_gate_triggered`, and
> `to_text`/`to_json`/`render`) following the `catalog.py` offline-action pattern.
> Wired into the CLI as `--diff OLD NEW` (nargs=2), handled right after
> `--list-checks` — before the scan-target requirement — so it runs with no
> `--contract`/`--batch`/`--input-type`. Honors `--format` (text default, json for
> automation; h1md/sarif rejected as inapplicable to a report delta), `-o`
> (atomic write, same as a scan report), and crucially `--fail-on`, which gates on
> the **added** findings only (exit `3` when a newly-introduced finding reaches
> the chosen severity) — the "fail the PR on a regression" CI move, with no need
> to re-run the scanner. A removed or unchanged finding never re-trips a gate the
> previous run already accounted for. A missing/unreadable/non-JSON report is an
> exit-`2` usage error, surfaced before any work, consistent with `--baseline`.
> Tests in `tests/test_diff.py` (31 cases: loader — keys by fingerprint keeping
> the full dict, JSONL/array/single shapes, empty findings/file, non-dict skip,
> first-wins-on-duplicate, missing/non-JSON raise; `diff_findings` —
> added/removed/unchanged, identical-no-changes, deterministic order, ignores
> severity/wording; build_diff summary counts; gate — trips on added high, ignores
> removed/unchanged; renderers — text lists +/- blocks, no-changes message, opcode
> location, json roundtrip, render dispatch + bad-format raise; CLI — parses two
> args, default None, needs-no-target, json format, fail-on trips on added /
> not on removed, missing-file & bad-format usage errors, output-file; subprocess
> end-to-end — diff with `--fail-on high` exits 3 on a new high finding). README
> gains a "Diffing two reports" section plus usage-block and flag-list mentions.
> Pure offline-action change — no detector, analysis-path, scan-format, or
> dependency change; the loader imports only stdlib `json`.
>
> **Why (R25 reasoning):** R24's `--baseline` solved the *scan-time* temporal
> question (fail only on findings new since a captured baseline). The remaining
> R3.2 gap was the *after-the-fact* one: given two reports already on disk, what
> changed? `--baseline` cannot answer it (it re-runs the scanner against a live
> target and a fingerprint set; it never sees the old report's *details*, only its
> identities, and it never reports what was *removed*). The two R3.2 candidates
> were `--diff` (compare two report files) and `--sarif-baseline` (SARIF-native
> `baselineState` suppression). `--diff` won on architectural fit and value
> density: it reuses the exact R3.1 fingerprint primitive, adds no dependency, is
> a pure offline action on the same `findings.py` seam, and serves the high-value
> "what did this PR change to the scan?" review/changelog workflow plus a
> zero-rescan regression gate. `--sarif-baseline` would have required modeling
> SARIF result-matching/`baselineState` semantics and reading SARIF *input* — a
> heavier, format-coupled surface for a workflow `--baseline` + the existing SARIF
> *output* already mostly cover. It remains the natural R3.3 candidate if a team
> needs GitHub-code-scanning-native suppression specifically.

### R3.3. `--sarif-baseline` SARIF-native suppression

**Rank: 1 (Rotation 26) — the GitHub-code-scanning-native complement to `--baseline`**

> **STATUS: ✅ IMPLEMENTED (R26, 2026-05-29).** `--sarif-baseline PATH`
> annotates each result in a `--format sarif` document with a SARIF-native
> [`baselineState`](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html#_Toc34317648):
> `"unchanged"` when the finding's fingerprint is already in `PATH` (a known,
> pre-existing issue) and `"new"` when it is not (introduced since). This is the
> R3.2 candidate deferred in R25's reasoning above, taken in the *value-dense*
> interpretation the architecture invited: it reuses the **exact R3.1
> fingerprint primitive** (`finding_fingerprint` — category + detector +
> contract + location, excluding severity/wording) loaded by the existing
> `load_baseline_fingerprints`, and annotates omen's own SARIF *output* rather
> than parsing SARIF *input*. No SARIF result-matching engine, no new
> dependency, no format-coupled input parser — the heavier surface R25 flagged
> is sidestepped while still delivering the GitHub-Advanced-Security-native
> suppression the candidate was about.
>
> The contrast with `--baseline` (R3.1) is the whole point and is deliberate:
> `--baseline` *drops* known findings before they are emitted (so they vanish
> from the report and the `--fail-on` gate); `--sarif-baseline` *keeps every
> result* and tags it, leaving the suppression to GitHub (which folds
> `unchanged` results into its pre-existing-alert view). Consequently
> `--sarif-baseline` does **not** alter the `--fail-on` exit code — a
> baselined-`unchanged` high finding still trips `--fail-on high` (exit 3),
> because nothing was dropped. The two are complementary and composable.
>
> **Surface.** `to_sarif(report, *, baseline=None)` gains the optional
> fingerprint set and writes `result["baselineState"]` only when it is not
> `None` (so the no-flag SARIF output is byte-for-byte unchanged); `render`
> grows a `sarif_baseline` keyword that it threads only to the SARIF branch
> (ignored for text/json/h1md, which have no `baselineState` analogue). The CLI
> adds `--sarif-baseline PATH`, validated up front: it is a usage error (exit 2)
> with anything but `--format sarif`, a usage error under `--batch` (batch emits
> JSONL, not a SARIF document), and a usage error for a missing/unreadable/
> non-JSON baseline — all surfaced before any compiler/network work, consistent
> with `--baseline`. `sarif_baseline` joins `_PATH_KEYS` in `config.py`, so a
> committed `sarif-baseline = "omen-baseline.json"` makes the annotation the
> default for a code-scanning workflow. Pure stdlib; the loader imports only
> `json`. Tests in `tests/test_sarif_baseline.py` (17 cases): formatter — no
> baseline omits the field, empty baseline marks all `new`, known→`unchanged`/
> fresh→`new`, severity-override survives, output shape unchanged but for the
> one added key, empty report valid; render threading — sarif gets it, other
> formats ignore it; CLI — help, parse/default-None, requires-sarif-format,
> rejects-batch, missing/non-JSON usage errors; end-to-end against the
> mixed-confidence bytecode fixture — self-baseline marks all `unchanged`,
> partial baseline marks the new finding `new`, and the `--fail-on` gate still
> trips (the explicit `--baseline` contrast). README gains a "SARIF-native
> suppression with a baseline" section plus usage-block, flag-list, and
> config-key mentions.
>
> **Why (R26 reasoning):** R24/R25 closed the temporal triage loop for omen's
> *own* formats — `--baseline` (scan-time suppression) and `--diff` (offline
> delta). The one audience that still lacked a native lever was the
> code-scanning audience the R6 SARIF output already targets: uploading SARIF
> surfaces every finding as an alert, and on a legacy codebase that means the
> first upload buries the team in pre-existing alerts with no in-platform way to
> distinguish them from regressions. `--baseline` can drop them, but dropping
> them also hides them from the GitHub UI entirely — you lose the audit trail
> and the "still open, but known" status. `baselineState` is the format's own
> answer: GitHub reads it to keep pre-existing alerts visible-but-folded while
> flagging new ones on the PR. Shipping it makes omen behave like every other
> code-scanning tool in the same pipeline, and it was the cheapest remaining
> R3.x gap to close cleanly — one optional formatter parameter, one CLI flag,
> one config key, all riding rails R3.1 already laid.
