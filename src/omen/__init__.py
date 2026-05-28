"""omen — a bounty-oriented hybrid scanner for Ethereum trace vulnerabilities.

omen specializes in the MAIAN class of trace vulnerabilities (prodigal,
suicidal, greedy) plus reentrancy, combining Slither's static/symbolic
analysis primitives with bytecode-level opcode evidence. As of R2 it also
covers access-control and tx-origin misuse — the #1 loss category by volume
(OWASP Smart Contract Top 10 2025/2026) and a persistent medium finding.

Prior art:
  - MAIAN (Nikolic et al., USENIX 2018) — the original prodigal/suicidal/greedy taxonomy.
  - Slither (Crytic / Trail of Bits) — the static analysis engine omen builds on.
"""

__version__ = "0.1.0"

CATEGORIES = (
    "prodigal",
    "suicidal",
    "greedy",
    "reentrancy",
    "access-control",
    "tx-origin",
    "delegatecall",
    "upgrade",
)
