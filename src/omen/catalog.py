"""Detector catalog introspection for omen (POST_V01 Rotation 2, Rank 1).

`omen --list-checks` answers a question a bounty hunter has to ask before every
scan: *what can omen actually detect, and how does each omen category map onto
the underlying Slither detectors?* Those mappings are deliberately non-obvious
(e.g. `access-control` maps onto `protected-vars` + `events-access`, not a
detector literally named "access-control", because no such Slither ARGUMENT
exists). Until now that knowledge lived only in source-code comments. This
module turns the existing in-code data structures — `CATEGORIES`,
`CATEGORY_TO_SLITHER`, `DEFAULT_SEVERITY`, `VYPER_SUPPORTED_CATEGORIES`, and the
bytecode-heuristic category set — into a single inspectable catalog.

It is pure introspection: it imports no Slither, solc, vyper, or network code,
so `omen --list-checks` is as fast and dependency-free as `omen --help` and
works in any environment (CI, offline, no compiler installed).
"""

from __future__ import annotations

import json
from typing import Any

from . import CATEGORIES, __version__
from .detectors import (
    CATEGORY_TO_SLITHER,
    OPCODE_SIGNATURE,
    VYPER_SUPPORTED_CATEGORIES,
)
from .findings import DEFAULT_SEVERITY, Severity

# Categories that have a bytecode/address-mode detector (precise opcode
# signature OR a coarse Rank-1 heuristic). These are the classes that produce
# findings without verified source — the rest are source-only. Kept here, next
# to the catalog that surfaces it, and asserted against analyzer behavior in the
# tests so it cannot silently drift from `_analyze_bytecode`.
BYTECODE_SUPPORTED_CATEGORIES: frozenset[str] = frozenset(
    set(OPCODE_SIGNATURE.values()) | {"prodigal", "greedy", "reentrancy"}
)


def _modes_for(category: str) -> list[str]:
    """Which input modes can surface this category, in display order."""
    modes = ["sol"]  # every category is reachable through Solidity source mode
    if category in VYPER_SUPPORTED_CATEGORIES:
        modes.append("vyper")
    if category in BYTECODE_SUPPORTED_CATEGORIES:
        modes.extend(["bytecode", "address"])
    return modes


def build_catalog() -> dict[str, Any]:
    """Assemble the full machine-readable detector catalog."""
    checks: list[dict[str, Any]] = []
    for category in CATEGORIES:
        severity = DEFAULT_SEVERITY.get(category, Severity.MEDIUM)
        checks.append(
            {
                "category": category,
                "default_severity": severity.value,
                "slither_detectors": list(CATEGORY_TO_SLITHER.get(category, [])),
                "modes": _modes_for(category),
            }
        )
    return {
        "tool": "omen",
        "version": __version__,
        "check_count": len(checks),
        "checks": checks,
    }


def to_json(catalog: dict[str, Any], *, indent: int = 2) -> str:
    return json.dumps(catalog, indent=indent, sort_keys=False)


def to_text(catalog: dict[str, Any]) -> str:
    """Render the catalog as an aligned plain-text table."""
    rows = catalog["checks"]
    # Column widths account for both the data and the header label so the
    # header and the rows line up under every column.
    cat_w = max([len("CATEGORY")] + [len(r["category"]) for r in rows])
    sev_w = max([len("SEVERITY")] + [len(r["default_severity"]) for r in rows])
    mode_w = max([len("MODES")] + [len(", ".join(r["modes"])) for r in rows])

    header = (
        f"{'CATEGORY'.ljust(cat_w)}  "
        f"{'SEVERITY'.ljust(sev_w)}  "
        f"{'MODES'.ljust(mode_w)}  "
        "SLITHER DETECTORS"
    )
    lines = [
        f"omen {catalog['version']} — {catalog['check_count']} detection classes",
        "",
        header,
        "-" * len(header),
    ]
    for r in rows:
        detectors = ", ".join(r["slither_detectors"]) or "(bytecode/opcode only)"
        lines.append(
            f"{r['category'].ljust(cat_w)}  "
            f"{r['default_severity'].ljust(sev_w)}  "
            f"{', '.join(r['modes']).ljust(mode_w)}  "
            f"{detectors}"
        )
    lines.append("")
    lines.append(
        "Use --check <category> to run one class, or --check all (default). "
        "Pass any of these to --check. SEVERITY is the default; source-mode "
        "findings follow Slither's per-finding impact."
    )
    return "\n".join(lines)


def render(fmt: str) -> str:
    """Build and render the catalog in the requested format ('text'|'json')."""
    catalog = build_catalog()
    if fmt == "json":
        return to_json(catalog)
    if fmt == "text":
        return to_text(catalog)
    raise ValueError(f"unknown catalog format: {fmt}")
