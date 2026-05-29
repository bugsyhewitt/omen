"""Report-to-report diffing for omen (POST_V01 R3.2 ``--diff``).

``omen --diff OLD NEW`` answers the temporal question ``--baseline`` (R3.1)
can only answer at scan time: *what changed between two already-saved omen
reports?* Where ``--baseline`` suppresses known findings during a live scan,
``--diff`` is a pure offline comparison of two saved JSON reports — the
single-contract JSON, a JSON array of reports, or a ``--batch`` JSONL stream
that either flag already produces. It needs no compiler, no Slither, and no
network, so it runs as fast and dependency-free as ``--list-checks``: load both
reports, key every finding by its stable fingerprint
(category + detector + contract + location), and report the set delta.

The delta has three parts:

  - **added** — findings in NEW but not OLD: the regressions / new leads a PR
    introduced. These are what a CI gate cares about, so ``--fail-on`` evaluates
    against *added* findings only.
  - **removed** — findings in OLD but not NEW: issues fixed (or code deleted)
    since the old report.
  - **unchanged** — findings in both: carried over.

Output honours ``--format``: ``text`` (the default for this action — a compact,
glanceable summary) or ``json`` (a machine-readable delta for changelog/triage
automation). The scan-oriented ``h1md``/``sarif`` formats do not apply to a
report delta.
"""

from __future__ import annotations

import json
from typing import Any

from . import __version__
from .findings import diff_findings, load_baseline_findings, severity_rank


def build_diff(old_path: str, new_path: str) -> dict[str, Any]:
    """Load both reports and assemble the machine-readable diff document.

    Raises ``ValueError`` (the CLI turns it into an exit-2 usage error) if either
    path is missing/unreadable/not JSON — consistent with the ``--baseline``
    loader, since a malformed diff input is a user mistake worth surfacing.
    """
    old = load_baseline_findings(old_path)
    new = load_baseline_findings(new_path)
    delta = diff_findings(old, new)
    return {
        "tool": "omen",
        "version": __version__,
        "old": old_path,
        "new": new_path,
        "summary": {
            "added": len(delta["added"]),
            "removed": len(delta["removed"]),
            "unchanged": len(delta["unchanged"]),
        },
        "added": delta["added"],
        "removed": delta["removed"],
        "unchanged": delta["unchanged"],
    }


def diff_gate_triggered(diff: dict[str, Any], fail_on: str | None) -> bool:
    """Whether ``--fail-on`` trips on the diff's *added* findings (the regressions).

    ``--diff`` is the natural CI gate for "fail the PR if it introduces a finding
    at or above severity X". Only *added* findings are eligible — a removed or
    unchanged finding never re-trips a gate the previous run already accounted
    for. ``never`` / ``None`` never trips (the default). Findings are read from
    the saved report dicts, so the severity is whatever was recorded there
    (including any ``--severity-override`` re-stamp applied when the report was
    produced).
    """
    if fail_on is None:
        return False
    normalized = fail_on.strip().lower()
    if not normalized or normalized == "never":
        return False
    threshold = severity_rank(normalized)
    return any(
        severity_rank(str(f.get("severity", ""))) >= threshold
        for f in diff["added"]
    )


def to_json(diff: dict[str, Any], *, indent: int = 2) -> str:
    return json.dumps(diff, indent=indent, sort_keys=False)


def _finding_line(f: dict[str, Any]) -> str:
    """One compact line for a diffed finding: severity, category, where.

    Mirrors the ``--format text`` scan view so a diff reads the same way as a
    scan report. The location is the first source mapping (source mode) or the
    first opcode offset (bytecode mode), falling back to the contract name.
    """
    sev = str(f.get("severity", "")).upper().ljust(13)
    category = str(f.get("category", ""))
    confidence = str(f.get("confidence", ""))
    evidence = f.get("evidence") or {}
    where = ""
    source_mapping = evidence.get("source_mapping") or []
    opcodes = evidence.get("opcodes") or []
    if source_mapping:
        where = f"  {source_mapping[0]}"
    elif opcodes and isinstance(opcodes[0], dict):
        off = opcodes[0].get("offset", 0)
        try:
            where = f"  @0x{int(off):x}"
        except (TypeError, ValueError):
            where = f"  @{off}"
    elif f.get("contract"):
        where = f"  {f['contract']}"
    return f"{sev} {category} [{confidence}]{where}"


def to_text(diff: dict[str, Any]) -> str:
    """Render the diff as a compact human-readable summary.

    A header naming both reports, a one-line counts summary, then an ``added``
    block (prefixed ``+``) and a ``removed`` block (prefixed ``-``). Unchanged
    findings are counted but not listed — the point of a diff is the delta, and
    listing every carried-over finding would bury it. An empty delta prints a
    clear "No changes" line.
    """
    summary = diff["summary"]
    lines = [
        f"omen {diff['version']} — report diff",
        f"old: {diff['old']}",
        f"new: {diff['new']}",
        (
            f"changes: +{summary['added']} added  "
            f"-{summary['removed']} removed  "
            f"={summary['unchanged']} unchanged"
        ),
    ]
    if not diff["added"] and not diff["removed"]:
        lines.append("")
        lines.append("No changes between the two reports.")
        return "\n".join(lines)

    if diff["added"]:
        lines.append("")
        lines.append(f"Added ({summary['added']}):")
        for f in diff["added"]:
            lines.append(f"  + {_finding_line(f)}")
    if diff["removed"]:
        lines.append("")
        lines.append(f"Removed ({summary['removed']}):")
        for f in diff["removed"]:
            lines.append(f"  - {_finding_line(f)}")
    return "\n".join(lines)


def render(diff: dict[str, Any], fmt: str) -> str:
    """Render the diff document in the requested format ('text'|'json')."""
    if fmt == "json":
        return to_json(diff)
    if fmt == "text":
        return to_text(diff)
    raise ValueError(f"unknown diff format: {fmt}")
