"""Multi-run SARIF consolidation for omen (POST_V01 R3.4 ``--sarif-merge``).

``omen --sarif-merge REPORT [REPORT ...]`` consolidates the findings from two
or more previously-saved omen JSON reports into a **single SARIF 2.1.0
document**. It is the spatial complement to ``--diff`` (R3.2, the *temporal*
delta of two reports): where ``--diff`` answers "what changed between these two
runs?", ``--sarif-merge`` answers "give me one code-scanning upload for this
whole set of runs".

The driving workflow is the same whole-program scope the ``--batch`` family
serves, but split across runs that each emitted their own report: a per-module
CI matrix, a sharded ``--parallel`` sweep saved per shard, or a SARIF produced
by ``-o`` on each of several contracts. GitHub Advanced Security accepts one
SARIF document per upload; without a merge step a team must upload N times (N
separate "tools" in the UI) or hand-stitch the JSON. ``--sarif-merge`` produces
the one document, deduplicating findings that appear in more than one input by
the **same stable fingerprint** ``--baseline``/``--diff``/``--sarif-baseline``
use (category + detector + contract + location), so a contract scanned in two
overlapping inputs is not double-counted.

Like ``--diff`` and ``--list-checks`` this is a pure offline operation: it reads
saved reports and writes SARIF, needing no contract, compiler, Slither, or
network, so it runs on a fresh checkout / in CI. Each input may be a
single-contract JSON report, a JSON array of reports, or a ``--batch`` JSONL
stream — whatever ``-o`` produced.
"""

from __future__ import annotations

from typing import Any

from .findings import finding_fingerprint, load_baseline_findings, severity_rank
from .formats import (
    _sarif_level_by_value,
    _sarif_rule,
    _sarif_rule_id,
    _source_mapping_locations,
    sarif_document,
)


def load_merge_findings(paths: list[str]) -> list[dict[str, Any]]:
    """Load and deduplicate the findings of every report in *paths*.

    Each path is read with the same permissive, fingerprint-keyed loader
    ``--diff`` uses (:func:`load_baseline_findings`), so each input may be a
    single-contract report, a JSON array of reports, or a ``--batch`` JSONL
    stream. Findings are merged across all inputs and deduplicated by
    :func:`finding_fingerprint`: a finding present in more than one input
    appears once in the result (the first occurrence, scanning inputs left to
    right, wins — consistent with the within-file first-wins rule).

    The returned list is ordered deterministically, worst-first: by descending
    severity, then by fingerprint, so the consolidated SARIF is byte-stable
    regardless of input order or how each report listed its findings — and the
    highest-impact leads lead the document, matching omen's default
    ``--sort severity`` convention.

    Raises ``ValueError`` (the CLI turns it into an exit-2 usage error) if any
    path is missing/unreadable/not JSON, consistent with ``--diff``/``--baseline``.
    """
    merged: dict[str, dict[str, Any]] = {}
    for path in paths:
        for fp, finding in load_baseline_findings(path).items():
            merged.setdefault(fp, finding)
    return sorted(
        merged.values(),
        key=lambda f: (
            -severity_rank(str(f.get("severity", ""))),
            finding_fingerprint(f),
        ),
    )


def _sarif_result_from_dict(f: dict[str, Any]) -> dict[str, Any]:
    """Build one SARIF result from a saved-report finding dict.

    The dict-form analogue of the per-finding result block in
    :func:`omen.formats.to_sarif`: same ``ruleId``, ``level``, ``message``,
    ``properties`` (category/severity/confidence/detector, plus contract and
    opcode evidence when present), and source ``locations``. Reads severity as a
    string (the saved form) rather than a ``Severity`` enum member.
    """
    category = str(f.get("category", ""))
    severity_value = str(f.get("severity", ""))
    level = _sarif_level_by_value(severity_value)
    description = f.get("description") or f.get("title") or ""
    evidence = f.get("evidence") or {}
    opcodes = evidence.get("opcodes") or []
    source_mapping = [str(loc) for loc in (evidence.get("source_mapping") or [])]

    result: dict[str, Any] = {
        "ruleId": _sarif_rule_id(category),
        "level": level,
        "message": {"text": description},
        "properties": {
            "category": category,
            "severity": severity_value,
            "confidence": str(f.get("confidence", "")),
            "detector": str(f.get("detector", "")),
        },
    }
    contract = f.get("contract")
    if contract:
        result["properties"]["contract"] = contract
    if opcodes:
        result["properties"]["opcodes"] = opcodes
    locations = _source_mapping_locations(source_mapping)
    if locations:
        result["locations"] = locations
    return result


def build_merged_sarif(paths: list[str], *, indent: int = 2) -> str:
    """Load every report in *paths* and render one consolidated SARIF document.

    Deduplicates by fingerprint (see :func:`load_merge_findings`), builds one
    reportingDescriptor (rule) per distinct category and one result per surviving
    finding, and serializes the standard omen SARIF envelope via
    :func:`omen.formats.sarif_document`. The result is identical in shape to a
    single-run ``--format sarif`` document, so it uploads to GitHub code
    scanning exactly like one — only it covers every input run at once.
    """
    findings = load_merge_findings(paths)
    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for f in findings:
        category = str(f.get("category", ""))
        rule_id = _sarif_rule_id(category)
        if rule_id not in rules_by_id:
            severity_value = str(f.get("severity", ""))
            rules_by_id[rule_id] = _sarif_rule(
                category, _sarif_level_by_value(severity_value), severity_value
            )
        results.append(_sarif_result_from_dict(f))
    return sarif_document(list(rules_by_id.values()), results, indent=indent)


def merge_gate_triggered(paths: list[str], fail_on: str | None) -> bool:
    """Whether ``--fail-on`` trips on the merged, deduplicated findings.

    Mirrors the scan / ``--diff`` ``--fail-on`` convention: exit 3 when a
    consolidated finding reaches the chosen severity. ``never`` / ``None`` never
    trips (the default). Severity is read from each saved finding dict, so a
    ``--severity-override`` re-stamp baked into a report carries through. The
    gate evaluates the *deduplicated* finding set, so a finding present in two
    inputs is counted once — it cannot trip the gate twice or hide behind dedup.
    """
    if fail_on is None:
        return False
    normalized = fail_on.strip().lower()
    if not normalized or normalized == "never":
        return False
    threshold = severity_rank(normalized)
    return any(
        severity_rank(str(f.get("severity", ""))) >= threshold
        for f in load_merge_findings(paths)
    )
