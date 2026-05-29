"""TOML config-file support for omen (POST_V01 Rotation 2, R2.10).

R2.1–R2.9 grew omen's CLI to ~a dozen flags: ``--check``, ``--exclude-check``,
``--min-confidence``, ``--min-severity``, ``--sort``, ``--limit``, ``--fail-on``,
``--format``, ``-o/--output-file``, ``--rpc-url``. A CI invocation that scopes a
scan, filters confidence, sorts, caps, gates, and redirects output is now a long
one-liner that has to be repeated verbatim in every pipeline step and every
teammate's shell history.

``--config PATH`` loads a TOML file whose keys set *default* values for those
flags, so a repo can commit a single ``omen.toml`` and shrink every invocation to
``omen --contract X --input-type sol`` (or even drive everything from the file's
``contract``/``input-type`` keys). The contract is deliberately small and
predictable:

  - **One section.** All keys live under an ``[omen]`` table (or at the top level
    — both are accepted). No nested sub-tables, no per-category overrides, no
    profiles. That is the Simplicity-Gate-respecting floor: a flat name→value map
    that mirrors the existing flags one-for-one.
  - **Keys are flag names** with the leading ``--`` dropped and dashes turned to
    underscores (``min-severity`` *or* ``min_severity`` both work; ``output-file``
    *or* ``output_file``; ``o`` is accepted as the short alias for ``output_file``).
  - **Values are validated against the same choices the CLI enforces**, so a typo
    in the file is caught at load time with a clear, file-named error instead of
    silently feeding a bad value into the analyzer.
  - **CLI flags always win.** Precedence is: explicit CLI flag > config-file value
    > built-in default. The config only fills in slots the user did not set on the
    command line, so it never surprises someone overriding it ad hoc.

Pure stdlib: ``tomllib`` ships with Python 3.11+ and omen requires 3.13+, so this
adds no dependency. The module is import-light (no analysis stack) so ``--help``
and ``--version`` stay fast.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from . import CATEGORIES

# The set of CLI options a config file may set, with the validation each one
# uses. ``contract``, ``batch``, ``input_type`` and ``rpc_url`` are free-form
# strings (paths / URLs / addresses); the rest are constrained choices that
# mirror argparse exactly. ``check``/``exclude_check`` are validated by the
# analyzer's category parser at scan time (a comma-list can name any category),
# so here we only require they be strings — the real check happens on the merged
# value, identically to a value passed on the CLI.
_STR_KEYS = frozenset(
    {
        "contract",
        "batch",
        "input_type",
        "check",
        "exclude_check",
        "rpc_url",
        "ignore",
        # org-specific risk tuning: a CATEGORY=SEVERITY[,...] list, validated on
        # the merged value by findings.parse_severity_overrides at scan time
        # (exactly as a CLI value would be), so here it is only required to be a
        # string — mirroring how check/exclude_check are handled.
        "severity_override",
    }
)

_CHOICE_KEYS: dict[str, tuple[str, ...]] = {
    "input_type": ("sol", "vyper", "bytecode", "address"),
    "format": ("json", "h1md", "sarif", "text"),
    "min_confidence": ("low", "medium", "high"),
    "min_severity": ("informational", "low", "medium", "high", "critical"),
    "sort": ("severity", "none"),
    "fail_on": ("never", "informational", "low", "medium", "high", "critical"),
}

# ``limit`` and ``parallel`` are positive ints; ``output_file`` is a path string.
# Listed here so they are recognised keys; their type is validated below.
# (``parallel`` is the --batch concurrency worker count, POST_V01.)
_INT_KEYS = frozenset({"limit", "parallel"})

# ``timeout`` is a positive, finite number of seconds (the --batch per-contract
# wall-clock budget, POST_V01 R2.14). It is a float key — distinct from the int
# counts above — so a fractional file value like ``timeout = 2.5`` is accepted;
# TOML ints (``timeout = 30``) are also accepted and coerced to float.
_FLOAT_KEYS = frozenset({"timeout"})
_PATH_KEYS = frozenset({"output_file"})

# ``batch_summary`` is a boolean flag (the --batch-summary store_true option,
# POST_V01 R2.12). TOML true/false arrive as Python bool, so the file form is
# ``batch-summary = true``.
_BOOL_KEYS = frozenset({"batch_summary"})

# Every key a config file may legally contain (canonical underscore form).
_KNOWN_KEYS = (
    _STR_KEYS
    | set(_CHOICE_KEYS)
    | _INT_KEYS
    | _FLOAT_KEYS
    | _PATH_KEYS
    | _BOOL_KEYS
)

# Convenience aliases accepted in the file → canonical key. ``o`` mirrors the
# ``-o`` short flag for ``output_file``.
_ALIASES = {"o": "output_file"}


class ConfigError(Exception):
    """A config file could not be read, parsed, or validated.

    Raised with a human-readable, file-named message; the CLI turns it into an
    argparse-style usage error (exit code 2), the same class as a bad flag.
    """


def _normalize_key(key: str) -> str:
    """Map a file key to its canonical underscore flag name.

    Dashes become underscores (so ``min-severity`` and ``min_severity`` are the
    same key) and the short-flag alias ``o`` resolves to ``output_file``.
    """
    canonical = key.strip().replace("-", "_")
    return _ALIASES.get(canonical, canonical)


def load_config(path: str) -> dict[str, Any]:
    """Read *path* as a TOML config file and return a {flag: value} mapping.

    Keys are normalised to the canonical underscore flag names used on
    ``argparse`` (e.g. ``min-severity`` -> ``min_severity``). Both a top-level
    layout and an ``[omen]`` table are accepted; if an ``[omen]`` table exists,
    its keys are used (top-level keys outside it are then ignored, so a file can
    sit alongside other tools' tables in a shared config without bleed-through).

    Every key must be a known flag and every value must satisfy the same
    constraint its CLI flag enforces. Violations raise :class:`ConfigError` with
    a message naming the file and the offending key/value.

    Returns an empty dict for an empty file / empty ``[omen]`` table.
    """
    p = Path(path)
    if not p.exists():
        raise ConfigError(f"--config file not found: {path}")
    try:
        raw = p.read_bytes()
    except OSError as exc:  # pragma: no cover - unusual FS error
        raise ConfigError(f"--config could not read {path}: {exc}") from exc
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"--config invalid TOML in {path}: {exc}") from exc

    # Prefer an explicit [omen] table when present; otherwise treat the whole
    # document as the flag map. This lets omen.toml be a dedicated file *or* a
    # section inside a shared config without colliding with other tables.
    section: Any
    if isinstance(data.get("omen"), dict):
        section = data["omen"]
    else:
        # Drop any nested tables (other tools' sections) from a top-level layout;
        # only scalar/leaf keys are flag values.
        section = {k: v for k, v in data.items() if not isinstance(v, dict)}

    resolved: dict[str, Any] = {}
    for key, value in section.items():
        canonical = _normalize_key(key)
        if canonical not in _KNOWN_KEYS:
            raise ConfigError(
                f"--config {path}: unknown key {key!r}; valid keys are "
                f"{', '.join(sorted(_KNOWN_KEYS))}"
            )
        resolved[canonical] = _validate_value(path, canonical, value)
    return resolved


def _validate_value(path: str, key: str, value: Any) -> Any:
    """Validate and coerce one config value for *key*, mirroring the CLI rules."""
    if key in _BOOL_KEYS:
        # TOML true/false arrive as Python bool. Require a real bool (an int like
        # 1 is rejected) so a typo is caught at load time, mirroring how the CLI
        # flag is a plain store_true.
        if not isinstance(value, bool):
            raise ConfigError(
                f"--config {path}: {key} must be a boolean (true/false), "
                f"got {value!r}"
            )
        return value

    if key in _INT_KEYS:
        # TOML ints arrive as int; reject bools (TOML true/false are bool) and
        # non-ints, and enforce the same positivity the --limit argparse type does.
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigError(
                f"--config {path}: {key} must be a positive integer, got {value!r}"
            )
        if value <= 0:
            raise ConfigError(
                f"--config {path}: {key} must be a positive integer (>= 1), "
                f"got {value}"
            )
        return value

    if key in _FLOAT_KEYS:
        # TOML floats arrive as float and TOML ints as int; accept either (so
        # both ``timeout = 2.5`` and ``timeout = 30`` work) and coerce to float.
        # Reject bools (TOML true/false are bool), non-numbers, and any
        # non-finite/non-positive value, mirroring the --timeout argparse type.
        import math

        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ConfigError(
                f"--config {path}: {key} must be a positive number of seconds, "
                f"got {value!r}"
            )
        fval = float(value)
        if not math.isfinite(fval) or fval <= 0:
            raise ConfigError(
                f"--config {path}: {key} must be a positive number of seconds "
                f"(> 0), got {value}"
            )
        return fval

    if key in _CHOICE_KEYS:
        if not isinstance(value, str):
            raise ConfigError(
                f"--config {path}: {key} must be a string, got {value!r}"
            )
        choices = _CHOICE_KEYS[key]
        if value not in choices:
            raise ConfigError(
                f"--config {path}: {key} must be one of {', '.join(choices)}, "
                f"got {value!r}"
            )
        return value

    # String keys (paths / URLs / addresses / category lists). Category-list
    # values (check / exclude_check) are validated on the merged result by the
    # analyzer's resolve_checks, exactly as a CLI value would be.
    if not isinstance(value, str):
        raise ConfigError(
            f"--config {path}: {key} must be a string, got {value!r}"
        )
    return value
