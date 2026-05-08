"""Config loading and persistence helpers."""

from __future__ import annotations

import json
from pathlib import Path

from dataguard.errors import InputError


CONFIG_FILE_NAME = ".dataguardrc"

DEFAULT_CONFIG = {
    "default_output_format": "text",     # Default style for console output
    "color_enabled": True,                # Toggle for ANSI color highlighting
    "verbosity": 0,                       # Default level of log detail (0 is standard)
    "strict_mode": False,                 # If true, warnings are treated as exit-code errors
    "min_confidence_threshold": 0.3,      # Sensitivity floor for PII detection (contacts)
    "password_min_length": 8,             # Default requirement for password auditing
    "log_top_n": 10,                      # Default number of entries in log summaries
    "pipe_format": "text",                # Default structure for piped stdout data
    "report_format": "text",              # Default file format for generated reports
}

_KNOWN_KEYS = frozenset(DEFAULT_CONFIG)

# Get the path to the config file
def get_config_path(cwd: str | None = None) -> Path:
    base_path = Path(cwd or Path.cwd())
    return base_path / CONFIG_FILE_NAME

# Constrain certain config values to valid ranges or sets of options.
def _constrain_config_value(key: str, value: object) -> object:
    if key == "min_confidence_threshold":
        v = float(value)
        return max(0.0, min(1.0, v))
    if key == "verbosity":
        return max(0, min(10, int(value)))
    if key == "password_min_length":
        return max(1, min(256, int(value)))
    if key == "log_top_n":
        return max(1, min(10_000, int(value)))
    if key == "pipe_format":
        v = str(value).lower()
        allowed = ("text", "json", "raw")
        if v not in allowed:
            raise ValueError(f"must be one of {list(allowed)}, got {value!r}")
        return v
    if key == "report_format":
        v = str(value).lower()
        allowed = ("text", "json", "csv")
        if v not in allowed:
            raise ValueError(f"must be one of {list(allowed)}, got {value!r}")
        return v
    if key == "default_output_format":
        s = str(value).strip()
        if not s:
            raise ValueError("cannot be empty")
        return s
    return value

# Coerce a single config value to the appropriate type and constraints for its key.
def coerce_config_value(key: str, value: object) -> object:
    """Coerce a single value to the type and constraints for ``key`` (must be a known key)."""
    default = DEFAULT_CONFIG[key]

    if type(default) is bool:
        if type(value) is bool:
            coerced = value
        elif isinstance(value, str):
            low = value.strip().lower()
            if low in ("true", "1", "yes", "on"):
                coerced = True
            elif low in ("false", "0", "no", "off"):
                coerced = False
            else:
                raise ValueError(f"expected a boolean, got {value!r}")
        elif type(value) is int:
            coerced = value != 0
        else:
            raise TypeError(f"expected boolean-like value, got {type(value).__name__}")

    elif type(default) is int:
        if type(value) is bool:
            raise TypeError("expected integer, not boolean")
        if isinstance(value, float) and not value.is_integer():
            raise TypeError("expected a whole number")
        coerced = int(value)

    elif type(default) is float:
        if type(value) is bool:
            raise TypeError("expected number, not boolean")
        coerced = float(value)

    elif isinstance(default, str):
        coerced = str(value).strip()

    else:
        coerced = value

    return _constrain_config_value(key, coerced)

# Merge a loaded config dict with the default config, coercing values and collecting warnings for unknown keys.
def _merge_loaded_dict(base: dict, loaded: dict) -> tuple[dict, list[str]]:
    warnings: list[str] = []
    out = dict(base)
    for key, raw in loaded.items():
        if key not in _KNOWN_KEYS:
            warnings.append(f"Ignored unknown config key {key!r}.")
            continue
        try:
            out[key] = coerce_config_value(key, raw)
        except (TypeError, ValueError) as exc:
            raise InputError(f"Invalid value for config key {key!r}: {exc}") from exc
    return out, warnings

# Load the config from file, merging with defaults and coercing values. Returns the merged config, the path it was loaded from, and any warnings about unknown keys.
def load_config(cwd: str | None = None) -> tuple[dict, Path, list[str]]:
    config = dict(DEFAULT_CONFIG)
    config_path = get_config_path(cwd)
    if not config_path.exists():
        return config, config_path, []

    try:
        text = config_path.read_text(encoding="utf-8")
        loaded = json.loads(text)
    except json.JSONDecodeError as exc:
        raise InputError(f"Invalid JSON in config file {config_path}: {exc}") from exc

    if not isinstance(loaded, dict):
        raise InputError(
            f"Config file must contain a JSON object, not {type(loaded).__name__}."
        )

    merged, warnings = _merge_loaded_dict(config, loaded)
    return merged, config_path, warnings

# Parse a list of key=value strings (e.g. from CLI arguments) into a dict of coerced config updates, validating keys and value types.
def parse_set_arguments(assignments: list[str]) -> dict:
    updates: dict[str, object] = {}
    for assignment in assignments:
        if "=" not in assignment:
            raise ValueError(f"Expected key=value assignment, got: {assignment}")
        key, raw_value = assignment.split("=", 1)
        key = key.strip()
        raw_value = raw_value.strip()
        if key not in _KNOWN_KEYS:
            valid = ", ".join(sorted(_KNOWN_KEYS))
            raise InputError(f"Unknown config key {key!r}. Valid keys: {valid}.")

        if raw_value.lower() in {"true", "false"}:
            value: object = raw_value.lower() == "true"
        else:
            try:
                value = int(raw_value)
            except ValueError:
                try:
                    value = float(raw_value)
                except ValueError:
                    value = raw_value

        try:
            updates[key] = coerce_config_value(key, value)
        except (TypeError, ValueError) as exc:
            raise InputError(f"Invalid value for config key {key!r}: {exc}") from exc

    return updates

# Determine the effective minimum confidence for contact extraction, using the CLI value if provided, otherwise falling back to the runtime config or default.
def resolve_contacts_min_confidence(cli_value: float | None, runtime_config: dict | None = None) -> float:
    """Effective minimum confidence for contact extraction.

    When the CLI omits ``--min-confidence``, use ``min_confidence_threshold`` from the merged runtime config
    (``load_config`` + CLI overrides), defaulting to ``DEFAULT_CONFIG``.
    """
    if cli_value is not None:
        return float(cli_value)
    cfg = runtime_config if runtime_config is not None else DEFAULT_CONFIG
    return float(cfg.get("min_confidence_threshold", DEFAULT_CONFIG["min_confidence_threshold"]))

# Apply a set of config updates (e.g. from CLI arguments) to the loaded config, coercing values and validating keys, then persist the updated config back to file. Returns the updated config and any warnings from loading.
def persist_config_updates(updates: dict, cwd: str | None = None) -> tuple[dict, list[str]]:
    coerced: dict[str, object] = {}
    for key, raw in updates.items():
        if key not in _KNOWN_KEYS:
            valid = ", ".join(sorted(_KNOWN_KEYS))
            raise InputError(f"Unknown config key {key!r}. Valid keys: {valid}.")
        try:
            coerced[key] = coerce_config_value(key, raw)
        except (TypeError, ValueError) as exc:
            raise InputError(f"Invalid value for config key {key!r}: {exc}") from exc

    config, config_path, load_warnings = load_config(cwd)
    config.update(coerced)

    with config_path.open("w", encoding="utf-8") as handle:
        json.dump(config, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return config, load_warnings
