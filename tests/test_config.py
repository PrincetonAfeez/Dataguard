"""Tests for config loading, coercion, and persistence."""

import json
from pathlib import Path

import pytest

from dataguard.config import (
    DEFAULT_CONFIG,
    coerce_config_value,
    load_config,
    parse_set_arguments,
    persist_config_updates,
)
from dataguard.errors import InputError


def test_load_config_missing_file(tmp_path: Path) -> None:
    cfg, path, warnings = load_config(cwd=str(tmp_path))
    assert path == tmp_path / ".dataguardrc"
    assert not path.exists()
    assert cfg == DEFAULT_CONFIG
    assert warnings == []


def test_load_config_invalid_json(tmp_path: Path) -> None:
    p = tmp_path / ".dataguardrc"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(InputError, match="Invalid JSON"):
        load_config(cwd=str(tmp_path))


def test_load_config_non_object_root(tmp_path: Path) -> None:
    p = tmp_path / ".dataguardrc"
    p.write_text("[1, 2]", encoding="utf-8")
    with pytest.raises(InputError, match="JSON object"):
        load_config(cwd=str(tmp_path))


def test_load_config_unknown_key_warns(tmp_path: Path) -> None:
    p = tmp_path / ".dataguardrc"
    p.write_text(json.dumps({"verbosity": 2, "bogus_key": 1}), encoding="utf-8")
    cfg, _, warnings = load_config(cwd=str(tmp_path))
    assert cfg["verbosity"] == 2
    assert any("bogus_key" in w for w in warnings)


def test_load_config_invalid_pipe_format(tmp_path: Path) -> None:
    p = tmp_path / ".dataguardrc"
    p.write_text(json.dumps({"pipe_format": "xml"}), encoding="utf-8")
    with pytest.raises(InputError, match="pipe_format"):
        load_config(cwd=str(tmp_path))


def test_load_config_clamps_min_confidence(tmp_path: Path) -> None:
    p = tmp_path / ".dataguardrc"
    p.write_text(json.dumps({"min_confidence_threshold": 99}), encoding="utf-8")
    cfg, _, _ = load_config(cwd=str(tmp_path))
    assert cfg["min_confidence_threshold"] == 1.0


def test_parse_set_unknown_key() -> None:
    with pytest.raises(InputError, match="Unknown config key"):
        parse_set_arguments(["nope=1"])


def test_parse_set_coerces_and_validates() -> None:
    out = parse_set_arguments(["verbosity=3", "strict_mode=true"])
    assert out["verbosity"] == 3
    assert out["strict_mode"] is True
    with pytest.raises(InputError, match="pipe_format"):
        parse_set_arguments(["pipe_format=xml"])


def test_persist_config_updates_round_trip(tmp_path: Path) -> None:
    cfg, warnings = persist_config_updates({"verbosity": 4}, cwd=str(tmp_path))
    assert cfg["verbosity"] == 4
    assert warnings == []
    cfg2, _, w2 = load_config(cwd=str(tmp_path))
    assert cfg2["verbosity"] == 4
    assert w2 == []


def test_coerce_config_value_rejects_bool_for_int_key() -> None:
    with pytest.raises(TypeError, match="boolean"):
        coerce_config_value("verbosity", True)
