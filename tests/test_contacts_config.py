"""Contacts min-confidence resolution (config vs CLI)."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


def _load_config_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("dataguard_config_under_test", root / "config.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class ResolveContactsMinConfidenceTests(unittest.TestCase):
    def test_uses_runtime_threshold_when_cli_omitted(self) -> None:
        cfg = _load_config_module()
        v = cfg.resolve_contacts_min_confidence(None, {"min_confidence_threshold": 0.55})
        self.assertEqual(v, 0.55)

    def test_explicit_zero_overrides_config(self) -> None:
        cfg = _load_config_module()
        v = cfg.resolve_contacts_min_confidence(0.0, {"min_confidence_threshold": 0.9})
        self.assertEqual(v, 0.0)

    def test_falls_back_to_default_config_constant(self) -> None:
        cfg = _load_config_module()
        v = cfg.resolve_contacts_min_confidence(None, {})
        self.assertEqual(v, cfg.DEFAULT_CONFIG["min_confidence_threshold"])
