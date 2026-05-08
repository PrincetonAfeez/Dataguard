"""Tests for string_sanitizer Unicode control and bidi/format stripping."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


def _load_sanitizer():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(
        "string_sanitizer_under_test",
        root / "modules" / "string_sanitizer.py",
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_s = _load_sanitizer()


class UnicodeControlTests(unittest.TestCase):
    def test_preserves_newline_and_tab(self) -> None:
        text = "a\nb\tc"
        cleaned, findings, _stats = _s.sanitize(text, strip_bidi_format_marks=True)
        self.assertEqual(cleaned, text)
        self.assertEqual(findings, [])

    def test_strips_unicode_cc_nel(self) -> None:
        text = "a\u0085b"
        cleaned, findings, _stats = _s.sanitize(text, strip_bidi_format_marks=True)
        self.assertEqual(cleaned, "ab")
        self.assertTrue(any(f["category"] == "control_characters" for f in findings))

    def test_strips_ascii_control_except_nt(self) -> None:
        text = "a\x00b"
        cleaned, _, _ = _s.sanitize(text, strip_bidi_format_marks=True)
        self.assertEqual(cleaned, "ab")


class BidiFormatTests(unittest.TestCase):
    def test_strips_lrm_by_default(self) -> None:
        text = "a\u200eb"
        cleaned, findings, _stats = _s.sanitize(text, strip_bidi_format_marks=True)
        self.assertEqual(cleaned, "ab")
        self.assertTrue(any(f["category"] == "bidi_format_marks" for f in findings))

    def test_preserves_lrm_when_disabled(self) -> None:
        text = "a\u200eb"
        cleaned, findings, _stats = _s.sanitize(text, strip_bidi_format_marks=False)
        self.assertEqual(cleaned, text)
        self.assertFalse(any(f["category"] == "bidi_format_marks" for f in findings))

    def test_strips_isolate_u2066(self) -> None:
        text = "x\u2066y\u2069z"
        cleaned, _, _ = _s.sanitize(text, strip_bidi_format_marks=True)
        self.assertEqual(cleaned, "xyz")

    def test_run_metadata_reflects_bidi_flag(self) -> None:
        r_on = _s.run("a\u200eb", {"source_name": "t", "strip_bidi_format_marks": True})
        r_off = _s.run("a\u200eb", {"source_name": "t", "strip_bidi_format_marks": False})
        self.assertTrue(r_on["metadata"]["strip_bidi_format_marks"])
        self.assertFalse(r_off["metadata"]["strip_bidi_format_marks"])


class StatsTests(unittest.TestCase):
    def test_net_code_unit_delta_matches_length(self) -> None:
        text = "a\u200bb"
        _c, _f, stats = _s.sanitize(text, strip_bidi_format_marks=True)
        self.assertEqual(stats["net_code_unit_delta"], len(text) - len("ab"))
        self.assertEqual(stats["characters_removed_or_replaced"], stats["net_code_unit_delta"])
