"""Tests for password_checker dictionary, entropy labeling, empty batch."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


def _load():
    root = Path(__file__).resolve().parents[1]
    parent = str(root.parent)
    if parent not in sys.path:
        sys.path.insert(0, parent)
    spec = importlib.util.spec_from_file_location(
        "password_checker_under_test",
        root / "modules" / "password_checker.py",
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_pc = _load()


class DictionaryTests(unittest.TestCase):
    def test_exact_common_fails(self) -> None:
        r = _pc.check_dictionary("qwerty")
        self.assertFalse(r["passed"])

    def test_suffix_digits_fails(self) -> None:
        r = _pc.check_dictionary("qwerty123!!")
        self.assertFalse(r["passed"])

    def test_unique_password_passes_dictionary(self) -> None:
        r = _pc.check_dictionary("xK9#mP2$vL8@nQ4&jR6!")
        self.assertTrue(r["passed"])

    def test_letter_skeleton_with_separators_fails(self) -> None:
        r = _pc.check_dictionary("p.a.s.s.w.o.r.d")
        self.assertFalse(r["passed"])
        self.assertIn("skeleton", r["details"].lower())

    def test_one_edit_from_common_fails(self) -> None:
        r = _pc.check_dictionary("welcom")
        self.assertFalse(r["passed"])
        self.assertIn("edit", r["details"].lower())


class EntropyTests(unittest.TestCase):
    def test_entropy_details_mention_naive(self) -> None:
        r = _pc.calculate_entropy("abcDEF12!@")
        self.assertIn("Naive", r["details"])
        self.assertNotIn("NIST", r["details"])


class RunTests(unittest.TestCase):
    def test_empty_input_no_crash(self) -> None:
        out = _pc.run("", {"source_name": "t"})
        self.assertEqual(out["stats"]["weakest_line"], "")
        self.assertEqual(out["stats"]["passwords_analyzed"], 0)

    def test_metadata_warns_plaintext_export(self) -> None:
        out = _pc.run("x", {"source_name": "t"})
        self.assertTrue(out["metadata"]["export_contains_plaintext_passwords"])
        self.assertEqual(out["metadata"]["entropy_metric"], "naive_uniform_random_pool_estimate")
        self.assertTrue(any("plaintext" in w.lower() for w in out["warnings"]))
