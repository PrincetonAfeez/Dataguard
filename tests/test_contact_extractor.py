"""Tests for contact_extractor pairing, email length, phones."""

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
        "contact_extractor_under_test",
        root / "modules" / "contact_extractor.py",
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_ce = _load()


class PairingTests(unittest.TestCase):
    def test_unequal_counts_no_false_pairing(self) -> None:
        emails = [{"email": "a@b.co", "confidence_score": 0.9}, {"email": "c@d.co", "confidence_score": 0.9}]
        phones = [{"phone": "+1 (212) 555-1212", "confidence_score": 0.85}]
        rows = _ce.pair_contact_rows(emails, phones, 1, "unknown")
        self.assertEqual(len(rows), 3)
        emails_only = [r for r in rows if r["email"] and not r["phone"]]
        phones_only = [r for r in rows if r["phone"] and not r["email"]]
        self.assertEqual(len(emails_only), 2)
        self.assertEqual(len(phones_only), 1)

    def test_equal_counts_zipped(self) -> None:
        emails = [{"email": "a@b.co", "confidence_score": 0.9}]
        phones = [{"phone": "(212) 555-1212", "confidence_score": 0.85}]
        rows = _ce.pair_contact_rows(emails, phones, 1, "unknown")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["email"], "a@b.co")
        self.assertIn("555", rows[0]["phone"])


class EmailValidationTests(unittest.TestCase):
    def test_local_part_too_long(self) -> None:
        local = "a" * 65
        ok, reason = _ce.validate_email(f"{local}@x.co")
        self.assertFalse(ok)
        self.assertIn("64", reason)

    def test_idn_domain_label(self) -> None:
        ok, _ = _ce.validate_email("user@münchen.de")
        self.assertTrue(ok)


class PhoneTests(unittest.TestCase):
    def test_nanp_invalid_exchange(self) -> None:
        ok, _, reason = _ce.normalize_us_phone("212-012-3456")
        self.assertFalse(ok)
        self.assertIn("NANP", reason or "invalid")

    def test_international_plus_44(self) -> None:
        ok, norm, _ = _ce.normalize_international_phone("+44 20 7946 0958")
        self.assertTrue(ok)
        self.assertTrue(norm.startswith("+"))
        self.assertGreater(len(_ce._phone_dedupe_key(norm)), 8)

    def test_raw_ten_digit_not_inside_longer_id(self) -> None:
        line = "id 123456789012345 and 2125551212 end"
        cands = _ce.collect_phone_candidates(line)
        self.assertTrue(any("2125551212" in c.replace(" ", "") for c in cands))


class RunIntegrationTests(unittest.TestCase):
    def test_stats_average_confidence_is_float(self) -> None:
        text = "Jane Doe\nreach jane@example.com or (415) 555-0199\n"
        r = _ce.run(text, {"source_name": "t", "min_confidence": 0.0})
        self.assertIsInstance(r["stats"]["average_confidence"], float)
        self.assertIn("average_confidence_display", r["stats"])
