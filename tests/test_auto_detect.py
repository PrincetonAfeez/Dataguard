"""Tests for auto_detect sampling and module scoring."""

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
    spec = importlib.util.spec_from_file_location("auto_detect_under_test", root / "auto_detect.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_ad = _load()


class SampleLinesTests(unittest.TestCase):
    def test_skips_blanks_and_hash_comments(self) -> None:
        text = "\n\n# skip\n\nalpha\nbeta\n"
        s = _ad.sample_lines(text)
        self.assertEqual(s, ["alpha", "beta"])

    def test_falls_back_when_only_comments(self) -> None:
        text = "# only\n# comments\n"
        s = _ad.sample_lines(text)
        self.assertEqual(s, ["# only", "# comments"])


class CsvScoreTests(unittest.TestCase):
    def test_quoted_comma_consistent_columns(self) -> None:
        text = 'name,value\n"Smith, Jr",10\nBob,20\n'
        lines = _ad.sample_lines(text)
        self.assertGreaterEqual(_ad.score_as_csv(lines), 0.5)

    def test_random_angles_not_csv(self) -> None:
        text = "a < b and c > d\nx < y\n"
        lines = _ad.sample_lines(text)
        self.assertLess(_ad.score_as_csv(lines), 0.35)


class LogScoreTests(unittest.TestCase):
    def test_access_log_line_scores(self) -> None:
        line = '203.0.113.1 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.0" 200 1234 "-" "-"'
        self.assertGreaterEqual(_ad.score_as_log([line]), 0.4)

    def test_substring_get_not_http(self) -> None:
        self.assertLess(_ad.score_as_log(["TARGETED path /foo"]), 0.15)


class HtmlScoreTests(unittest.TestCase):
    def test_doctype_scores(self) -> None:
        text = "<!DOCTYPE html><html><body><p>Hi</p></body></html>"
        self.assertGreaterEqual(_ad.score_as_html(_ad.sample_lines(text)), 0.5)

    def test_bare_angles_low(self) -> None:
        text = "if (a < b && c > d) { }\n"
        self.assertLess(_ad.score_as_html(_ad.sample_lines(text)), 0.5)


class ContactsScoreTests(unittest.TestCase):
    def test_email_boosts(self) -> None:
        text = "Contact: alice@example.com\n"
        self.assertGreaterEqual(_ad.score_as_contacts(_ad.sample_lines(text)), 0.4)

    def test_plain_angle_brackets_minimal(self) -> None:
        text = "x < y and z > w\n"
        self.assertLess(_ad.score_as_contacts(_ad.sample_lines(text)), 0.2)


class PasswordScoreTests(unittest.TestCase):
    def test_wordlist_not_over_csv(self) -> None:
        csv_text = "a,b,c\n1,2,3\n4,5,6\n7,8,9\n"
        lines = _ad.sample_lines(csv_text)
        csv_s = _ad.score_as_csv(lines)
        audit = _ad.score_as_passwords(lines, csv_score=csv_s, html_score=0.0)
        self.assertGreater(csv_s, 0.45)
        self.assertLess(audit, 0.35)

    def test_simple_password_file_scores(self) -> None:
        text = "hunter2\nletmein\nPassword1\nsecret\n"
        lines = _ad.sample_lines(text)
        self.assertGreaterEqual(_ad.score_as_passwords(lines, csv_score=0.0, html_score=0.0), 0.45)


class DetectModuleIntegrationTests(unittest.TestCase):
    def test_extension_hint_csv(self) -> None:
        text = "garbage that might confuse"
        r = _ad.detect_module(text, file_path="data.csv")
        self.assertEqual(r["module"], "csv")
        self.assertGreaterEqual(r["scores"]["csv"], 0.9)

    def test_low_confidence_fallback(self) -> None:
        r = _ad.detect_module("   \n  \n")
        self.assertEqual(r["module"], "sanitize")
        self.assertTrue(any("threshold" in n.lower() for n in r["notes"]))

    def test_result_shape(self) -> None:
        r = _ad.detect_module("hello world")
        self.assertEqual(set(r), {"module", "scores", "reason", "notes"})
        self.assertEqual(set(r["scores"]), {"logs", "csv", "html", "contacts", "audit", "sanitize"})
