"""Tests for csv_converter: delimiters, quotes, ragged rows, strict mode, headers, line indexing."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


def _load():
    root = Path(__file__).resolve().parents[1]
    parent = str(root.parent)
    if parent not in sys.path:
        sys.path.insert(0, parent)
    spec = importlib.util.spec_from_file_location(
        "csv_converter_under_test",
        root / "modules" / "csv_converter.py",
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_cc = _load()


class DelimiterTests(unittest.TestCase):
    def test_auto_detects_semicolon(self) -> None:
        text = "a;b;c\n1;2;3\n4;5;6\n"
        out = _cc.run(text, {"source_name": "t", "delimiter": "auto"})
        self.assertIn(";", out["stats"]["delimiter"])
        self.assertEqual(len(out["rows"]), 2)

    def test_explicit_tab(self) -> None:
        text = "a\tb\tc\n1\t2\t3\n"
        out = _cc.run(text, {"source_name": "t", "delimiter": "tab"})
        self.assertEqual(out["rows"][0]["a"], 1)
        self.assertEqual(out["rows"][0]["b"], 2)


class QuoteTests(unittest.TestCase):
    def test_quoted_comma_does_not_trigger_mixed_delimiter(self) -> None:
        text = 'name,value\n"Smith, Jr",10\n'
        out = _cc.run(text, {"source_name": "t", "delimiter": ","})
        mixed = [f for f in out["findings"] if f.get("category") == "mixed_delimiter"]
        self.assertEqual(len(mixed), 0)
        self.assertEqual(out["rows"][0]["value"], 10)


class RaggedRowTests(unittest.TestCase):
    def test_short_row_padded_with_line_on_finding(self) -> None:
        text = "a,b,c\n1,2,3\n9,8\n"
        out = _cc.run(text, {"source_name": "t", "delimiter": ","})
        pad = [f for f in out["findings"] if f.get("category") == "row_padding"]
        self.assertTrue(pad)
        self.assertEqual(pad[0]["line"], 3)
        self.assertIsNone(out["rows"][1]["c"])


class StrictModeTests(unittest.TestCase):
    def test_strict_rejects_long_row(self) -> None:
        text = "a,b,c\n1,2,3\n1,2,3,4\n"
        out = _cc.run(text, {"source_name": "t", "delimiter": ",", "strict": True})
        self.assertEqual(out["stats"]["rows_rejected"], 1)
        self.assertEqual(len(out["rows"]), 1)
        strict_f = [f for f in out["findings"] if f.get("category") == "strict_rejection"]
        self.assertTrue(strict_f)
        self.assertEqual(strict_f[0]["line"], 3)

    def test_strict_rejects_short_row(self) -> None:
        text = "a,b,c\n1,2\n"
        out = _cc.run(text, {"source_name": "t", "delimiter": ",", "strict": True})
        self.assertEqual(out["stats"]["rows_rejected"], 1)


class HeaderGuessTests(unittest.TestCase):
    def test_text_header_row(self) -> None:
        text = "name,age\nAlice,30\n"
        out = _cc.run(text, {"source_name": "t", "delimiter": ","})
        self.assertEqual(out["metadata"]["header_status"], "provided")
        self.assertIn("name", out["rows"][0])

    def test_numeric_first_row_not_header(self) -> None:
        text = "1,2,3\n4,5,6\n"
        out = _cc.run(text, {"source_name": "t", "delimiter": ","})
        self.assertEqual(out["metadata"]["header_status"], "generated")
        self.assertIn("column_1", out["rows"][0])


class TypeMismatchLineTests(unittest.TestCase):
    def test_type_mismatch_uses_source_line_number(self) -> None:
        """Force inferred type so convert raises; finding line must be the row's start line."""
        text = "a\n1\nx\n"
        with mock.patch.object(_cc, "detect_type", return_value="integer"):
            out = _cc.run(text, {"source_name": "t", "delimiter": ","})
        mism = [f for f in out["findings"] if f.get("category") == "type_mismatch"]
        self.assertTrue(mism)
        self.assertEqual(mism[0]["line"], 3)


class MultilineFieldTests(unittest.TestCase):
    def test_multiline_quoted_field_parses_one_row(self) -> None:
        text = 'a,b\n1,"hello\nworld"\n3,c\n'
        out = _cc.run(text, {"source_name": "t", "delimiter": ","})
        self.assertEqual(len(out["rows"]), 2)
        self.assertEqual(out["rows"][0]["a"], 1)
        self.assertIn("hello", out["rows"][0]["b"] or "")
        self.assertEqual(out["rows"][1]["a"], 3)

    def test_type_mismatch_on_multiline_row_uses_start_line(self) -> None:
        text = 'a\n1\n"bad\nline"\n'
        with mock.patch.object(_cc, "detect_type", return_value="integer"):
            out = _cc.run(text, {"source_name": "t", "delimiter": ","})
        mism = [f for f in out["findings"] if f.get("category") == "type_mismatch"]
        self.assertTrue(mism)
        self.assertEqual(mism[0]["line"], 3)


class ParseSpansTests(unittest.TestCase):
    def test_parse_csv_rows_with_spans_matches_parse_csv_rows(self) -> None:
        text = "x,y\n1,2\n"
        d = ","
        full, spans = _cc.parse_csv_rows_with_spans(text, d)
        simple = _cc.parse_csv_rows(text, d)
        self.assertEqual(full, simple)
        self.assertEqual(len(spans), len(full))
        self.assertEqual(spans[0], (1, 1))
        self.assertEqual(spans[1], (2, 2))


class WrongDelimiterHeuristicTests(unittest.TestCase):
    def test_mixed_delimiter_when_forced_wrong_primary(self) -> None:
        """Header parsed with comma (3 cols); data row is semicolon-separated; alt delimiter fits width."""
        text = "a,b,c\n1;2;3\n"
        out = _cc.run(text, {"source_name": "t", "delimiter": ","})
        mixed = [f for f in out["findings"] if f.get("category") == "mixed_delimiter"]
        self.assertTrue(mixed)
        self.assertEqual(mixed[0]["line"], 2)
