"""Tests for primary stdout serialization."""

from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path


def _load_formatter_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("dataguard_formatter_under_test", root / "formatter.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_f = _load_formatter_module()
serialize_primary_output = _f.serialize_primary_output
format_table = _f.format_table
render_report = _f.render_report


class SerializePrimaryOutputTests(unittest.TestCase):
    def test_text_dict_is_indented_json(self) -> None:
        out = serialize_primary_output({"a": 1}, "text")
        self.assertIn("\n", out)
        self.assertEqual(json.loads(out), {"a": 1})

    def test_raw_dict_is_compact_json(self) -> None:
        out = serialize_primary_output({"a": 1, "b": [2, 3]}, "raw")
        self.assertNotIn("\n", out)
        self.assertEqual(json.loads(out), {"a": 1, "b": [2, 3]})

    def test_raw_string_is_plain_str(self) -> None:
        self.assertEqual(serialize_primary_output("hello", "raw"), "hello")

    def test_json_encodes_string_as_json(self) -> None:
        self.assertEqual(serialize_primary_output("hello", "json"), '"hello"')

    def test_text_dict_nonserializable_falls_back_to_str(self) -> None:
        out = serialize_primary_output({"x": object()}, "text")
        self.assertIn("x", out)

    def test_pipe_format_case_insensitive(self) -> None:
        self.assertEqual(serialize_primary_output("hello", "JSON"), '"hello"')


class FormatTableTests(unittest.TestCase):
    def test_row_wider_than_headers_no_crash(self) -> None:
        table = format_table(["A", "B"], [["1", "2", "extra-wide-third"]])
        self.assertIn("extra-wide-third", table)
        self.assertIn("A", table)

    def test_empty_table(self) -> None:
        self.assertEqual(format_table([], []), "")


class RenderReportTests(unittest.TestCase):
    def test_unknown_format_raises(self) -> None:
        with self.assertRaises(ValueError):
            render_report({"title": "t"}, report_format="yaml")

    def test_json_report_nonserializable_safe_fallback(self) -> None:
        payload = {"title": "T", "bad": object()}
        out = render_report(payload, report_format="json")
        data = json.loads(out)
        self.assertIn("error", data)
        self.assertEqual(data.get("title"), "T")
