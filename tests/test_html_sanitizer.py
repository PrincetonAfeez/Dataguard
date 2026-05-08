"""Tests for html_sanitizer: comments, scripts, URLs, plain/safe modes, strip behavior."""

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
        "html_sanitizer_under_test",
        root / "modules" / "html_sanitizer.py",
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_hs = _load()


class CommentAndScriptTests(unittest.TestCase):
    def test_comment_pattern_removes_real_comments_not_everywhere(self) -> None:
        text = "before<!--hide-->after"
        out, findings, _ = _hs.sanitize_html(text, mode="plain")
        self.assertEqual(out, "beforeafter")
        cats = {f["category"] for f in findings}
        self.assertIn("comment", cats)

    def test_script_removed_and_logged(self) -> None:
        text = '<p>x</p><script>alert(1)</script><p>y</p>'
        out, findings, _ = _hs.sanitize_html(text, mode="plain")
        self.assertNotIn("script", out.lower())
        self.assertNotIn("alert", out)
        self.assertIn("x", out)
        self.assertIn("y", out)
        self.assertTrue(any(f["category"] == "script_tag" for f in findings))

    def test_self_closing_script_removed(self) -> None:
        text = '<script src="//evil.com/x.js" />'
        out, findings, _ = _hs.sanitize_html(text, mode="plain")
        self.assertEqual(out.strip(), "")
        self.assertTrue(any(f["category"] == "script_tag" for f in findings))


class UrlValidationTests(unittest.TestCase):
    def test_javascript_href_rejected_in_safe_mode(self) -> None:
        text = '<a href="javascript:alert(1)">click</a>'
        out, findings, _ = _hs.sanitize_html(text, mode="safe")
        self.assertIn("#removed", out)
        self.assertTrue(any(f["category"] == "dangerous_url" for f in findings))

    def test_protocol_relative_href_allowed_after_normalization(self) -> None:
        text = '<a href="//example.com/path">x</a>'
        out, findings, _ = _hs.sanitize_html(text, mode="safe")
        self.assertIn("example.com", out)
        self.assertNotIn("#removed", out)


class PlainModeStripTests(unittest.TestCase):
    def test_quoted_gt_in_attribute_preserved_in_text(self) -> None:
        text = '<p title="a>b">Hello</p>'
        out, _, _ = _hs.sanitize_html(text, mode="plain")
        self.assertIn("Hello", out)
        self.assertNotIn("<p", out)


class SafeModeTests(unittest.TestCase):
    def test_event_handler_on_allowed_tag_removed_with_finding(self) -> None:
        text = '<a href="https://ok.example" onclick="evil()">ok</a>'
        out, findings, _ = _hs.sanitize_html(text, mode="safe")
        self.assertNotIn("onclick", out.lower())
        self.assertTrue(any("event" in f["category"] for f in findings))

    def test_inline_style_removed_with_finding(self) -> None:
        text = '<p style="color:red">x</p>'
        out, findings, _ = _hs.sanitize_html(text, mode="safe")
        self.assertNotIn("style=", out.lower())
        self.assertTrue(any(f["category"] == "style_strip" for f in findings))


class EntityDecodeTests(unittest.TestCase):
    def test_entity_encoded_script_stripped(self) -> None:
        text = "&lt;script&gt;bad()&lt;/script&gt;&lt;p&gt;ok&lt;/p&gt;"
        out, findings, _ = _hs.sanitize_html(text, mode="plain")
        self.assertNotIn("bad", out)
        self.assertIn("ok", out)
        self.assertTrue(any(f["category"] == "entity_decode" for f in findings))


class ShowDiffTests(unittest.TestCase):
    def test_show_diff_adds_unified_diff(self) -> None:
        out = _hs.run("<p>Hi</p>", {"source_name": "t", "mode": "plain", "show_diff": True})
        self.assertIn("diff", out)
        assert isinstance(out["diff"], dict)
        self.assertIn("unified", out["diff"])
        self.assertTrue(out["diff"]["unified"])
        self.assertTrue(out["metadata"].get("show_diff"))


class ReplacePatternTests(unittest.TestCase):
    def test_event_handler_pass_logs_findings(self) -> None:
        text = '<div onclick="x()">a</div>'
        out, findings, _ = _hs.sanitize_html(text, mode="plain")
        self.assertNotIn("onclick", out.lower())
        self.assertTrue(any(f["category"] == "event_handler_attr" for f in findings))
