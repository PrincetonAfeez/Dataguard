"""Tests for log_parser: detection sample, timestamps, IP validation, coercion, deduped threats."""

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
        "log_parser_under_test",
        root / "modules" / "log_parser.py",
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_lp = _load()


class TimestampTests(unittest.TestCase):
    def test_apache_timestamp_no_tz(self) -> None:
        dt = _lp.parse_timestamp("02/Jan/2024:15:04:05")
        self.assertIsNotNone(dt)
        assert dt is not None
        self.assertEqual(dt.year, 2024)
        self.assertEqual(dt.month, 1)
        self.assertEqual(dt.day, 2)

    def test_iso_fractional_z(self) -> None:
        dt = _lp.parse_timestamp("2024-01-02T15:04:05.123Z")
        self.assertIsNotNone(dt)

    def test_iso_space_fractional(self) -> None:
        dt = _lp.parse_timestamp("2024-01-02 15:04:05.123456")
        self.assertIsNotNone(dt)


class IpTests(unittest.TestCase):
    def test_ipv6_brackets_normalized(self) -> None:
        self.assertEqual(_lp.normalize_log_client_ip("[2001:db8::1]"), "2001:db8::1")

    def test_ipv6_valid(self) -> None:
        self.assertTrue(_lp.valid_client_ip("[::1]"))
        self.assertTrue(_lp.valid_client_ip("192.168.0.1"))

    def test_invalid_client(self) -> None:
        self.assertFalse(_lp.valid_client_ip("not-an-ip"))
        self.assertFalse(_lp.valid_client_ip(""))


class CoercionTests(unittest.TestCase):
    def test_coerce_rejects_bad_size(self) -> None:
        entry = {
            "ip": "1.1.1.1",
            "timestamp": "",
            "method": "GET",
            "url": "/",
            "status": "200",
            "size": "huge",
            "referer": "-",
            "agent": "-",
        }
        self.assertIsNone(_lp.coerce_parsed_fields(entry))

    def test_coerce_accepts_dash_size(self) -> None:
        entry = {
            "ip": "1.1.1.1",
            "timestamp": "",
            "method": "GET",
            "url": "/",
            "status": "200",
            "size": "-",
            "referer": "-",
            "agent": "-",
        }
        c = _lp.coerce_parsed_fields(entry)
        self.assertIsNotNone(c)
        assert c is not None
        self.assertEqual(c["response_size"], 0)
        self.assertEqual(c["status"], 200)


class DetectionTests(unittest.TestCase):
    def test_skips_comments_and_blanks_for_detect(self) -> None:
        lines = [
            "",
            "# comment",
            "   ",
        ]
        lines.append(
            '192.168.1.1 - - [02/Jan/2024:15:04:05 +0000] "GET / HTTP/1.1" 200 1234 "-" "curl"'
        )
        fmt = _lp.detect_format(lines)
        self.assertEqual(fmt, "apache")

    def test_sample_lines_for_detection_respects_cap(self) -> None:
        lines = ["# skip"] * 50
        lines.extend(
            [
                '10.0.0.1 - - [02/Jan/2024:15:04:05 +0000] "GET / HTTP/1.1" 200 0 "-" "-"',
            ]
            * 120
        )
        sample = _lp.sample_lines_for_detection(lines)
        self.assertEqual(len(sample), 100)


class RunIntegrationTests(unittest.TestCase):
    def test_apache_line_parses(self) -> None:
        line = (
            '203.0.113.7 - - [02/Jan/2024:15:04:05 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"'
        )
        out = _lp.run(line, {"format": "apache", "source_name": "t"})
        self.assertEqual(out["stats"]["parsed_lines"], 1)
        self.assertEqual(out["entries"][0]["ip"], "203.0.113.7")
        self.assertEqual(out["entries"][0]["status"], 200)

    def test_rapid_fire_deduped(self) -> None:
        base = '1.1.1.1 - - [02/Jan/2024:15:04:{sec:02d} +0000] "GET / HTTP/1.1" 200 0 "-" "-"'
        lines = "\n".join(base.format(sec=i % 60) for i in range(55))
        out = _lp.run(lines, {"format": "apache", "source_name": "t"})
        rapid = [f for f in out["findings"] if f["category"] == "rapid_fire"]
        self.assertEqual(len(rapid), 1)

    def test_path_traversal_deduped_per_url(self) -> None:
        line = (
            '1.1.1.1 - - [02/Jan/2024:15:04:05 +0000] "GET /../../../etc/passwd HTTP/1.1" 404 0 "-" "-"'
        )
        out = _lp.run((line + "\n") * 5, {"format": "apache", "source_name": "t"})
        pt = [f for f in out["findings"] if f["category"] == "path_traversal"]
        self.assertEqual(len(pt), 1)
