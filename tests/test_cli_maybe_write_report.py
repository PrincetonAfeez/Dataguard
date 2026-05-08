"""Tests for cli.maybe_write_report."""

from __future__ import annotations

import argparse
import sys
import unittest
from pathlib import Path


def _cli():
    root = Path(__file__).resolve().parents[1]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    import dataguard.cli as cli_mod

    return cli_mod


_cli_mod = _cli()


class MaybeWriteReportTests(unittest.TestCase):
    def test_invalid_report_format_is_input_error(self) -> None:
        args = argparse.Namespace(quiet=False, report=True, report_file=None, show_diff=False)
        with self.assertRaises(_cli_mod.InputError) as ctx:
            _cli_mod.maybe_write_report({"title": "t"}, args, {"report_format": "yaml"})
        self.assertIn("yaml", str(ctx.exception))
