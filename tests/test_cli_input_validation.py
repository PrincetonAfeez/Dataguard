"""Tests for cli.validate_input_sources."""

from __future__ import annotations

import argparse
import sys
import unittest
from pathlib import Path


def _cli():
    root = Path(__file__).resolve().parents[1]
    parent = str(root.parent)
    if parent not in sys.path:
        sys.path.insert(0, parent)
    import dataguard.cli as cli

    return cli


_cli_mod = _cli()


class ValidateInputSourcesTests(unittest.TestCase):
    def test_contacts_file_and_stdin_conflict(self) -> None:
        args = argparse.Namespace(file="a.txt", stdin=True)
        with self.assertRaises(_cli_mod.InputError):
            _cli_mod.validate_input_sources(args, "contacts")

    def test_sanitize_input_and_file_conflict(self) -> None:
        args = argparse.Namespace(input="x", file="a.txt", stdin=False)
        with self.assertRaises(_cli_mod.InputError):
            _cli_mod.validate_input_sources(args, "sanitize")

    def test_audit_password_and_file_conflict(self) -> None:
        args = argparse.Namespace(password="secret", file="p.txt", stdin=False)
        with self.assertRaises(_cli_mod.InputError):
            _cli_mod.validate_input_sources(args, "audit")

    def test_single_source_ok(self) -> None:
        args = argparse.Namespace(file="a.txt", stdin=False)
        _cli_mod.validate_input_sources(args, "csv")
