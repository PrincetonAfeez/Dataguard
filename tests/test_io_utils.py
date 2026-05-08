"""Tests for dataguard.io_utils."""

from __future__ import annotations

import io
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import dataguard.io_utils as io_utils_mod

from dataguard.io_utils import UTF8_BOM, decode_bytes, read_text_file


def test_decode_bytes_utf8() -> None:
    text, enc, w = decode_bytes("hello".encode())
    assert text == "hello"
    assert enc == "utf-8"
    assert w == []


def test_decode_bytes_strips_bom() -> None:
    text, enc, w = decode_bytes(UTF8_BOM + "x".encode())
    assert text == "x"
    assert enc == "utf-8"
    assert any("BOM" in m for m in w)


def test_decode_bytes_latin1_fallback_warns() -> None:
    raw = bytes([0xE9])
    text, enc, w = decode_bytes(raw)
    assert enc == "latin-1"
    assert text == "\xe9"
    assert any("Latin-1" in m for m in w)


def test_read_text_file_round_trip(tmp_path: Path) -> None:
    p = tmp_path / "f.txt"
    p.write_bytes("café".encode("utf-8"))
    text, meta = read_text_file(str(p))
    assert text == "café"
    assert meta["encoding"] == "utf-8"
    assert meta["read_warnings"] == []


def test_read_input_text_stdin_binary() -> None:
    stdin_obj = SimpleNamespace(
        isatty=lambda: False,
        buffer=io.BytesIO(UTF8_BOM + b"ok"),
    )
    fake_sys = SimpleNamespace(stdin=stdin_obj)
    with patch.object(io_utils_mod, "sys", fake_sys):
        text, meta = io_utils_mod.read_input_text(None, use_stdin=False)
    assert text == "ok"
    assert meta["path"] == "<stdin>"
    assert meta["encoding"] == "utf-8"
    assert any("BOM" in m for m in meta["read_warnings"])
