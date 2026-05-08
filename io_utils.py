"""Shared file and stdin helpers.

Files and stdin are read as **bytes**, then decoded with the same :func:`decode_bytes` pipeline so
``encoding`` and ``read_warnings`` in metadata match actual behavior (not the interpreter's text-mode stdin).
"""

from __future__ import annotations

import sys
from typing import TypedDict

from dataguard.errors import InputError

# UTF-8 BOM marker, which is not part of the UTF-8 encoding but is sometimes included at the start of files to indicate they are UTF-8. We want to strip it if present before decoding.
UTF8_BOM = b"\xef\xbb\xbf"
# If UTF-8 decoding fails, we decode as Latin-1 (ISO-8859-1) which never fails for byte strings, but we want to warn the user that this fallback happened in case it was not intentional and they have mis-encoded UTF-8 data.
_LATIN1_FALLBACK_WARNING = (
    "UTF-8 decode failed; interpreted bytes as Latin-1 (ISO-8859-1); "
    "if this is wrong, convert the input to UTF-8."
)

# Metadata returned with text read from a file or stdin.
class InputReadMetadata(TypedDict):
    """Metadata returned with text read from a file or stdin."""

    path: str
    encoding: str
    read_warnings: list[str]

# The main decoding function that all input reading functions use, so they all have consistent behavior and metadata.
def decode_bytes(raw_bytes: bytes) -> tuple[str, str, list[str]]:
    """Decode ``raw_bytes`` to text; strip UTF-8 BOM when present.

    Tries strict UTF-8 first. If that fails, decodes as Latin-1 (never fails for byte strings) and
    appends a warning so mis-encoded UTF-8 is not silent mojibake without notice.
    """
    warnings: list[str] = []
    payload = raw_bytes
    if payload.startswith(UTF8_BOM):
        payload = payload[len(UTF8_BOM) :]
        warnings.append("Stripped UTF-8 BOM marker before decoding input.")

    try:
        return payload.decode("utf-8"), "utf-8", warnings
    except UnicodeDecodeError:
        text = payload.decode("latin-1")
        return text, "latin-1", warnings + [_LATIN1_FALLBACK_WARNING]

# Read a text file as bytes, decode it, and return the text and metadata about the read operation.
def read_text_file(path: str) -> tuple[str, InputReadMetadata]:
    try:
        with open(path, "rb") as handle:
            raw_bytes = handle.read()
    except OSError as exc:
        raise InputError(f"Could not read file: {path}") from exc

    text, encoding, warnings = decode_bytes(raw_bytes)
    metadata: InputReadMetadata = {"path": path, "encoding": encoding, "read_warnings": warnings}
    return text, metadata

# Check if stdin has data to read (not a TTY). This is used to determine if we should read from stdin when the user does not explicitly specify it, allowing for flexible usage where the user can pipe data in or specify a file.
def stdin_has_data() -> bool:
    return not sys.stdin.isatty()

# Read from stdin as bytes, decode it, and return the text and metadata about the read operation. This is used when the user wants to read from stdin, either explicitly or implicitly by having data piped in.
def _read_stdin_decoded() -> tuple[str, str, list[str]]:
    try:
        buf = sys.stdin.buffer
    except AttributeError as exc:
        raise InputError(
            "Standard input does not expose a binary buffer in this environment."
        ) from exc
    try:
        raw = buf.read()
    except OSError as exc:
        raise InputError("Could not read standard input.") from exc
    return decode_bytes(raw)

# The main function to read input text, which can come from a file or stdin. It checks the parameters to determine where to read from, and returns the text along with metadata about the read operation. If no input is provided, it raises an error.
def read_input_text(file_path: str | None = None, use_stdin: bool = False) -> tuple[str, InputReadMetadata]:
    if file_path:
        return read_text_file(file_path)
    if use_stdin or stdin_has_data():
        text, encoding, warnings = _read_stdin_decoded()
        metadata: InputReadMetadata = {
            "path": "<stdin>",
            "encoding": encoding,
            "read_warnings": warnings,
        }
        return text, metadata
    raise InputError("No input provided. Use --file, --input, or pipe data through stdin.")

# Write text to a file, encoding it as UTF-8. This is a simple helper for output operations, and it raises an error if the file cannot be written.
def write_text_file(path: str, text: str) -> None:
    try:
        with open(path, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
    except OSError as exc:
        raise InputError(f"Could not write file: {path}") from exc
