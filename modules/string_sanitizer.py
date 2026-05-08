"""Text artifact sanitizer for invisible and unsafe character-level content.

Strips ANSI escapes, Unicode category Cc (controls) except newline/tab, normalizes curated spaces and
smart quotes, removes common zero-width marks, and optionally removes bidi embedding / isolate /
format marks (U+200E–U+200F, U+202A–U+202E, U+2066–U+2069, U+FEFF) that can affect comparison or
“trojan source” style display. Does not apply full NFKC normalization or confusable detection.
"""

from __future__ import annotations

import re
import unicodedata

ANSI_ESCAPE_PATTERN = re.compile(
    r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])"
)

# Newline and tab are preserved in plain text pipelines.
_ALLOWED_CC_CHARACTERS = frozenset({"\n", "\t"})

UNICODE_WHITESPACE_MAP = {
    "\u00a0": "NO-BREAK SPACE",
    "\u1680": "OGHAM SPACE MARK",
    "\u2000": "EN QUAD",
    "\u2001": "EM QUAD",
    "\u2002": "EN SPACE",
    "\u2003": "EM SPACE",
    "\u2004": "THREE-PER-EM SPACE",
    "\u2005": "FOUR-PER-EM SPACE",
    "\u2006": "SIX-PER-EM SPACE",
    "\u2007": "FIGURE SPACE",
    "\u2008": "PUNCTUATION SPACE",
    "\u2009": "THIN SPACE",
    "\u200a": "HAIR SPACE",
    "\u202f": "NARROW NO-BREAK SPACE",
    "\u205f": "MEDIUM MATHEMATICAL SPACE",
    "\u3000": "IDEOGRAPHIC SPACE",
}

SMART_QUOTES = {
    "\u2018": "'",
    "\u2019": "'",
    "\u201c": '"',
    "\u201d": '"',
}

ZERO_WIDTH_CHARACTERS = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u2060": "WORD JOINER",
    "\u00ad": "SOFT HYPHEN",
}

# Bidi / explicit directional and isolate controls + FEFF when not already removed as leading BOM.
_BIDI_FORMAT_STRIP_ORDS: frozenset[int] = frozenset(
    list(range(0x200E, 0x2010))  # LRM, RLM
    + list(range(0x202A, 0x202F))  # LRE–RLO, PDF
    + list(range(0x2066, 0x206A))  # isolates
    + [0xFEFF]
)

CATEGORY_ORDER = [
    "bom_markers",
    "ansi_codes",
    "control_characters",
    "unicode_whitespace",
    "smart_quotes",
    "zero_width_characters",
    "bidi_format_marks",
]


def build_tracked_characters(text: str) -> list[dict]:
    return [{"char": character, "origin": index} for index, character in enumerate(text)]


def line_number_for_position(text: str, position: int) -> int:
    return text.count("\n", 0, max(position, 0)) + 1


def describe_character(character: str) -> str:
    codepoint = f"U+{ord(character):04X}"
    name = unicodedata.name(character, "UNKNOWN")
    return f"{codepoint} {name}"


def add_character_finding(findings: list[dict], category: str, text: str, position: int, message: str) -> None:
    findings.append(
        {
            "severity": "low",
            "category": category,
            "line": line_number_for_position(text, position),
            "position": position,
            "message": message,
        }
    )


def strip_bom(records: list[dict], original_text: str, findings: list[dict]) -> list[dict]:
    if records and records[0]["char"] == "\ufeff":
        add_character_finding(
            findings,
            "bom_markers",
            original_text,
            records[0]["origin"],
            f"Removed BOM marker at position {records[0]['origin']}.",
        )
        return records[1:]
    return records


def remove_ansi_codes(records: list[dict], original_text: str, findings: list[dict]) -> list[dict]:
    if not records:
        return records

    combined = "".join(record["char"] for record in records)
    kept_records = []
    current_index = 0

    for match in ANSI_ESCAPE_PATTERN.finditer(combined):
        start, end = match.span()
        kept_records.extend(records[current_index:start])
        start_position = records[start]["origin"]
        raw_sequence = match.group(0).encode("unicode_escape").decode("ascii")
        add_character_finding(
            findings,
            "ansi_codes",
            original_text,
            start_position,
            f"Removed ANSI escape sequence {raw_sequence} starting at position {start_position}.",
        )
        current_index = end

    kept_records.extend(records[current_index:])
    return kept_records


def strip_unicode_controls(records: list[dict], original_text: str, findings: list[dict]) -> list[dict]:
    """Remove all Unicode category Cc characters except preserved newline and tab."""
    kept_records = []
    for record in records:
        character = record["char"]
        if character in _ALLOWED_CC_CHARACTERS:
            kept_records.append(record)
            continue
        if unicodedata.category(character) == "Cc":
            add_character_finding(
                findings,
                "control_characters",
                original_text,
                record["origin"],
                f"Removed {describe_character(character)} at position {record['origin']}.",
            )
            continue
        kept_records.append(record)
    return kept_records


def normalize_whitespace(records: list[dict], original_text: str, findings: list[dict]) -> list[dict]:
    normalized = []
    for record in records:
        character = record["char"]
        if character in UNICODE_WHITESPACE_MAP:
            add_character_finding(
                findings,
                "unicode_whitespace",
                original_text,
                record["origin"],
                f"Normalized {describe_character(character)} to ASCII space at position {record['origin']}.",
            )
            normalized.append({"char": " ", "origin": record["origin"]})
            continue
        normalized.append(record)
    return normalized


def normalize_smart_quotes(records: list[dict], original_text: str, findings: list[dict]) -> list[dict]:
    normalized = []
    for record in records:
        character = record["char"]
        if character in SMART_QUOTES:
            replacement = SMART_QUOTES[character]
            add_character_finding(
                findings,
                "smart_quotes",
                original_text,
                record["origin"],
                f"Normalized {describe_character(character)} to {replacement!r} at position {record['origin']}.",
            )
            normalized.append({"char": replacement, "origin": record["origin"]})
            continue
        normalized.append(record)
    return normalized


def remove_zero_width(records: list[dict], original_text: str, findings: list[dict]) -> list[dict]:
    kept_records = []
    for record in records:
        character = record["char"]
        if character in ZERO_WIDTH_CHARACTERS:
            add_character_finding(
                findings,
                "zero_width_characters",
                original_text,
                record["origin"],
                f"Removed {describe_character(character)} at position {record['origin']}.",
            )
            continue
        kept_records.append(record)
    return kept_records


def remove_bidi_format_marks(records: list[dict], original_text: str, findings: list[dict]) -> list[dict]:
    """Remove explicit bidi / isolate controls and FEFF (after leading BOM handling)."""
    kept_records = []
    for record in records:
        code = ord(record["char"])
        if code in _BIDI_FORMAT_STRIP_ORDS:
            add_character_finding(
                findings,
                "bidi_format_marks",
                original_text,
                record["origin"],
                f"Removed {describe_character(record['char'])} at position {record['origin']}.",
            )
            continue
        kept_records.append(record)
    return kept_records


def summarize_findings(findings: list[dict]) -> dict:
    summary = {category: 0 for category in CATEGORY_ORDER}
    for finding in findings:
        summary[finding["category"]] = summary.get(finding["category"], 0) + 1
    return summary


def sanitize(text: str, *, strip_bidi_format_marks: bool = True) -> tuple[str, list[dict], dict]:
    findings: list[dict] = []
    tracked = build_tracked_characters(text)
    tracked = strip_bom(tracked, text, findings)
    tracked = remove_ansi_codes(tracked, text, findings)
    tracked = strip_unicode_controls(tracked, text, findings)
    tracked = normalize_whitespace(tracked, text, findings)
    tracked = normalize_smart_quotes(tracked, text, findings)
    tracked = remove_zero_width(tracked, text, findings)
    if strip_bidi_format_marks:
        tracked = remove_bidi_format_marks(tracked, text, findings)
    cleaned = "".join(record["char"] for record in tracked)
    stats = summarize_findings(findings)
    stats["original_characters"] = len(text)
    stats["cleaned_characters"] = len(cleaned)
    stats["net_code_unit_delta"] = len(text) - len(cleaned)
    stats["normalization_events"] = stats["unicode_whitespace"] + stats["smart_quotes"]
    stats["characters_removed_or_replaced"] = stats["net_code_unit_delta"]
    return cleaned, findings, stats


def build_result(cleaned_text: str, findings: list[dict], stats: dict, source_name: str = "<input>") -> dict:
    return {
        "module_name": "sanitize",
        "title": "DataGuard Sanitizer Report",
        "output": cleaned_text,
        "findings": findings,
        "warnings": [],
        "errors": [],
        "stats": stats,
        "metadata": {"source": source_name},
        "summary": (
            f"Removed or normalized {sum(stats.get(category, 0) for category in CATEGORY_ORDER)} "
            f"artifacts across {len(findings)} findings."
        ),
    }


def run(input_text: str, config: dict | None = None) -> dict:
    config = config or {}
    strip_bidi = bool(config.get("strip_bidi_format_marks", True))
    cleaned_text, findings, stats = sanitize(input_text, strip_bidi_format_marks=strip_bidi)
    result = build_result(cleaned_text, findings, stats, config.get("source_name", "<input>"))
    result["metadata"]["strip_bidi_format_marks"] = strip_bidi
    return result
