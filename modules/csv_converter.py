"""CSV repair and JSON conversion."""

from __future__ import annotations

import csv
import io
import json
import re
from collections import Counter, defaultdict

from dataguard.modules import string_sanitizer

DELIMITER_LABELS = {"auto": None, ",": ",", ";": ";", "|": "|", "tab": "\t"}
EMPTY_CELL_VALUES = {"", "n/a", "null", "-", "--", "none", "na"}

_DETECT_MAX_SCAN = 250
_DETECT_MAX_NONEMPTY = 30


def sample_nonempty_lines(lines: list[str], max_nonempty: int = _DETECT_MAX_NONEMPTY, max_scan: int = _DETECT_MAX_SCAN) -> list[str]:
    """Skip blanks and # comments; cap scan depth for delimiter detection."""
    sampled: list[str] = []
    scanned = 0
    for line in lines:
        scanned += 1
        if scanned > max_scan:
            break
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        sampled.append(line)
        if len(sampled) >= max_nonempty:
            break
    return sampled


def detect_delimiter(lines: list[str]) -> tuple[str, str]:
    candidates = [",", ";", "\t", "|"]
    sample = sample_nonempty_lines(lines)
    if not sample:
        return ",", "low"
    counts: dict[str, int] = {}
    for delimiter in candidates:
        counts[delimiter] = sum(line.count(delimiter) for line in sample)
    best = max(counts, key=counts.get)
    sorted_counts = sorted(counts.values(), reverse=True)
    confidence = "high" if len(sorted_counts) < 2 or sorted_counts[0] >= sorted_counts[1] * 1.5 else "low"
    return best, confidence


def looks_like_header(row: list[str]) -> bool:
    if not row:
        return False
    cleaned = [cell.strip() for cell in row]
    non_empty = [cell for cell in cleaned if cell]
    if not non_empty:
        return False
    if all(re.fullmatch(r"-?\d+(?:\.\d+)?", cell) for cell in non_empty):
        return False
    if len({cell.lower() for cell in non_empty}) != len(non_empty):
        return False
    return True


def normalize_headers(header_row: list[str]) -> tuple[list[str], list[dict]]:
    findings: list[dict] = []
    normalized: list[str] = []
    seen: Counter[str] = Counter()

    for index, raw_header in enumerate(header_row, start=1):
        header = raw_header.strip()
        if not header:
            header = f"unnamed_column_{index}"
            findings.append(
                {
                    "severity": "low",
                    "category": "header_repair",
                    "line": 1,
                    "message": f"Header {index} was empty and became {header}.",
                }
            )
        elif header != raw_header:
            findings.append(
                {
                    "severity": "low",
                    "category": "header_trim",
                    "line": 1,
                    "message": f"Trimmed whitespace in header {raw_header!r}.",
                }
            )

        seen[header] += 1
        if seen[header] > 1:
            new_header = f"{header}_{seen[header]}"
            findings.append(
                {
                    "severity": "low",
                    "category": "duplicate_header",
                    "line": 1,
                    "message": f"Duplicate header {header!r} renamed to {new_header}.",
                }
            )
            header = new_header

        normalized.append(header)

    return normalized, findings


class _LineTrackingReader:
    """Feeds csv.reader physical lines and records 1-based (start, end) line span per logical row."""

    __slots__ = ("_lines", "_i", "row_start_1based")

    def __init__(self, lines: list[str]):
        self._lines = lines
        self._i = 0
        self.row_start_1based: int | None = None

    def __iter__(self) -> _LineTrackingReader:
        return self

    def __next__(self) -> str:
        if self._i >= len(self._lines):
            raise StopIteration
        if self.row_start_1based is None:
            self.row_start_1based = self._i + 1
        line = self._lines[self._i]
        self._i += 1
        return line


def parse_csv_rows_with_spans(text: str, delimiter: str) -> tuple[list[list[str]], list[tuple[int, int]]]:
    """Parse CSV; return rows and inclusive 1-based (start_line, end_line) in ``text`` for each logical row."""
    if not text:
        return [], []
    physical = text.splitlines(keepends=True)
    if not physical:
        return [], []
    tracker = _LineTrackingReader(physical)
    reader = csv.reader(tracker, delimiter=delimiter)
    rows: list[list[str]] = []
    spans: list[tuple[int, int]] = []
    for row in reader:
        start = tracker.row_start_1based or 1
        end_line = tracker._i
        tracker.row_start_1based = None
        rows.append(row)
        spans.append((start, end_line))
    return rows, spans


def parse_csv_rows(text: str, delimiter: str) -> list[list[str]]:
    rows, _ = parse_csv_rows_with_spans(text, delimiter)
    return rows


def clean_cell(value: str) -> str | None:
    trimmed = value.strip()
    if trimmed.lower() in EMPTY_CELL_VALUES:
        return None
    return trimmed


def detect_type(values: list[str | None]) -> str:
    non_empty = [value for value in values if value not in {None, ""}]
    if not non_empty:
        return "empty"
    if all(str(value).lower() in {"true", "false", "yes", "no", "1", "0", "y", "n"} for value in non_empty):
        return "boolean"
    if all(re.fullmatch(r"-?\d+", str(value)) for value in non_empty):
        return "integer"
    if all(re.fullmatch(r"-?\d+(?:\.\d+)?%?", str(value).replace(",", "").replace("$", "")) for value in non_empty):
        return "float"
    return "string"


def convert_value(value: str | None, target_type: str):
    if value is None:
        return None
    if target_type == "boolean":
        return str(value).lower() in {"true", "yes", "1", "y"}
    if target_type == "integer":
        return int(str(value).replace(",", "").replace("$", ""))
    if target_type == "float":
        cleaned = str(value).replace(",", "").replace("$", "").rstrip("%")
        return float(cleaned)
    return value


def _maybe_flag_mixed_delimiter(
    *,
    chunk: str,
    delimiter: str,
    expected_columns: int,
    raw_row: list[str],
    start_line: int,
    findings: list[dict],
    mixed_seen: set[int],
) -> None:
    """If re-parsing the row chunk with another delimiter matches column count better, record one finding per start line."""
    if len(raw_row) == expected_columns:
        return
    candidates = [",", ";", "\t", "|"]
    for alt in candidates:
        if alt == delimiter:
            continue
        try:
            alt_rows = list(csv.reader(io.StringIO(chunk, newline=""), delimiter=alt))
        except csv.Error:
            continue
        if len(alt_rows) != 1:
            continue
        alt_row = alt_rows[0]
        if len(alt_row) == expected_columns and len(raw_row) != expected_columns:
            if start_line in mixed_seen:
                return
            mixed_seen.add(start_line)
            findings.append(
                {
                    "severity": "low",
                    "category": "mixed_delimiter",
                    "line": start_line,
                    "message": (
                        f"Starting at line {start_line}: parsed {len(raw_row)} column(s) with {delimiter!r} "
                        f"but {len(alt_row)} with {alt!r} (expected {expected_columns}); check delimiter or quoting."
                    ),
                }
            )
            return


def run(input_text: str, config: dict | None = None) -> dict:
    config = config or {}
    sanitized = string_sanitizer.run(input_text, {"source_name": config.get("source_name", "<input>")})
    cleaned_text = sanitized["output"]
    lines = cleaned_text.splitlines()
    findings = list(sanitized["findings"])

    delimiter_flag = config.get("delimiter", "auto")
    if delimiter_flag == "auto":
        delimiter, confidence = detect_delimiter(lines)
    else:
        delimiter = DELIMITER_LABELS.get(delimiter_flag, delimiter_flag)
        confidence = "manual"

    raw_rows, row_spans = parse_csv_rows_with_spans(cleaned_text, delimiter)
    if not raw_rows:
        return {
            "module_name": "csv",
            "title": "DataGuard CSV Doctor Report",
            "output": "[]",
            "rows": [],
            "findings": findings,
            "warnings": ["CSV input was empty."],
            "errors": [],
            "stats": {"rows_converted": 0},
            "metadata": {"source": config.get("source_name", "<input>"), "delimiter": repr(delimiter)},
            "summary": "No rows were converted because the input was empty.",
        }

    physical_lines = cleaned_text.splitlines(keepends=True)

    first_row = raw_rows[0]
    header_line = row_spans[0][0]
    if looks_like_header(first_row):
        headers, header_findings = normalize_headers(first_row)
        for hf in header_findings:
            hf["line"] = header_line
        data_rows = raw_rows[1:]
        data_spans = row_spans[1:]
        header_status = "provided"
    else:
        headers = [f"column_{index}" for index in range(1, len(first_row) + 1)]
        header_findings = [
            {
                "severity": "medium",
                "category": "missing_header",
                "line": header_line,
                "message": "First row did not look like a header, so column_1 style headers were generated.",
            }
        ]
        data_rows = raw_rows
        data_spans = row_spans
        header_status = "generated"
    findings.extend(header_findings)

    expected_columns = len(headers)
    strict_mode = bool(config.get("strict"))
    no_types = bool(config.get("no_types"))
    repaired_rows = 0
    rejected_rows = 0
    quarantine_rows: list[list[str]] = []
    converted_rows: list[dict] = []
    converted_row_lines: list[int] = []

    mixed_seen: set[int] = set()

    for raw_row, (start_line, end_line) in zip(data_rows, data_spans):
        chunk = "".join(physical_lines[start_line - 1 : end_line])
        _maybe_flag_mixed_delimiter(
            chunk=chunk,
            delimiter=delimiter,
            expected_columns=expected_columns,
            raw_row=raw_row,
            start_line=start_line,
            findings=findings,
            mixed_seen=mixed_seen,
        )

        row = list(raw_row)
        if len(row) < max(1, expected_columns // 2):
            rejected_rows += 1
            findings.append(
                {
                    "severity": "medium",
                    "category": "rejected_row",
                    "line": start_line,
                    "message": f"Row had only {len(row)} columns versus expected {expected_columns}.",
                }
            )
            quarantine_rows.append(raw_row)
            continue

        overflow_values: list[str] | None = None

        if len(row) < expected_columns:
            if strict_mode:
                rejected_rows += 1
                quarantine_rows.append(raw_row)
                findings.append(
                    {
                        "severity": "medium",
                        "category": "strict_rejection",
                        "line": start_line,
                        "message": f"Strict mode rejected short row with {len(row)} columns.",
                    }
                )
                continue
            row.extend([""] * (expected_columns - len(row)))
            repaired_rows += 1
            findings.append(
                {
                    "severity": "low",
                    "category": "row_padding",
                    "line": start_line,
                    "message": f"Padded short row from {len(raw_row)} to {expected_columns} columns.",
                }
            )
        elif len(row) > expected_columns:
            overflow_values = row[expected_columns:]
            if strict_mode:
                rejected_rows += 1
                quarantine_rows.append(raw_row)
                findings.append(
                    {
                        "severity": "medium",
                        "category": "strict_rejection",
                        "line": start_line,
                        "message": f"Strict mode rejected long row with {len(row)} columns.",
                    }
                )
                continue
            row = row[:expected_columns]
            repaired_rows += 1
            findings.append(
                {
                    "severity": "low",
                    "category": "row_overflow",
                    "line": start_line,
                    "message": "Moved extra columns into _overflow.",
                }
            )

        row_dict: dict = {}
        for header, value in zip(headers, row):
            row_dict[header] = clean_cell(value)
        if overflow_values:
            row_dict["_overflow"] = [clean_cell(value) for value in overflow_values]

        converted_rows.append(row_dict)
        converted_row_lines.append(start_line)

    column_values: defaultdict[str, list] = defaultdict(list)
    for row in converted_rows:
        for header in headers:
            column_values[header].append(row.get(header))

    inferred_types = {header: detect_type(column_values[header]) for header in headers}
    type_mismatches = 0
    if not no_types:
        for start_line, row in zip(converted_row_lines, converted_rows):
            for header, target_type in inferred_types.items():
                value = row.get(header)
                if value is None or target_type in {"string", "empty"}:
                    continue
                try:
                    row[header] = convert_value(value, target_type)
                except ValueError:
                    type_mismatches += 1
                    findings.append(
                        {
                            "severity": "low",
                            "category": "type_mismatch",
                            "line": start_line,
                            "message": f"Value {value!r} in column {header} did not fit inferred type {target_type}.",
                        }
                    )

    completeness = {}
    for header in headers:
        values = column_values[header]
        non_null = sum(1 for value in values if value is not None)
        completeness[header] = round((non_null / max(len(values), 1)) * 100, 1)

    output_json = json.dumps(converted_rows, indent=2, ensure_ascii=False)
    stats = {
        "rows_converted": len(converted_rows),
        "rows_repaired": repaired_rows,
        "rows_rejected": rejected_rows,
        "delimiter": repr(delimiter),
        "delimiter_confidence": confidence,
        "header_status": header_status,
        "expected_columns": expected_columns,
        "mixed_delimiter_lines": len(mixed_seen),
        "type_mismatches": type_mismatches,
    }

    metadata = {
        "source": config.get("source_name", "<input>"),
        "delimiter": repr(delimiter),
        "header_status": header_status,
    }

    summary = (
        f"Converted {len(converted_rows)} rows to JSON, repaired {repaired_rows}, rejected {rejected_rows}. "
        f"Delimiter {repr(delimiter)} detected with {confidence} confidence."
    )

    return {
        "module_name": "csv",
        "title": "DataGuard CSV Doctor Report",
        "output": output_json,
        "rows": converted_rows,
        "quarantine_rows": quarantine_rows,
        "findings": findings,
        "warnings": [f"{rejected_rows} rows were rejected."] if rejected_rows else [],
        "errors": [],
        "stats": stats,
        "metadata": metadata,
        "column_profiles": [{"name": header, "type": inferred_types[header], "completeness": completeness[header]} for header in headers],
        "summary": summary,
    }
