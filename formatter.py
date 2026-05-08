"""Shared output and report formatting.

Primary stdout serialization is for CLI piping; it is not a security boundary.
"""

from __future__ import annotations

import csv
import io
import json
import os
import sys
from typing import Any


ANSI_COLORS = {
    "reset": "\033[0m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
}

SEVERITY_COLORS = {
    "critical": "magenta",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "cyan",
}


def stream_supports_color(stream: Any) -> bool:
    """Return True if ``stream`` is a TTY and ``NO_COLOR`` is not set."""
    if not hasattr(stream, "isatty") or not stream.isatty():
        return False
    if os.environ.get("NO_COLOR"):
        return False
    return True


def colorize(text: str | object, color: str, enabled: bool = True) -> str:
    """Wrap stringified ``text`` in ANSI ``color`` when ``enabled`` and the color is known."""
    plain = text if isinstance(text, str) else str(text)
    if not enabled or color not in ANSI_COLORS:
        return plain
    return f"{ANSI_COLORS[color]}{plain}{ANSI_COLORS['reset']}"


def format_table(headers: list[str], rows: list[list[object]], borders: bool = False) -> str:
    """Build a fixed-width text table; column count is the max of header and row widths."""
    string_rows = [[str(cell) for cell in row] for row in rows]
    ncol = max(len(headers), max((len(r) for r in string_rows), default=0))
    if ncol == 0:
        return ""

    header_cells = [str(headers[i]) if i < len(headers) else "" for i in range(ncol)]
    widths = [len(header_cells[i]) for i in range(ncol)]
    for row in string_rows:
        for index, value in enumerate(row):
            if index < ncol:
                widths[index] = max(widths[index], len(value))

    def render_row(row_values: list[str]) -> str:
        padded = (row_values + [""] * ncol)[:ncol]
        cells = [value.ljust(widths[i]) for i, value in enumerate(padded)]
        if borders:
            return "| " + " | ".join(cells) + " |"
        return "  ".join(cells)

    lines = [render_row(header_cells)]
    divider_parts = ["-" * w for w in widths]
    if borders:
        lines.append("|-" + "-|-".join(divider_parts) + "-|")
    else:
        lines.append("  ".join(divider_parts))
    for row in string_rows:
        lines.append(render_row(row))
    return "\n".join(lines)


def findings_to_rows(findings: list[Any]) -> list[list[object]]:
    rows: list[list[object]] = []
    for finding in findings:
        if isinstance(finding, dict):
            rows.append(
                [
                    finding.get("severity", "info"),
                    finding.get("category", ""),
                    finding.get("line", ""),
                    finding.get("message", ""),
                ]
            )
        else:
            rows.append(["info", "", "", str(finding)])
    return rows


def render_report_text(result: dict, color_enabled: bool = True) -> str:
    lines: list[str] = []
    title = result.get("title") or result.get("module_name", "DataGuard Report")
    title_str = str(title)
    lines.append(title_str)
    lines.append("=" * len(title_str))

    metadata = result.get("metadata", {})
    if metadata:
        for key, value in metadata.items():
            lines.append(f"{key}: {value}")

    stats = result.get("stats", {})
    if stats:
        lines.append("")
        lines.append("Stats")
        lines.append("-----")
        for key, value in stats.items():
            lines.append(f"{key}: {value}")

    findings = result.get("findings", [])
    if findings:
        lines.append("")
        lines.append("Findings")
        lines.append("--------")
        rendered_rows: list[list[object]] = []
        for row in findings_to_rows(findings):
            raw_severity = row[0]
            display_severity = raw_severity if raw_severity is not None else "info"
            color = SEVERITY_COLORS.get(str(display_severity).lower(), "cyan")
            row[0] = colorize(display_severity, color, color_enabled)
            rendered_rows.append(row)
        lines.append(format_table(["Severity", "Category", "Line", "Message"], rendered_rows))

    warnings = result.get("warnings", [])
    if warnings:
        lines.append("")
        lines.append("Warnings")
        lines.append("--------")
        for warning in warnings:
            lines.append(f"- {warning}")

    errors = result.get("errors", [])
    if errors:
        lines.append("")
        lines.append("Errors")
        lines.append("------")
        for error in errors:
            lines.append(f"- {error}")

    diff_block = result.get("diff")
    if diff_block:
        lines.append("")
        lines.append("Diff (unified)")
        lines.append("------------")
        if isinstance(diff_block, dict):
            body = diff_block.get("unified", "")
            for key in ("before_characters", "after_characters"):
                if key in diff_block:
                    lines.append(f"{key}: {diff_block[key]}")
            if body.strip():
                lines.append(body.rstrip())
        else:
            lines.append(str(diff_block))

    summary = result.get("summary")
    if summary:
        lines.append("")
        lines.append(f"Summary: {summary}")

    return "\n".join(lines).strip()


def render_report_csv(result: dict) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["severity", "category", "line", "message"])
    for finding in result.get("findings", []):
        if isinstance(finding, dict):
            writer.writerow(
                [
                    finding.get("severity", "info"),
                    finding.get("category", ""),
                    finding.get("line", ""),
                    finding.get("message", ""),
                ]
            )
        else:
            writer.writerow(["info", "", "", str(finding)])
    return buffer.getvalue()


def render_report(result: dict, report_format: str = "text", color_enabled: bool = True) -> str:
    fmt = report_format.lower()
    if fmt == "json":
        try:
            return json.dumps(result, indent=2, ensure_ascii=False)
        except (TypeError, ValueError):
            return json.dumps(
                {
                    "error": "Report could not be encoded as JSON (non-serializable values in result).",
                    "title": result.get("title") if isinstance(result, dict) else None,
                    "module_name": result.get("module_name") if isinstance(result, dict) else None,
                },
                indent=2,
                ensure_ascii=False,
            )
    if fmt == "csv":
        return render_report_csv(result)
    if fmt == "text":
        return render_report_text(result, color_enabled=color_enabled)
    raise ValueError(f"Unknown report format {report_format!r}; expected text, json, or csv.")


def write_report(
    result: dict,
    report_format: str = "text",
    color_enabled: bool = True,
    report_file: str | None = None,
) -> None:
    rendered = render_report(result, report_format=report_format, color_enabled=color_enabled)
    if report_file:
        with open(report_file, "w", encoding="utf-8", newline="") as handle:
            handle.write(rendered)
            if not rendered.endswith("\n"):
                handle.write("\n")
        return
    sys.stderr.write(rendered)
    if not rendered.endswith("\n"):
        sys.stderr.write("\n")


def serialize_primary_output(output, pipe_format: str = "text") -> str:
    """Format module primary output for stdout.

    * ``text`` — Human-oriented default: ``dict`` / ``list`` as indented JSON; other values as ``str()``.
    * ``json`` — Indented JSON for JSON-serializable values; non-serializable values fall back to ``str()``.
    * ``raw`` — Compact single-line JSON for ``dict`` / ``list`` (distinct from ``text``/``json``); strings and
      other scalars as ``str()`` with no added decoration.

    ``pipe_format`` is matched case-insensitively. Unknown values behave like ``text``.
    """
    fmt = pipe_format.lower()
    if fmt == "raw":
        if isinstance(output, (dict, list)):
            try:
                return json.dumps(output, ensure_ascii=False, separators=(",", ":"))
            except (TypeError, ValueError):
                return str(output)
        return str(output)
    if fmt == "json":
        try:
            return json.dumps(output, indent=2, ensure_ascii=False)
        except (TypeError, ValueError):
            return str(output)
    if isinstance(output, (dict, list)):
        try:
            return json.dumps(output, indent=2, ensure_ascii=False)
        except (TypeError, ValueError):
            return str(output)
    return str(output)