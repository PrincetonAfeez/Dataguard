"""File type detection for the unified DataGuard CLI."""

from __future__ import annotations

import csv
import io
import os
import re

# Mapping of file extensions to their likely modules, used to boost confidence when an extension is present.
EXTENSION_TO_MODULE = {
    ".log": "logs",
    ".csv": "csv",
    ".tsv": "csv",
    ".html": "html",
    ".htm": "html",
}

# When multiple modules have similar scores, this ordering is used to break ties based on typical specificity.
MODULE_PRIORITY = ["logs", "csv", "html", "contacts", "audit", "sanitize"]

# Word-boundary HTTP methods (avoids matching "TARGETED", "wget", etc.)
_HTTP_METHOD_RE = re.compile(
    r"\b(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b",
)

_SAMPLE_MAX_SCAN = 250
_SAMPLE_MAX_NONEMPTY = 35

# The sampling strategy is designed to find a representative subset of lines that are likely to contain meaningful content, while avoiding excessive scanning of large files. It prioritizes non-empty, non-comment lines, which are more likely to contain the patterns relevant for detection. If no such lines are found within the scan limit, it falls back to a raw prefix of the file, which may still provide useful clues for detection without being too costly to analyze.
def sample_lines(text: str) -> list[str]:
    """Prefer non-empty, non-comment lines up to limits; fall back to raw prefix if sample is empty."""
    sampled: list[str] = []
    scanned = 0
    for line in text.splitlines():
        scanned += 1
        if scanned > _SAMPLE_MAX_SCAN:
            break
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        sampled.append(line)
        if len(sampled) >= _SAMPLE_MAX_NONEMPTY:
            break
    if sampled:
        return sampled
    raw = text.splitlines()[:25]
    return raw

# Scoring functions return a confidence score from 0.0 to 1.0 for how well the lines match the expected patterns for that module. They are designed to be heuristic and may boost confidence based on multiple indicators, but they should not be overly strict or rely on any single pattern. The final decision is made by comparing scores across modules and applying tie-breaking logic as needed.
def score_as_log(lines: list[str]) -> float:
    score = 0.0
    line_count = max(len(lines), 1)
    for line in lines:
        if re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", line):
            score += 0.2
        # Bracketed segment long enough to resemble a log timestamp, not just "[]"
        if re.search(r"\[[^\]\n]{4,}\]", line):
            score += 0.1
        if _HTTP_METHOD_RE.search(line):
            score += 0.2
        if re.search(r"\b[1-5]\d{2}\b", line):
            score += 0.1
    return min(score / line_count, 1.0)

# The CSV scoring function looks for consistent column counts across lines, the presence of common delimiters, and the nature of the first row (which may indicate headers). It also considers the total number of lines that parse successfully as CSV rows. The presence of a consistent structure is a strong indicator of CSV format, while variability or lack of delimiters reduces confidence.
def _parsed_column_counts(lines: list[str], delimiter: str) -> list[int]:
    counts: list[int] = []
    for line in lines:
        if not line.strip():
            continue
        try:
            row = next(csv.reader(io.StringIO(line, newline=""), delimiter=delimiter))
        except csv.Error:
            continue
        if not row:
            continue
        if len(row) == 1 and not (row[0] or "").strip():
            continue
        counts.append(len(row))
    return counts

# The row parsing function attempts to parse a single line as a CSV row using the specified delimiter. It returns the list of cells if successful, or an empty list if parsing fails. This is used to analyze the first line for potential headers and to check for consistency with the column counts.
def _row_cells(line: str, delimiter: str) -> list[str]:
    try:
        return list(next(csv.reader(io.StringIO(line.strip(), newline=""), delimiter=delimiter)))
    except (csv.Error, StopIteration):
        return []

# The CSV scoring function evaluates multiple potential delimiters and looks for consistent column counts across lines, the presence of a header row, and the overall structure. It assigns points based on these factors, with a maximum score of 1.0. The function is designed to be robust against variability in the input and to recognize common CSV patterns without being overly strict.
def score_as_csv(lines: list[str]) -> float:
    if not lines:
        return 0.0
    delimiters = [",", ";", "\t", "|"]
    scores: list[float] = []
    for delimiter in delimiters:
        counts = _parsed_column_counts(lines, delimiter)
        if len(counts) < 2:
            continue
        head = counts[: min(8, len(counts))]
        if len(set(head)) != 1:
            continue
        col_count = head[0]
        if col_count < 2:
            continue
        full_consistent = len(set(counts)) == 1
        score = 0.3
        if col_count >= 3:
            score += 0.15
        if full_consistent:
            score += 0.25
        if len(counts) >= 5:
            score += 0.1
        first_cells = _row_cells(lines[0], delimiter)
        if len(first_cells) == col_count and first_cells:
            nonempty = [(c or "").strip() for c in first_cells if (c or "").strip()]
            if nonempty and not all(re.fullmatch(r"-?\d+(?:\.\d+)?", c) for c in nonempty):
                score += 0.15
        scores.append(min(score, 1.0))
    return min(max(scores or [0.0]), 1.0)

# The HTML scoring function looks for the presence of common HTML tags and structures. It assigns points based on the presence of doctype declarations, structural tags like <html> and <body>, and other common elements like <script>, <a>, and <img>. The function is designed to recognize typical HTML patterns while allowing for variability in formatting and content.
def score_as_html(lines: list[str]) -> float:
    score = 0.0
    text = "\n".join(lines)
    if re.search(r"<!DOCTYPE|<html|<body|<div|<span|<p\b", text, re.IGNORECASE):
        score += 0.55
    if re.search(r"<script|<a\b|<img\b|</\w+>", text, re.IGNORECASE):
        score += 0.4
    # No extra score for bare "<" and ">" (reduces false positives in logs/code)
    return min(score, 1.0)

# The contacts scoring function looks for patterns commonly found in contact lists, such as email addresses, phone numbers, names, and "From:" lines. It assigns points based on the presence of these patterns, with a maximum score of 1.0. The function is designed to recognize typical contact information while allowing for variability in formatting and content.
def score_as_contacts(lines: list[str]) -> float:
    score = 0.0
    text = "\n".join(lines)
    if re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}", text):
        score += 0.45
    if re.search(r"(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}", text):
        score += 0.3
    if re.search(r"\b[A-Z][a-z]+ [A-Z][a-z]+\b", text):
        score += 0.12
    if re.search(r"(?m)^From:\s", text):
        score += 0.1
    if re.search(r"<[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}>", text):
        score += 0.08
    return min(score, 1.0)

# The password scoring function looks for patterns commonly found in password audit files, such as single-word lines, the presence of both letters and digits, and the absence of common delimiters. It also considers the scores from the CSV and HTML functions, reducing confidence if those scores are high (since password lists are less likely to be in those formats). The function is designed to recognize typical password patterns while allowing for variability in formatting and content.
def score_as_passwords(lines: list[str], *, csv_score: float = 0.0, html_score: float = 0.0) -> float:
    if not lines:
        return 0.0
    usable_lines = [line for line in lines if line.strip()]
    if not usable_lines:
        return 0.0
    if len(usable_lines) < 3:
        return 0.15

    score = 0.0
    simple_lines = sum(
        1
        for line in usable_lines
        if len(line.split()) == 1 and "@" not in line and "<" not in line and not line.strip().startswith("#")
    )
    if simple_lines / len(usable_lines) >= 0.75:
        score += 0.35
    if any(re.search(r"[A-Z]", line) and re.search(r"\d", line) for line in usable_lines):
        score += 0.2
    if all("," not in line and ";" not in line and "\t" not in line and "|" not in line for line in usable_lines):
        score += 0.15
    if all(len(line) <= 64 for line in usable_lines):
        score += 0.15

    score = min(score, 1.0)
    if csv_score >= 0.5:
        score *= 0.4
    elif csv_score >= 0.35:
        score *= 0.65
    if html_score >= 0.55:
        score *= 0.45
    return min(score, 1.0)

# The plain text scoring function assigns a baseline score for any non-empty text, with a boost if it detects zero-width characters that are sometimes used in obfuscation. This allows the "sanitize" module to be selected as a fallback when no other module has strong indicators, while still recognizing when the content is essentially just plain text without special patterns.
def score_as_plain_text(lines: list[str]) -> float:
    text = "\n".join(lines)
    if not text.strip():
        return 0.0
    if re.search(r"[\u200b\u200c\u200d\u2060]", text):
        return 0.8
    return 0.35

# The main detection function applies all scoring functions to the sampled lines and combines their results. It also considers the file extension if available, boosting the score for the corresponding module. Finally, it compares the scores across modules, applies tie-breaking logic based on the defined priority, and returns the best guess along with the scores and reasoning.
def detect_module(text: str, file_path: str | None = None) -> dict:
    lines = sample_lines(text)
    csv_s = score_as_csv(lines)
    html_s = score_as_html(lines)
    scores = {
        "logs": score_as_log(lines),
        "csv": csv_s,
        "html": html_s,
        "contacts": score_as_contacts(lines),
        "audit": score_as_passwords(lines, csv_score=csv_s, html_score=html_s),
        "sanitize": score_as_plain_text(lines),
    }

    if file_path:
        extension = os.path.splitext(file_path)[1].lower()
        if extension in EXTENSION_TO_MODULE:
            scores[EXTENSION_TO_MODULE[extension]] = max(scores[EXTENSION_TO_MODULE[extension]], 0.9)

    sorted_scores = sorted(scores.items(), key=lambda item: item[1], reverse=True)
    best_module, best_score = sorted_scores[0]
    second_module, second_score = sorted_scores[1]

    notes: list[str] = []
    if best_score < 0.3:
        notes.append("No module cleared the confidence threshold, falling back to sanitize.")
        best_module = "sanitize"
    elif best_score - second_score <= 0.1:
        tied = {name for name, score in sorted_scores if best_score - score <= 0.1}
        notes.append(
            "Close detection scores between "
            + ", ".join(sorted(tied))
            + "; priority ordering was used to break the tie."
        )
        for candidate in MODULE_PRIORITY:
            if candidate in tied:
                best_module = candidate
                break

    reason = f"Detected {best_module} with confidence {scores[best_module]:.2f}"
    return {"module": best_module, "scores": scores, "reason": reason, "notes": notes}
