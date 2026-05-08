"""Email and phone extraction from messy text.

The unified CLI supplies ``min_confidence``; when omitted there, it comes from ``min_confidence_threshold`` in config
(see ``dataguard.config.resolve_contacts_min_confidence``).

Phones: NANP (US/Canada) with exchange/area plausibility, digit-sequence matches that are not substrings of longer
numeric runs, and international ``+`` E.164-style numbers (7–15 digits, no leading 0). Email validation adds RFC 5321
-ish length limits and optional IDN (punycode) domain labels. When email and phone counts differ on one line, rows are
emitted unpaired (no false index-based pairing).
"""

from __future__ import annotations

import csv
import io
import re
from collections import Counter

from dataguard.modules import string_sanitizer

EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b"
)

# NANP: NPA and exchange first digits 2–9; optional +1; separators allowed.
PHONE_US_FORMATTED = re.compile(
    r"(?:\+1[-.\s]?)?(?:\([2-9]\d{2}\)|[2-9]\d{2})[-.\s]?(?:[2-9]\d{2})[-.\s]?\d{4}"
)

# Standalone NANP 10 digits; optional +1 / separators before the NPA (not inside longer digit runs).
PHONE_US_RAW = re.compile(r"(?<!\d)(?:\+?1[-.\s]*)?([2-9]\d{2}[2-9]\d{2}\d{4})(?!\d)")

# + and subscriber digits (separators allowed); length validated in normalize. +1 NANP handled by US patterns only.
PHONE_INTL = re.compile(r"(?<![A-Za-z0-9@])(\+[1-9][\d().\s-]*\d)")

NAME_PATTERNS = [
    re.compile(r"\b([A-Z][a-z]+(?: [A-Z][a-z]+){1,3})\b"),
    re.compile(r"\b([A-Z]{2,}(?: [A-Z]{2,}){1,3})\b"),
    re.compile(
        r"\b([A-Z][a-z]+(?:[-'][A-Z]?[a-z]+)*(?: (?:[Vv]an|[Dd]e|[Dd]er|[Vv]on|[Dd]el|[Ll]a|[Ll]e|[Dd]i|[Dd]a) [A-Z][a-z]+){1,2})\b"
    ),
]

PHONE_CONTEXT_WORDS = {"cell", "phone", "mobile", "tel", "office", "contact", "fax", "call"}


def validate_email(candidate: str) -> tuple[bool, str]:
    local_part, _, domain = candidate.partition("@")
    if ".." in candidate:
        return False, "contains consecutive dots"
    if not local_part or not domain:
        return False, "missing local part or domain"
    if len(local_part) > 64:
        return False, "local part exceeds 64 characters"
    if len(domain) > 253:
        return False, "domain exceeds 253 characters"
    if local_part[0] in ".-_+" or local_part[-1] in ".-_+":
        return False, "starts or ends with a special character"
    labels = domain.split(".")
    if any(not label for label in labels):
        return False, "contains an empty domain label"
    for label in labels:
        if len(label) > 63:
            return False, "domain label exceeds 63 characters"
    if any(label.startswith("-") or label.endswith("-") for label in labels):
        return False, "domain label starts or ends with hyphen"
    if not _domain_labels_valid_encoding(labels):
        return False, "domain label not valid for DNS (IDN)"
    tld = labels[-1]
    if not 2 <= len(tld) <= 63:
        return False, "invalid TLD length"
    return True, ""


def _domain_labels_valid_encoding(labels: list[str]) -> bool:
    try:
        "".join(labels).encode("ascii")
        return True
    except UnicodeEncodeError:
        pass
    for label in labels:
        try:
            label.encode("idna")
        except UnicodeError:
            return False
    return True


def normalize_us_phone(candidate: str) -> tuple[bool, str, str]:
    digits = re.sub(r"\D", "", candidate)
    had_country = len(digits) == 11 and digits.startswith("1")
    if had_country:
        digits = digits[1:]
    if len(digits) != 10:
        return False, "", "must contain 10 digits (NANP) or 11 with country code 1"
    if not _valid_nanp_10(digits):
        return False, "", "invalid NANP area or exchange code"
    prefix = "+1 " if had_country or candidate.strip().startswith("+1") else ""
    normalized = f"{prefix}({digits[:3]}) {digits[3:6]}-{digits[6:]}"
    return True, normalized, ""


def _valid_nanp_10(d: str) -> bool:
    if len(d) != 10 or not d.isdigit():
        return False
    if d[0] in "01" or d[3] in "01":
        return False
    return True


def normalize_international_phone(candidate: str) -> tuple[bool, str, str]:
    stripped = candidate.strip()
    if not stripped.startswith("+"):
        return False, "", "international numbers must include + and country code"
    digits = re.sub(r"\D", "", stripped[1:])
    if len(digits) < 7 or len(digits) > 15:
        return False, "", "international number must have 7–15 digits"
    if digits[0] == "0":
        return False, "", "invalid leading digit in international number"
    if digits.startswith("1") and len(digits) == 11 and _valid_nanp_10(digits[1:]):
        return False, "", "use NANP path for +1 numbers"
    return True, f"+{digits}", ""


def try_normalize_phone(candidate: str) -> tuple[bool, str, str, bool]:
    """Return (ok, normalized, reason, international)."""
    stripped = candidate.strip()
    digits_all = re.sub(r"\D", "", stripped)

    if stripped.startswith("+"):
        if digits_all.startswith("1") and len(digits_all) == 11 and _valid_nanp_10(digits_all[1:]):
            ok, norm, reason = normalize_us_phone(candidate)
            return ok, norm, reason, False
        ok, norm, reason = normalize_international_phone(candidate)
        return ok, norm, reason, True

    ok, norm, reason = normalize_us_phone(candidate)
    return ok, norm, reason, False


def collect_phone_candidates(line: str) -> list[str]:
    """Non-overlapping matches; prefer longer / higher-priority spans (formatted US > intl > raw US)."""
    spans: list[tuple[int, int, str, int]] = []
    for m in PHONE_US_FORMATTED.finditer(line):
        spans.append((m.start(), m.end(), m.group(0), 0))
    for m in PHONE_US_RAW.finditer(line):
        body = m.group(1)
        if body and _valid_nanp_10(body):
            spans.append((m.start(), m.end(), m.group(0), 2))

    for m in PHONE_INTL.finditer(line):
        chunk = m.group(0)
        sub = re.sub(r"\D", "", chunk[1:])
        if sub.startswith("1") and len(sub) == 11 and _valid_nanp_10(sub[1:]):
            continue
        if 7 <= len(sub) <= 15:
            spans.append((m.start(), m.end(), chunk, 1))

    spans.sort(key=lambda x: (x[0], -(x[1] - x[0]), x[3]))
    chosen: list[tuple[int, int, str]] = []
    for s, e, text, _prio in spans:
        if any(s < ce and e > cs for cs, ce, _ in chosen):
            continue
        chosen.append((s, e, text))
    chosen.sort(key=lambda x: x[0])
    return [t for _, _, t in chosen]


def find_name(lines: list[str], index: int) -> str:
    current_line = lines[index]
    prev_line = lines[index - 1] if index > 0 else ""
    for line in (current_line, prev_line):
        for pat in NAME_PATTERNS:
            found = pat.findall(line)
            if found:
                return found[0]
    return "unknown"


def score_email(email: str, name: str) -> float:
    score = 0.0
    domain = email.split("@", 1)[1]
    local_part = email.split("@", 1)[0]
    tld = domain.split(".")[-1]
    if 2 <= len(tld) <= 63:
        score += 0.3
    if re.fullmatch(r"[A-Za-z0-9._%+-]+", local_part):
        score += 0.2
    if all(label and not label.startswith("-") and not label.endswith("-") for label in domain.split(".")):
        score += 0.2
    if local_part.lower() not in {"noreply", "mailer-daemon", "no-reply", "donotreply"}:
        score += 0.15
    if name != "unknown":
        score += 0.15
    return round(min(score, 1.0), 2)


def score_phone(raw_phone: str, normalized_phone: str, line: str, name: str, *, international: bool) -> float:
    score = 0.0
    digits = re.sub(r"\D", "", normalized_phone)

    if international:
        if 8 <= len(digits) <= 15:
            score += 0.35
        if raw_phone.strip().startswith("+"):
            score += 0.25
        if any(c in raw_phone for c in "()-. "):
            score += 0.15
    else:
        if len(digits) == 10 or (len(digits) == 11 and digits.startswith("1")):
            score += 0.3
        if any(separator in raw_phone for separator in "()-. "):
            score += 0.25
        score += 0.15

    if any(word in line.lower() for word in PHONE_CONTEXT_WORDS):
        score += 0.15
    if name != "unknown":
        score += 0.1
    return round(min(score, 1.0), 2)


def _contact_row(
    name: str,
    email: str,
    phone: str,
    line_number: int,
    confidence: float,
) -> dict:
    return {
        "name_if_found": name,
        "email": email,
        "phone": phone,
        "source_line": line_number,
        "confidence_score": round(confidence, 2),
    }


def pair_contact_rows(
    email_rows: list[dict],
    phone_rows: list[dict],
    line_number: int,
    name: str,
) -> list[dict]:
    if not email_rows and not phone_rows:
        return []
    if not email_rows:
        return [_contact_row(name, "", p["phone"], line_number, p["confidence_score"]) for p in phone_rows]
    if not phone_rows:
        return [_contact_row(name, e["email"], "", line_number, e["confidence_score"]) for e in email_rows]
    if len(email_rows) == len(phone_rows):
        return [
            _contact_row(
                name,
                e["email"],
                p["phone"],
                line_number,
                round((e["confidence_score"] + p["confidence_score"]) / 2, 2),
            )
            for e, p in zip(email_rows, phone_rows)
        ]
    rows = [_contact_row(name, e["email"], "", line_number, e["confidence_score"]) for e in email_rows]
    rows.extend(_contact_row(name, "", p["phone"], line_number, p["confidence_score"]) for p in phone_rows)
    return rows


def rows_to_csv(rows: list[dict]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(["name_if_found", "email", "phone", "source_line", "confidence_score"])
    for row in rows:
        writer.writerow(
            [
                row["name_if_found"],
                row["email"],
                row["phone"],
                row["source_line"],
                f"{row['confidence_score']:.2f}",
            ]
        )
    return buffer.getvalue()


def _phone_dedupe_key(normalized: str) -> str:
    return re.sub(r"\D", "", normalized)


def run(input_text: str, config: dict | None = None) -> dict:
    config = config or {}
    sanitized_result = string_sanitizer.run(input_text, {"source_name": config.get("source_name", "<input>")})
    cleaned_text = sanitized_result["output"]
    lines = cleaned_text.splitlines()
    min_confidence = float(config.get("min_confidence", 0.0))
    progress_callback = config.get("progress_callback")

    rows = []
    rejected = []
    seen_emails: dict[str, int] = {}
    seen_phones: dict[str, int] = {}
    counts = Counter()

    for index, line in enumerate(lines, start=1):
        if progress_callback and index % 100 == 0:
            progress_callback(index)

        name = find_name(lines, index - 1)
        valid_emails: list[dict] = []
        valid_phones: list[dict] = []

        for candidate in EMAIL_PATTERN.findall(line):
            is_valid, reason = validate_email(candidate)
            if not is_valid:
                rejected.append(
                    {
                        "severity": "medium",
                        "category": "rejected_email",
                        "line": index,
                        "message": f"{candidate} rejected: {reason}",
                    }
                )
                counts["rejected"] += 1
                continue

            if candidate.lower() in seen_emails:
                rejected.append(
                    {
                        "severity": "low",
                        "category": "duplicate_email",
                        "line": index,
                        "message": f"{candidate} duplicates line {seen_emails[candidate.lower()]}.",
                    }
                )
                counts["duplicates"] += 1
                continue

            confidence = score_email(candidate, name)
            if confidence < min_confidence:
                rejected.append(
                    {
                        "severity": "low",
                        "category": "low_confidence_email",
                        "line": index,
                        "message": f"{candidate} fell below min confidence ({confidence:.2f} < {min_confidence:.2f}).",
                    }
                )
                counts["rejected"] += 1
                continue

            valid_emails.append({"email": candidate, "confidence_score": confidence})
            seen_emails[candidate.lower()] = index
            counts["emails"] += 1

        for candidate in collect_phone_candidates(line):
            ok, normalized, reason, international = try_normalize_phone(candidate)
            if not ok:
                rejected.append(
                    {
                        "severity": "medium",
                        "category": "rejected_phone",
                        "line": index,
                        "message": f"{candidate} rejected: {reason}",
                    }
                )
                counts["rejected"] += 1
                continue

            phone_key = _phone_dedupe_key(normalized)
            if phone_key in seen_phones:
                rejected.append(
                    {
                        "severity": "low",
                        "category": "duplicate_phone",
                        "line": index,
                        "message": f"{normalized} duplicates line {seen_phones[phone_key]}.",
                    }
                )
                counts["duplicates"] += 1
                continue

            confidence = score_phone(candidate, normalized, line, name, international=international)
            if confidence < min_confidence:
                rejected.append(
                    {
                        "severity": "low",
                        "category": "low_confidence_phone",
                        "line": index,
                        "message": f"{normalized} fell below min confidence ({confidence:.2f} < {min_confidence:.2f}).",
                    }
                )
                counts["rejected"] += 1
                continue

            valid_phones.append({"phone": normalized, "confidence_score": confidence})
            seen_phones[phone_key] = index
            counts["phones"] += 1

        if valid_emails or valid_phones:
            rows.extend(pair_contact_rows(valid_emails, valid_phones, index, name))

    average_confidence = round(
        sum(row["confidence_score"] for row in rows) / max(len(rows), 1),
        2,
    )

    findings = list(sanitized_result["findings"])
    if config.get("show_rejected"):
        findings.extend(rejected)
    else:
        findings.extend(rejected[:10])

    stats = {
        "lines_processed": len(lines),
        "total_rows": len(rows),
        "emails_found": counts["emails"],
        "phones_found": counts["phones"],
        "duplicates_removed": counts["duplicates"],
        "rejected_candidates": counts["rejected"],
        "average_confidence": average_confidence,
        "average_confidence_display": f"{average_confidence:.2f}",
    }

    summary = (
        f"Extracted {len(rows)} contact rows from {len(lines)} lines. "
        f"Found {counts['emails']} emails and {counts['phones']} phones."
    )

    return {
        "module_name": "contacts",
        "title": "DataGuard Contact Extraction Report",
        "output": rows_to_csv(rows),
        "rows": rows,
        "findings": findings,
        "warnings": [] if rows else ["No valid contacts were extracted."],
        "errors": [],
        "stats": stats,
        "metadata": {"source": config.get("source_name", "<input>"), "min_confidence": min_confidence},
        "summary": summary,
    }
