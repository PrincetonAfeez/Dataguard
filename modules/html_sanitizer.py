"""HTML and script sanitizer.

Uses regex and allowlists for practical cleanup of untrusted-ish markup. This is a triage helper, not a
replacement for a hardened HTML sanitizer, browser parsing, or security controls (e.g. CSP) for hostile input.
"""

from __future__ import annotations

import difflib
import html
import re
from html.parser import HTMLParser

# HTML comments (non-greedy; DOTALL so newlines inside comments match)
COMMENT_PATTERN = re.compile(r"<!--[\s\S]*?-->", re.IGNORECASE)
# Script: full blocks, empty/whitespace-only bodies, and XHTML-style self-closing
SCRIPT_PATTERN = re.compile(
    r"<script\b[^>]*\s*/\s*>|<script\b[^>]*>[\s\S]*?</script\s*>",
    re.IGNORECASE,
)
STYLE_PATTERN = re.compile(r"<style\b[^>]*>[\s\S]*?</style\s*>", re.IGNORECASE)
# Blocked containers + void-like dangerous tags (link can pull remote resources)
BLOCKED_TAGS_PATTERN = re.compile(
    r"<(?:iframe|object|embed|applet|form|base)\b[^>]*>[\s\S]*?</(?:iframe|object|embed|applet|form|base)\s*>"
    r"|<(?:iframe|object|embed|applet|form|base)\b[^>]*/?>"
    r"|<link\b[^>]*/?>",
    re.IGNORECASE,
)
META_REFRESH_PATTERN = re.compile(r"<meta\b[^>]*http-equiv\s*=\s*['\"]?refresh['\"]?[^>]*>", re.IGNORECASE)
CDATA_PATTERN = re.compile(r"<!\[CDATA\[[\s\S]*?\]\]>", re.IGNORECASE)
EVENT_HANDLER_PATTERN = re.compile(
    r"\s+on[a-z0-9_-]+\s*=\s*(?:\"[^\"]*\"|'[^']*'|`[^`]*`|[^\s>]+)",
    re.IGNORECASE,
)
STYLE_DANGER_PATTERN = re.compile(r"expression\s*\(|url\s*\(\s*javascript:|-moz-binding|behavior\s*:", re.IGNORECASE)
TAG_PATTERN = re.compile(r"<(?P<closing>/)?(?P<tag>[A-Za-z0-9]+)(?P<attrs>[^>]*)>", re.IGNORECASE | re.DOTALL)
ATTRIBUTE_PATTERN = re.compile(
    r"([^\s=<>'\"`/]+)(?:\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|`([^`]*)`|([^\s>]+)))?",
    re.DOTALL,
)

DEFAULT_SAFE_TAGS = {
    "p": [],
    "b": [],
    "i": [],
    "u": [],
    "strong": [],
    "em": [],
    "br": [],
    "hr": [],
    "ul": [],
    "ol": [],
    "li": [],
    "h1": [],
    "h2": [],
    "h3": [],
    "h4": [],
    "h5": [],
    "h6": [],
    "blockquote": [],
    "pre": [],
    "code": [],
    "a": ["href"],
    "img": ["src", "alt"],
}

SELF_CLOSING_TAGS = {"br", "hr", "img"}


def line_number_for_position(text: str, position: int) -> int:
    return text.count("\n", 0, max(position, 0)) + 1


def add_finding(findings: list[dict], text: str, position: int, category: str, severity: str, message: str) -> None:
    findings.append(
        {
            "severity": severity,
            "category": category,
            "line": line_number_for_position(text, position),
            "message": message,
        }
    )


def replace_pattern(
    text: str,
    pattern: re.Pattern[str],
    replacement: str,
    findings: list[dict],
    category: str,
    severity: str,
    message_template: str,
) -> str:
    def replacement_function(match: re.Match[str]) -> str:
        add_finding(
            findings,
            text,
            match.start(),
            category,
            severity,
            message_template.format(content=match.group(0)[:80]),
        )
        return replacement

    return pattern.sub(replacement_function, text)


def validate_url(raw_value: str, attribute_name: str) -> tuple[str, bool]:
    decoded = html.unescape(raw_value).replace("\x00", "").strip()
    compact = re.sub(r"\s+", "", decoded).lower()
    # Protocol-relative URLs: normalize for scheme checks (treated like https:)
    if compact.startswith("//"):
        compact = "https:" + compact
    allowed = ("http:", "https:", "mailto:")
    if compact.startswith(("javascript:", "data:", "vbscript:")):
        return "#removed", False
    if ":" in compact and not compact.startswith(allowed):
        return "#removed", False
    if attribute_name == "src" and compact.startswith("mailto:"):
        return "#removed", False
    return decoded, True


def sanitize_allowed_attributes(
    tag_name: str,
    raw_attrs: str,
    findings: list[dict],
    source_text: str,
    start_position: int,
    safe_tags: dict[str, list[str]],
) -> str:
    kept: list[str] = []
    allowed_attributes = safe_tags.get(tag_name, [])
    for match in ATTRIBUTE_PATTERN.finditer(raw_attrs):
        attribute_name = match.group(1).lower()
        raw_value = next((group for group in match.groups()[1:] if group is not None), "")
        if attribute_name.startswith("on"):
            add_finding(
                findings,
                source_text,
                start_position,
                "event_handler",
                "high",
                f"Removed event handler {attribute_name}.",
            )
            continue
        if attribute_name == "style":
            if STYLE_DANGER_PATTERN.search(raw_value):
                add_finding(
                    findings,
                    source_text,
                    start_position,
                    "css_attack",
                    "medium",
                    "Removed dangerous inline style content.",
                )
            else:
                add_finding(
                    findings,
                    source_text,
                    start_position,
                    "style_strip",
                    "low",
                    "Removed inline style attribute (not allowlisted in safe mode).",
                )
            continue
        if attribute_name not in allowed_attributes:
            if attribute_name not in {"", "/"}:
                add_finding(
                    findings,
                    source_text,
                    start_position,
                    "attribute_strip",
                    "low",
                    f"Removed attribute {attribute_name} from <{tag_name}>.",
                )
            continue
        if attribute_name in {"href", "src"}:
            safe_value, is_safe = validate_url(raw_value, attribute_name)
            if not is_safe:
                add_finding(
                    findings,
                    source_text,
                    start_position,
                    "dangerous_url",
                    "critical",
                    f"Replaced dangerous {attribute_name} value on <{tag_name}>.",
                )
            kept.append(f'{attribute_name}="{html.escape(safe_value, quote=True)}"')
            continue
        kept.append(f'{attribute_name}="{html.escape(raw_value, quote=True)}"')
    return (" " + " ".join(kept)) if kept else ""


def rebuild_safe_html(text: str, safe_tags: dict[str, list[str]], findings: list[dict]) -> str:
    def replacement_function(match: re.Match[str]) -> str:
        tag_name = match.group("tag").lower()
        closing = bool(match.group("closing"))
        raw_attrs = match.group("attrs") or ""
        if tag_name not in safe_tags:
            add_finding(findings, text, match.start(), "tag_strip", "low", f"Removed disallowed tag <{tag_name}>.")
            return ""
        if closing:
            return f"</{tag_name}>"
        safe_attrs = sanitize_allowed_attributes(tag_name, raw_attrs, findings, text, match.start(), safe_tags)
        if tag_name in SELF_CLOSING_TAGS:
            return f"<{tag_name}{safe_attrs}>"
        return f"<{tag_name}{safe_attrs}>"

    return TAG_PATTERN.sub(replacement_function, text)


class _StripTagsParser(HTMLParser):
    """Emit only text nodes; skips script/style rawtext (handled earlier by regex passes)."""

    __slots__ = ("_chunks",)

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._chunks: list[str] = []

    def handle_data(self, data: str) -> None:
        self._chunks.append(data)


def strip_all_tags(text: str) -> str:
    """Strip markup using html.parser for quoted '>' in attributes; regex fallback on parse failure."""
    parser = _StripTagsParser()
    try:
        parser.feed(text)
        parser.close()
    except Exception:
        return html.unescape(re.sub(r"<[^>]+>", "", text))
    return "".join(parser._chunks)


def unified_diff_snippet(before: str, after: str, max_lines: int = 500) -> str:
    """Build a unified diff for reports; truncates very large diffs."""
    diff_iter = difflib.unified_diff(
        before.splitlines(keepends=True),
        after.splitlines(keepends=True),
        fromfile="input",
        tofile="output",
        n=3,
    )
    lines = list(diff_iter)
    total = len(lines)
    if total > max_lines:
        lines = lines[:max_lines]
        lines.append(f"... ({total - max_lines} more diff lines omitted)\n")
    return "".join(lines)


def danger_score(findings: list[dict]) -> int:
    weights = {"critical": 25, "high": 15, "medium": 8, "low": 2, "info": 1}
    return min(sum(weights.get(item.get("severity", "info"), 1) for item in findings), 100)


def sanitize_html(
    input_text: str,
    mode: str = "plain",
    allowed_tags: list[str] | None = None,
) -> tuple[str, list[dict], dict]:
    findings: list[dict] = []
    safe_tags: dict[str, list[str]] = DEFAULT_SAFE_TAGS.copy()
    if allowed_tags is not None:
        # Tags not in DEFAULT_SAFE_TAGS are allowed with no attributes (empty allowlist).
        safe_tags = {tag: DEFAULT_SAFE_TAGS.get(tag, []) for tag in allowed_tags if tag}

    text = input_text
    decoded = html.unescape(text)
    if decoded != text:
        findings.append(
            {"severity": "low", "category": "entity_decode", "line": 1, "message": "Decoded HTML entities before scanning."}
        )
        text = decoded
    if "\x00" in text:
        findings.append(
            {"severity": "medium", "category": "null_byte", "line": 1, "message": "Removed null bytes used for obfuscation."}
        )
        text = text.replace("\x00", "")

    previous = None
    loop_count = 0
    while text != previous and loop_count < 5:
        previous = text
        loop_count += 1
        text = replace_pattern(text, COMMENT_PATTERN, "", findings, "comment", "low", "Removed HTML comment: {content}")
        text = replace_pattern(text, CDATA_PATTERN, "", findings, "cdata", "medium", "Removed CDATA section: {content}")
        text = replace_pattern(text, SCRIPT_PATTERN, "", findings, "script_tag", "critical", "Removed script tag and contents: {content}")
        text = replace_pattern(text, STYLE_PATTERN, "", findings, "style_block", "medium", "Removed style block: {content}")
        text = replace_pattern(text, BLOCKED_TAGS_PATTERN, "", findings, "blocked_tag", "critical", "Removed blocked tag: {content}")
        text = replace_pattern(text, META_REFRESH_PATTERN, "", findings, "meta_refresh", "critical", "Removed meta refresh tag: {content}")
        text = replace_pattern(
            text,
            EVENT_HANDLER_PATTERN,
            "",
            findings,
            "event_handler_attr",
            "high",
            "Removed inline event handler: {content}",
        )

    if mode == "safe":
        output = rebuild_safe_html(text, safe_tags, findings)
    else:
        output = strip_all_tags(text)

    stats = {
        "mode": mode,
        "before_characters": len(input_text),
        "after_characters": len(output),
        "characters_removed": max(len(input_text) - len(output), 0),
        "danger_score": danger_score(findings),
        "passes": loop_count,
    }
    return output, findings, stats


def run(input_text: str, config: dict | None = None) -> dict:
    config = config or {}
    mode = config.get("mode", "plain")
    allowed_tags = config.get("allowed_tags")
    show_diff = bool(config.get("show_diff"))
    output, findings, stats = sanitize_html(input_text, mode=mode, allowed_tags=allowed_tags)

    summary = (
        f"Sanitized HTML in {mode} mode. Removed {stats['characters_removed']} characters "
        f"with danger score {stats['danger_score']}."
    )

    result: dict = {
        "module_name": "html",
        "title": "DataGuard HTML Sanitizer Report",
        "output": output,
        "findings": findings,
        "warnings": [] if not findings else [f"Removed or modified {len(findings)} HTML threat indicators."],
        "errors": [],
        "stats": stats,
        "metadata": {"source": config.get("source_name", "<input>"), "mode": mode, "show_diff": show_diff},
        "summary": summary,
    }
    if show_diff:
        result["diff"] = {
            "unified": unified_diff_snippet(input_text, output),
            "before_characters": len(input_text),
            "after_characters": len(output),
        }
    return result
