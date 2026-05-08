"""Server log parser and analyzer.

Threat-style findings use pattern heuristics for triage and exploration. They are not a substitute for a SIEM,
IDS/IPS, WAF, or structured security review.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from dataguard.formatter import format_table

# Regex for standard Apache Combined Log Format
APACHE_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<url>\S+)(?:\s+HTTP/\d\.\d)?"\s+(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)

# Regex for standard Nginx log format (very similar to Apache but often has minor spacing differences)
NGINX_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+-\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<url>\S+)(?:\s+HTTP/\d\.\d)?"\s+(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)

# Fallback: same line only, bounded gaps between fields to reduce mis-parsing on noisy lines
GENERIC_PATTERN = re.compile(
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
    r".{0,240}?"
    r"(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+"
    r"(?P<url>\S+)"
    r".{0,240}?"
    r"(?P<status>(?<![0-9])\d{3}(?![0-9]))"
    r".{0,120}?"
    r"(?P<size>\d+|-)(?:\s|$)"
)

HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
SCANNER_SIGNATURES = {"nikto", "sqlmap", "nmap", "dirbuster", "acunetix", "masscan"}
PATH_TRAVERSAL_PATTERN = re.compile(r"\.\./|\.\.%2f|/etc/passwd|/proc/self", re.IGNORECASE)
SQLI_PATTERN = re.compile(r"(?:union\s+select|or\s+1=1|drop\s+table|--)", re.IGNORECASE)
LOGIN_PATH_PATTERN = re.compile(r"/(?:login|auth|signin|wp-login)", re.IGNORECASE)

# Auto-detect scans non-empty, non-comment lines up to these limits
_DETECT_MAX_SCAN_LINES = 500
_DETECT_MAX_NONEMPTY_SAMPLE = 100


def normalize_log_client_ip(raw: str) -> str:
    """Strip brackets from IPv6 literals as logged by some servers (e.g. [::1])."""
    s = raw.strip()
    if len(s) >= 2 and s[0] == "[" and s[-1] == "]":
        return s[1:-1]
    return s


def valid_client_ip(raw: str) -> bool:
    """True if the field is a valid IPv4 or IPv6 address (after bracket normalization)."""
    try:
        ipaddress.ip_address(normalize_log_client_ip(raw))
        return True
    except ValueError:
        return False


def parse_timestamp(raw_timestamp: str) -> datetime | None:
    """Parse common access-log timestamp shapes; returns naive UTC/local-comparable datetime."""
    s = raw_timestamp.strip()
    if not s:
        return None

    def _naive(dt: datetime) -> datetime:
        if dt.tzinfo is not None:
            return dt.replace(tzinfo=None)
        return dt

    formats = (
        "%d/%b/%Y:%H:%M:%S %z",
        "%d/%b/%Y:%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
    )
    for fmt in formats:
        try:
            return _naive(datetime.strptime(s, fmt))
        except ValueError:
            continue

    try:
        iso = s.replace("Z", "+00:00")
        return _naive(datetime.fromisoformat(iso))
    except ValueError:
        pass

    return None


def sample_lines_for_detection(lines: list[str]) -> list[str]:
    """Skip blanks and # comments; cap scan depth and sample size for stable format detection."""
    sampled: list[str] = []
    scanned = 0
    for line in lines:
        scanned += 1
        if scanned > _DETECT_MAX_SCAN_LINES:
            break
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        sampled.append(line)
        if len(sampled) >= _DETECT_MAX_NONEMPTY_SAMPLE:
            break
    return sampled


def detect_format(lines: list[str]) -> str:
    sample = sample_lines_for_detection(lines)
    if not sample:
        return "generic"
    apache_hits = sum(1 for line in sample if APACHE_PATTERN.search(line))
    nginx_hits = sum(1 for line in sample if NGINX_PATTERN.search(line))
    generic_hits = sum(1 for line in sample if GENERIC_PATTERN.search(line))
    if apache_hits >= nginx_hits and apache_hits >= generic_hits:
        return "apache"
    if nginx_hits >= generic_hits:
        return "nginx"
    return "generic"


def parse_line(line: str, log_format: str) -> dict | None:
    pattern = {
        "apache": APACHE_PATTERN,
        "nginx": NGINX_PATTERN,
        "generic": GENERIC_PATTERN,
    }.get(log_format, APACHE_PATTERN)
    match = pattern.search(line)
    if not match:
        return None
    data = match.groupdict()
    data.setdefault("referer", "-")
    data.setdefault("agent", "-")
    return data


def coerce_parsed_fields(entry: dict) -> dict | None:
    """Validate status and size; return normalized entry dict or None if fields are not usable."""
    status_raw = entry.get("status", "")
    size_raw = entry.get("size", "")
    if not isinstance(status_raw, str) or len(status_raw) != 3 or not status_raw.isdigit():
        return None
    status_code = int(status_raw)

    if size_raw == "-":
        response_size = 0
    elif isinstance(size_raw, str) and size_raw.isdigit():
        response_size = int(size_raw)
    else:
        return None

    out = dict(entry)
    out["status"] = status_code
    out["response_size"] = response_size
    return out


def add_threat(findings: list[dict], line_number: int, category: str, severity: str, ip_address: str, message: str) -> None:
    findings.append(
        {
            "severity": severity,
            "category": category,
            "line": line_number,
            "ip": ip_address,
            "message": message,
        }
    )


def add_threat_deduped(
    findings: list[dict],
    seen_keys: set[tuple],
    line_number: int,
    category: str,
    severity: str,
    ip_address: str,
    message: str,
    *,
    url: str | None = None,
    method: str | None = None,
    status_code: int | None = None,
) -> None:
    """Append a threat once per logical key so busy IPs do not flood the report."""
    if category in ("rapid_fire", "brute_force", "scanner_fingerprint", "invalid_ip"):
        key: tuple = (category, ip_address)
    elif category in ("path_traversal", "sql_injection_probe"):
        key = (category, ip_address, url or "")
    elif category == "invalid_method":
        key = (category, ip_address, method or "")
    elif category == "invalid_status":
        key = (category, ip_address, status_code if status_code is not None else -1)
    else:
        key = (category, line_number, message)
    if key in seen_keys:
        return
    seen_keys.add(key)
    add_threat(findings, line_number, category, severity, ip_address, message)


def render_output_summary(
    stats: dict,
    top_ips: list[tuple[str, int]],
    top_urls: list[tuple[str, int]],
    findings: list[dict],
    top_n: int,
    threats_only: bool,
) -> str:
    sections = []
    if findings:
        threat_rows = [
            [item.get("severity", ""), item.get("category", ""), item.get("ip", ""), item.get("message", "")]
            for item in findings[: max(top_n, 5)]
        ]
        sections.append("Threat Alerts")
        sections.append(format_table(["Severity", "Category", "IP", "Message"], threat_rows))
    elif threats_only:
        sections.append("No threats detected.")

    if threats_only:
        return "\n\n".join(sections)

    sections.append("")
    sections.append("Overview")
    sections.append(f"Requests parsed: {stats['parsed_lines']}/{stats['total_lines']} ({stats['parse_rate']})")
    sections.append(f"Error rate: {stats['error_rate']}")

    if top_ips:
        sections.append("")
        sections.append("Top IPs")
        sections.append(format_table(["IP", "Requests"], [[ip_address, count] for ip_address, count in top_ips[:top_n]]))

    if top_urls:
        sections.append("")
        sections.append("Top URLs")
        sections.append(format_table(["URL", "Hits"], [[url, count] for url, count in top_urls[:top_n]]))

    return "\n".join(section for section in sections if section is not None)


def run(input_text: str, config: dict | None = None) -> dict:
    config = config or {}
    lines = input_text.splitlines()
    forced_format = config.get("format", "auto")
    log_format = forced_format if forced_format and forced_format != "auto" else detect_format(lines)
    top_n = int(config.get("top", 10))

    parsed_entries: list[dict] = []
    parse_failures: list[dict] = []
    status_counts: Counter[str] = Counter()
    status_bands: Counter[str] = Counter()
    ip_counter: Counter[str] = Counter()
    url_counter: Counter[str] = Counter()
    window_by_ip: defaultdict[str, list[datetime]] = defaultdict(list)
    login_windows: defaultdict[str, list[datetime]] = defaultdict(list)
    findings: list[dict] = []
    threat_dedupe_keys: set[tuple] = set()

    for line_number, line in enumerate(lines, start=1):
        raw_entry = parse_line(line, log_format)
        if not raw_entry:
            parse_failures.append({"line": line_number, "raw": line})
            continue

        coerced = coerce_parsed_fields(raw_entry)
        if not coerced:
            parse_failures.append({"line": line_number, "raw": line})
            continue

        ip_raw = coerced["ip"]
        ip_address = normalize_log_client_ip(ip_raw)
        method = coerced["method"]
        url = coerced["url"]
        status_code = coerced["status"]
        response_size = coerced["response_size"]
        agent = coerced.get("agent") or "-"
        timestamp = parse_timestamp(coerced.get("timestamp", "") or "")

        parsed_entries.append(
            {
                "line": line_number,
                "ip": ip_address,
                "timestamp": timestamp.isoformat() if timestamp else "",
                "method": method,
                "url": url,
                "status": status_code,
                "response_size": response_size,
                "agent": agent,
            }
        )

        if not valid_client_ip(ip_raw):
            add_threat_deduped(
                findings,
                threat_dedupe_keys,
                line_number,
                "invalid_ip",
                "medium",
                ip_address,
                f"Client field is not a valid IPv4/IPv6 address after normalization: {ip_raw!r}.",
            )

        if method not in HTTP_METHODS:
            add_threat_deduped(
                findings,
                threat_dedupe_keys,
                line_number,
                "invalid_method",
                "medium",
                ip_address,
                f"Non-standard HTTP method {method}.",
                method=method,
            )

        if not 100 <= status_code <= 599:
            add_threat_deduped(
                findings,
                threat_dedupe_keys,
                line_number,
                "invalid_status",
                "medium",
                ip_address,
                f"Status code {status_code} is outside 100-599.",
                status_code=status_code,
            )

        status_counts[str(status_code)] += 1
        status_bands[f"{status_code // 100}xx"] += 1
        ip_counter[ip_address] += 1
        url_counter[url] += 1

        if PATH_TRAVERSAL_PATTERN.search(url):
            add_threat_deduped(
                findings,
                threat_dedupe_keys,
                line_number,
                "path_traversal",
                "high",
                ip_address,
                f"Path traversal probe in URL {url}.",
                url=url,
            )

        if SQLI_PATTERN.search(url):
            add_threat_deduped(
                findings,
                threat_dedupe_keys,
                line_number,
                "sql_injection_probe",
                "high",
                ip_address,
                f"SQL injection probe in URL {url}.",
                url=url,
            )

        if any(signature in agent.lower() for signature in SCANNER_SIGNATURES):
            add_threat_deduped(
                findings,
                threat_dedupe_keys,
                line_number,
                "scanner_fingerprint",
                "medium",
                ip_address,
                f"Scanner-like user agent {agent!r}.",
            )

        if timestamp:
            recent_requests = window_by_ip[ip_address]
            recent_requests.append(timestamp)
            cutoff = timestamp - timedelta(seconds=60)
            window_by_ip[ip_address] = [item for item in recent_requests if item >= cutoff]
            if len(window_by_ip[ip_address]) >= 50:
                add_threat_deduped(
                    findings,
                    threat_dedupe_keys,
                    line_number,
                    "rapid_fire",
                    "high",
                    ip_address,
                    "50+ requests from the same IP inside 60 seconds.",
                )

            if LOGIN_PATH_PATTERN.search(url):
                login_requests = login_windows[ip_address]
                login_requests.append(timestamp)
                login_cutoff = timestamp - timedelta(seconds=60)
                login_windows[ip_address] = [item for item in login_requests if item >= login_cutoff]
                if len(login_windows[ip_address]) >= 10:
                    add_threat_deduped(
                        findings,
                        threat_dedupe_keys,
                        line_number,
                        "brute_force",
                        "high",
                        ip_address,
                        "10+ login/auth requests inside 60 seconds.",
                    )

    parse_rate = f"{(len(parsed_entries) / max(len(lines), 1)) * 100:.1f}%"
    error_requests = sum(count for code, count in status_counts.items() if code.startswith("4") or code.startswith("5"))
    error_rate = f"{(error_requests / max(len(parsed_entries), 1)) * 100:.1f}%"

    stats = {
        "format": log_format,
        "total_lines": len(lines),
        "parsed_lines": len(parsed_entries),
        "unparseable_lines": len(parse_failures),
        "parse_rate": parse_rate,
        "error_rate": error_rate,
        "2xx": status_bands["2xx"],
        "3xx": status_bands["3xx"],
        "4xx": status_bands["4xx"],
        "5xx": status_bands["5xx"],
    }

    findings.extend(
        {
            "severity": "low",
            "category": "parse_failure",
            "line": failure["line"],
            "message": f"Could not parse line {failure['line']}.",
        }
        for failure in parse_failures[:20]
    )

    output_text = render_output_summary(
        stats,
        ip_counter.most_common(top_n),
        url_counter.most_common(top_n),
        findings,
        top_n,
        bool(config.get("threats_only")),
    )

    alert_count = len([item for item in findings if item["category"] != "parse_failure"])
    summary = (
        f"Parsed {len(parsed_entries)} of {len(lines)} log lines as {log_format}. "
        f"Detected {alert_count} alerts."
    )

    return {
        "module_name": "logs",
        "title": "DataGuard Log Analysis Report",
        "output": output_text,
        "entries": parsed_entries,
        "findings": findings,
        "warnings": [f"{len(parse_failures)} lines could not be parsed."] if parse_failures else [],
        "errors": [],
        "stats": stats,
        "metadata": {"source": config.get("source_name", "<input>"), "format": log_format, "top": top_n},
        "summary": summary,
    }
