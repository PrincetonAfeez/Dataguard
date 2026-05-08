"""Password strength analyzer.

Scores passwords with length, character diversity, an offline common-password list (with composition checks),
simple sequences/repeats, US QWERTY keyboard walks, and a naive bit estimate that assumes uniform random choice
from detected character classes — it is not NIST SP 800-63B verification and not true guessing entropy for
human-chosen secrets.

Security: ``analyze_password`` / ``run`` return structures and ``--export`` JSON contain full plaintext passwords;
do not log, commit, or share those outputs.
"""

# Enable postponed evaluation of type annotations for cleaner type hinting
from __future__ import annotations

# Import standard libraries for math and string/regex for pattern matching
import math
import re
import string
import unicodedata

# Import the pre-defined list of the world's most common compromised passwords
from dataguard.common_passwords import COMMON_PASSWORDS
# Import the table formatter for clean, human-readable reporting
from dataguard.formatter import format_table


# Define common physical keyboard layouts to detect "keyboard walks" like 'qwerty'
KEYBOARD_ROWS = ["1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"]
# Map common "Leet Speak" substitutions back to English characters for deep dictionary checking
LEET_MAP = str.maketrans({"@": "a", "4": "a", "3": "e", "1": "i", "0": "o", "$": "s", "5": "s", "7": "t"})
# Composite heuristic score bands — not a compliance certification or NIST verifier outcome
GRADE_BANDS = [
    (85, "Fortress"),
    (70, "Strong"),
    (50, "Fair"),
    (30, "Weak"),
    (0, "Terrible"),
]

# Lowercased set for O(1) lookups in dictionary checks (built once at import)
_COMMON_PASSWORDS_LOWER: frozenset[str] = frozenset(entry.lower() for entry in COMMON_PASSWORDS)


# Letters-only skeleton (non-letters stripped) to catch p.a.s.s.w.o.r.d123-style separators around a common root
def _letter_skeleton(s: str) -> str:
    return re.sub(r"[^a-z]+", "", s.lower())


# Precomputed skeletons for dictionary entries with enough letters to be meaningful (>= 4)
_COMMON_SKELETONS: frozenset[str] = frozenset(
    sk for sk in (_letter_skeleton(c) for c in _COMMON_PASSWORDS_LOWER) if len(sk) >= 4
)


# True if Levenshtein distance is at most 1 (insert / delete / substitute one code unit)
def _within_one_edit(a: str, b: str) -> bool:
    if a == b:
        return True
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        return sum(1 for i in range(la) if a[i] != b[i]) <= 1
    if la > lb:
        a, b = b, a
        la, lb = lb, la
    # Shorter in `a`, longer in `b`: at most one extra code unit in `b`
    i = j = 0
    skips = 0
    while i < la and j < lb:
        if a[i] == b[j]:
            i += 1
            j += 1
        else:
            skips += 1
            if skips > 1:
                return False
            j += 1
    if j < lb:
        skips += lb - j
    return i == la and skips <= 1


# Hide the password characters (masking) for security unless the user explicitly requests to see them
def mask_password(password: str, show_password: bool) -> str:
    if show_password:
        return password
    if not password:
        return "<empty>"
    if len(password) <= 2:
        return "*" * len(password)
    # Show only the first and last characters to provide context without revealing the secret
    return password[0] + "*" * (len(password) - 2) + password[-1]


# Lowercase the password and undo common "Leet Speak" (e.g., 'P4ssword' becomes 'password')
def normalized_password(password: str) -> str:
    return password.lower().translate(LEET_MAP)


# Yield lowercase variants after repeatedly stripping weak trailing digits and punctuation (composition check)
def _weak_suffix_variants(s: str) -> set[str]:
    seen: set[str] = set()
    cur = s
    for _ in range(8):
        if cur in seen:
            break
        seen.add(cur)
        nxt = re.sub(r"[\d!@#$%^&*()_+=\[\]{}|\\;:,.<>?/~`'-]+$", "", cur)
        if nxt == cur or not nxt:
            break
        cur = nxt
    return seen


# Score the password based on its length relative to a target minimum
def check_length(password: str, min_length: int) -> dict:
    length = len(password)
    # Give max points for 20+ characters; otherwise, scale points based on the target length
    if length >= 20:
        points = 20
    elif length >= min_length:
        points = min(20, 12 + (length - min_length) * 1.0)
    else:
        points = max(0, int((length / max(min_length, 1)) * 12))
    return {
        "name": "length",
        "points": int(points),
        "max_points": 20,
        "passed": length >= min_length,
        "details": f"Length is {length}; minimum target is {min_length}.",
        "feedback": f"Add at least {max(min_length - length, 0)} more characters." if length < min_length else "Good length coverage.",
    }


def _has_ascii_lower(password: str) -> bool:
    return bool(re.search(r"[a-z]", password))


def _has_ascii_upper(password: str) -> bool:
    return bool(re.search(r"[A-Z]", password))


def _has_unicode_letter(password: str) -> bool:
    return any(not ch.isascii() and unicodedata.category(ch).startswith("L") for ch in password)


def _has_digit(password: str) -> bool:
    return bool(re.search(r"\d", password))


def _has_symbol(password: str) -> bool:
    if re.search(rf"[{re.escape(string.punctuation)}]", password):
        return True
    return any(unicodedata.category(ch).startswith(("S", "P")) for ch in password if not ch.isalnum())


# Check for the presence of different character types (Upper, Lower, Number, Symbol)
def check_diversity(password: str) -> dict:
    # Include non-ASCII letters so Unicode passwords are not falsely penalized for "missing" Latin classes
    classes = {
        "lowercase": _has_ascii_lower(password) or _has_unicode_letter(password),
        "uppercase": _has_ascii_upper(password),
        "digits": _has_digit(password),
        "symbols": _has_symbol(password),
    }
    class_count = sum(classes.values())
    # Award 5 points for every unique class used (max 20)
    points = class_count * 5
    missing = [name for name, present in classes.items() if not present]
    return {
        "name": "diversity",
        "points": points,
        "max_points": 20,
        "passed": class_count >= 3,
        "details": (
            f"Uses {class_count} character classes "
            '("lowercase" here means Latin a-z or any Unicode letter; other classes are uppercase, digits, symbols).'
        ),
        "feedback": "Add " + ", ".join(missing[:2]) + "." if missing else "Good character diversity.",
    }


# Compare the password (and its leet-speak variant) against a database of common passwords
def check_dictionary(password: str) -> dict:
    lowered = password.lower()
    leet_normalized = normalized_password(password)
    common_set = _COMMON_PASSWORDS_LOWER
    # Fail if the password is found in the "Top Compromised" list
    if lowered in common_set or leet_normalized in common_set:
        return {
            "name": "dictionary",
            "points": 0,
            "max_points": 20,
            "passed": False,
            "details": "Exact match to a built-in common password (case-insensitive or leet-normalized).",
            "feedback": "Choose something less common than a top-list password.",
        }

    # Strip trailing digits/symbols and test again (e.g. qwerty123!, Passw0rd!!)
    for variant in _weak_suffix_variants(lowered) | _weak_suffix_variants(leet_normalized):
        if variant in common_set:
            return {
                "name": "dictionary",
                "points": 0,
                "max_points": 20,
                "passed": False,
                "details": "Matches a common password after stripping trailing digits/symbols.",
                "feedback": "Avoid common roots with only numbers or punctuation added at the end.",
            }

    # Short passwords that start with a long common root (e.g. password99)
    for common in common_set:
        if len(common) < 4:
            continue
        if lowered.startswith(common) and len(lowered) <= len(common) + 6:
            return {
                "name": "dictionary",
                "points": 0,
                "max_points": 20,
                "passed": False,
                "details": f"Starts with common password {common!r} with only a short suffix.",
                "feedback": "Do not prefix or extend a well-known password with a few extra characters.",
            }
        if leet_normalized.startswith(common) and len(leet_normalized) <= len(common) + 6:
            return {
                "name": "dictionary",
                "points": 0,
                "max_points": 20,
                "passed": False,
                "details": f"Leet-normalized form starts with common password {common!r} with a short suffix.",
                "feedback": "Do not prefix or extend a well-known password with a few extra characters.",
            }

    # Embedded common core in a still-short password (e.g. xpasswordx with tight length bound)
    for common in common_set:
        if len(common) < 6:
            continue
        if common in lowered and len(lowered) <= len(common) + 4:
            return {
                "name": "dictionary",
                "points": 0,
                "max_points": 20,
                "passed": False,
                "details": f"Contains common password {common!r} in a short overall string.",
                "feedback": "Avoid embedding a top-list password inside a slightly longer guess.",
            }

    # Same letters as a common password with punctuation/digits only between (e.g. p.a.s.s.w.o.r.d)
    for candidate_form in (lowered, leet_normalized):
        sk = _letter_skeleton(candidate_form)
        # Allow roughly one non-letter between letters (2*L-1) plus a short trailing tail
        if sk in _COMMON_SKELETONS and len(candidate_form) <= 2 * len(sk) + 3:
            return {
                "name": "dictionary",
                "points": 0,
                "max_points": 20,
                "passed": False,
                "details": "Letter-only skeleton matches a common password (non-letters were ignored for this check).",
                "feedback": "Do not spell a common password with extra punctuation or digits between letters.",
            }

    # Single typo / extra character vs a short common password (bounded length to limit false positives)
    if len(lowered) <= 14:
        for common in common_set:
            if not (4 <= len(common) <= 12):
                continue
            if _within_one_edit(lowered, common) or _within_one_edit(leet_normalized, common):
                return {
                    "name": "dictionary",
                    "points": 0,
                    "max_points": 20,
                    "passed": False,
                    "details": f"Within one character edit of common password {common!r} (insert/delete/substitute).",
                    "feedback": "Avoid passwords that are one typo away from a top-list password.",
                }

    passed = True
    return {
        "name": "dictionary",
        "points": 20 if passed else 0,
        "max_points": 20,
        "passed": passed,
        "details": (
            "Compared against built-in common passwords: exact/leet, trailing strip, prefix/short-embed, "
            "letter-skeleton, and at-most-1-edit matches (short passwords vs short dictionary entries)."
        ),
        "feedback": "Good: no common dictionary matches found." if passed else "Choose something less common than a top-list password.",
    }


# Find predictable character runs like 'abc', '123', or 'cba'
def detect_sequences(password: str) -> list[str]:
    sequences = []
    lowered = password.lower()
    # Sliding window of 3 characters to check for mathematical progression in character codes
    for index in range(len(lowered) - 2):
        chunk = lowered[index : index + 3]
        if len(set(chunk)) == 1:
            continue
        diffs = [ord(chunk[position + 1]) - ord(chunk[position]) for position in range(2)]
        # If the distance between chars is consistently +1 or -1, it's a sequence
        if diffs == [1, 1] or diffs == [-1, -1]:
            sequences.append(chunk)
    return sequences


# Score based on the absence of predictable sequences
def check_sequences(password: str) -> dict:
    sequences = detect_sequences(password)
    passed = not sequences
    detail = "No ascending or descending 3-character sequences found." if passed else f"Found sequences: {', '.join(sequences[:3])}."
    feedback = "Avoid predictable runs like abc or 321." if not passed else "No simple sequences detected."
    return {
        "name": "sequences",
        "points": 10 if passed else 0,
        "max_points": 10,
        "passed": passed,
        "details": detail,
        "feedback": feedback,
    }


# Detect long streaks of the exact same character (e.g., 'aaaaa' or '111')
def check_repeats(password: str) -> dict:
    # Use regex backreference to find 3 or more of the same character in a row
    match = re.search(r"(.)\1{2,}", password)
    passed = match is None
    return {
        "name": "repeats",
        "points": 5 if passed else 0,
        "max_points": 5,
        "passed": passed,
        "details": "No repeated 3-character streaks found." if passed else f"Repeated streak {match.group(0)!r} is guessable.",
        "feedback": "Break up repeated characters like aaa or 111." if not passed else "No repeated streaks detected.",
    }


# Check if the user is "walking" across their keyboard (e.g., 'qwer' or '12345')
def detect_keyboard_patterns(password: str) -> list[str]:
    found = []
    lowered = password.lower()
    # Check each row of the keyboard against the password
    for row in KEYBOARD_ROWS:
        for window_size in range(3, min(6, len(row)) + 1):
            for index in range(len(row) - window_size + 1):
                chunk = row[index : index + window_size]
                # Check both forward (qwerty) and backward (ytrewq)
                if chunk in lowered or chunk[::-1] in lowered:
                    found.append(chunk)
    return found


# Score based on the absence of keyboard walks
def check_keyboard_patterns(password: str) -> dict:
    patterns = detect_keyboard_patterns(password)
    passed = not patterns
    return {
        "name": "keyboard_patterns",
        "points": 10 if passed else 0,
        "max_points": 10,
        "passed": passed,
        "details": "No obvious keyboard walks found." if passed else f"Found keyboard patterns like {patterns[0]!r}.",
        "feedback": "Avoid keyboard walks like qwerty or asdf." if not passed else "No keyboard walks detected.",
    }


# Calculate the total "alphabet size" available based on the characters used
def character_pool_size(password: str) -> int:
    # Heuristic pool for a naive uniform-random model — not a true password-guessing alphabet for humans
    pool_size = 0
    if _has_ascii_lower(password):
        pool_size += 26
    if _has_ascii_upper(password):
        pool_size += 26
    if _has_unicode_letter(password):
        pool_size += 96
    if _has_digit(password):
        pool_size += 10
    if _has_symbol(password):
        pool_size += max(len(string.punctuation), 33)
    return max(pool_size, 1)


# Naive bit estimate: assumes each character is chosen uniformly at random from the detected pool (usually false for humans)
def calculate_entropy(password: str) -> dict:
    pool_size = character_pool_size(password)
    entropy_bits = len(password) * math.log2(pool_size)
    # Threshold labels are informal bands on this naive metric only — not NIST SP 800-63B strength categories
    if entropy_bits >= 80:
        points = 15
        label = "Excellent (naive model)"
    elif entropy_bits >= 60:
        points = 12
        label = "Strong (naive model)"
    elif entropy_bits >= 40:
        points = 8
        label = "Moderate (naive model)"
    else:
        points = 3
        label = "Low (naive model)"
    return {
        "name": "entropy",
        "points": points,
        "max_points": 15,
        "passed": entropy_bits >= 40,
        "details": (
            f"Naive estimate ~{entropy_bits:.1f} bits if uniform over a pool of ~{pool_size} character types "
            f"({label}); real user-chosen passwords are often easier to guess than this suggests."
        ),
        "feedback": "Increase length and character variety to raise the naive score." if entropy_bits < 40 else "Naive uniform-random estimate looks healthy; still avoid predictable words.",
        "entropy_bits": round(entropy_bits, 1),
    }


# Convert the final numerical score (0-100) into a qualitative security grade
def grade_from_score(score: int) -> str:
    for threshold, label in GRADE_BANDS:
        if score >= threshold:
            return label
    return "Terrible"


# Identify the top 3 most helpful suggestions based on which rules lost the most points
def top_feedback(rule_results: list[dict]) -> list[str]:
    failed_rules = [rule for rule in rule_results if not rule["passed"]]
    # Sort by "point deficit" to prioritize fixing the biggest weaknesses first
    failed_rules.sort(key=lambda item: item["max_points"] - item["points"], reverse=True)
    return [rule["feedback"] for rule in failed_rules[:3]]


# Run all security rules against a single password string
def analyze_password(password: str, config: dict) -> dict:
    min_length = int(config.get("min_length", 8))
    include_dictionary = not config.get("no_dictionary", False)
    include_entropy = not config.get("no_entropy", False)

    # Initialize the results list with mandatory checks
    rule_results = [
        check_length(password, min_length),
        check_diversity(password),
    ]
    # Add the dictionary check if not disabled in the config
    if include_dictionary:
        rule_results.append(check_dictionary(password))
    else:
        rule_results.append(
            {
                "name": "dictionary",
                "points": 20,
                "max_points": 20,
                "passed": True,
                "details": "Dictionary check skipped by flag.",
                "feedback": "Dictionary check skipped.",
            }
        )
    # Add pattern-based checks
    rule_results.extend(
        [
            check_sequences(password),
            check_repeats(password),
            check_keyboard_patterns(password),
        ]
    )
    # Add the mathematical entropy check if not disabled
    if include_entropy:
        rule_results.append(calculate_entropy(password))
    else:
        rule_results.append(
            {
                "name": "entropy",
                "points": 15,
                "max_points": 15,
                "passed": True,
                "details": "Entropy calculation skipped by flag.",
                "feedback": "Entropy calculation skipped.",
                "entropy_bits": None,
            }
        )

    # Calculate final score and grade
    score = int(sum(rule["points"] for rule in rule_results))
    grade = grade_from_score(score)
    return {
        "password": password,
        "score": score,
        "grade": grade,
        "rules": rule_results,
        "feedback": top_feedback(rule_results),
        "entropy_bits": next((rule.get("entropy_bits") for rule in rule_results if rule["name"] == "entropy"), None),
    }


# Format the analysis of a single password for display in the terminal/UI
def render_single_analysis(analysis: dict, show_password: bool) -> str:
    lines = [
        f"Password: {mask_password(analysis['password'], show_password)}",
        f"Score: {analysis['score']}/100",
        f"Grade: {analysis['grade']}",
    ]
    if analysis["entropy_bits"] is not None:
        lines.append(f"Naive uniform-random estimate: {analysis['entropy_bits']:.1f} bits (see entropy rule details)")
    lines.append("")
    lines.append("Rule checks:")
    # Create a list of PASS/FAIL for every individual rule applied
    for rule in analysis["rules"]:
        status = "PASS" if rule["passed"] else "FAIL"
        lines.append(f"- {rule['name']}: {status} ({rule['points']}/{rule['max_points']})")
        lines.append(f"  {rule['details']}")
    # Append the actionable advice section
    if analysis["feedback"]:
        lines.append("")
        lines.append("Top advice:")
        for item in analysis["feedback"]:
            lines.append(f"- {item}")
    return "\n".join(lines)


# Format a bulk analysis into a clean table for auditing multiple passwords at once
def render_batch_analysis(analyses: list[dict], show_password: bool) -> str:
    rows = []
    for analysis in analyses:
        top_issue = analysis["feedback"][0] if analysis["feedback"] else "Looks healthy."
        rows.append(
            [
                mask_password(analysis["password"], show_password),
                analysis["score"],
                analysis["grade"],
                top_issue,
            ]
        )
    return format_table(["Password", "Score", "Grade", "Top issue"], rows)


def _audit_warnings(analyses: list[dict], below_fair: list[dict]) -> list[str]:
    """Human-facing warnings aligned with module docstring and export metadata."""
    warnings: list[str] = []
    if below_fair:
        warnings.append(f"{len(below_fair)} password(s) scored Weak or Terrible.")
    if analyses:
        warnings.append(
            "Structured output (analyses and --export JSON) includes full plaintext passwords; "
            "do not log, commit, or share those outputs."
        )
    return warnings


# Main pipeline entry point for the password audit module
def run(input_text: str, config: dict | None = None) -> dict:
    config = config or {}
    # Determine if we are checking a single manual string or a file full of passwords
    if config.get("single_password") is not None:
        passwords = [config["single_password"]]
    else:
        passwords = [line.rstrip("\n") for line in input_text.splitlines() if line.strip()]

    # Analyze every password in the list
    analyses = [analyze_password(password, config) for password in passwords]
    # Pick the appropriate renderer (Single vs Batch)
    output = render_single_analysis(analyses[0], bool(config.get("show_password"))) if len(analyses) == 1 else render_batch_analysis(analyses, bool(config.get("show_password")))

    # Calculate overall audit statistics
    below_fair = [analysis for analysis in analyses if analysis["grade"] in {"Terrible", "Weak"}]
    # Tie-break weakest by earliest line index so the result is stable when scores match
    if analyses:
        weakest_index, weakest = min(enumerate(analyses), key=lambda item: (item[1]["score"], item[0]))
    else:
        weakest_index, weakest = -1, None
    average_score = round(sum(item["score"] for item in analyses) / max(len(analyses), 1), 1)

    # Generate security findings for passwords that failed the audit
    findings = []
    for index, analysis in enumerate(analyses, start=1):
        if analysis["grade"] in {"Terrible", "Weak"}:
            findings.append(
                {
                    "severity": "medium",
                    "category": "weak_password",
                    "line": index,
                    "message": f"Password at line {index} scored {analysis['score']} ({analysis['grade']}).",
                }
            )

    # Compile the final summary string
    summary = (
        f"Analyzed {len(analyses)} password(s); average score {average_score:.1f}. "
        f"{len(below_fair)} password(s) fell below Fair."
    )

    # Return the full module report object
    return {
        "module_name": "audit",
        "title": "DataGuard Password Audit Report",
        "output": output,
        "analyses": analyses,
        "findings": findings,
        "warnings": _audit_warnings(analyses, below_fair),
        "errors": [],
        "stats": {
            "passwords_analyzed": len(analyses),
            "average_score": average_score,
            "weakest_line": weakest_index + 1 if weakest is not None else "",
            "below_fair": len(below_fair),
        },
        "metadata": {
            "source": config.get("source_name", "<input>"),
            "minimum_length": int(config.get("min_length", 8)),
            "export_contains_plaintext_passwords": True,
            "entropy_metric": "naive_uniform_random_pool_estimate",
        },
        "summary": summary,
    }
