# Architecture Decision Record
## App 07 — DataGuard Bootstrapper
**DataGuard Group | Document 1 of 5**
**Status: Accepted**

---

## Context

Apps 01–06 are independent modules — each has its own CLI, its own `run()` function, and its own result envelope. The DataGuard Bootstrapper (App 07) is the unified CLI that ties all six modules together under a single `python -m dataguard` entry point. It adds four capabilities that no individual module has: auto-detection of file type, batch processing of directories, persistent configuration via `.dataguardrc`, and a module-health diagnostic.

The bootstrapper is also the module that converts a collection of independent apps into a coherent system with a shared interface contract.

---

## Decisions

### Decision 1 — `MODULE_RUNNERS` dispatch dict over a chained if-elif

**Chosen:** `MODULE_RUNNERS = {"sanitize": string_sanitizer.run, "contacts": contact_extractor.run, ...}` — a module-level dict mapping command names to runner functions.

**Rejected:** A chained `if args.command == "sanitize": ... elif args.command == "contacts": ...` in `main()`.

**Reason:** A dict is the correct data structure for this dispatch pattern. Adding a seventh module requires one dict entry and one import — no changes to `main()` or any existing handler. The dict is also introspectable — `handle_info()` iterates it to check module health without hardcoding names.

---

### Decision 2 — `auto_detect.py` using six scoring functions with tie-breaking priority

**Chosen:** Six independent scoring functions (`score_as_log`, `score_as_csv`, `score_as_html`, `score_as_contacts`, `score_as_passwords`, `score_as_plain_text`), each returning 0.0–1.0. `detect_module()` compares all scores, applies `MODULE_PRIORITY` tie-breaking, and falls back to `"sanitize"` when no module clears 0.3.

**Rejected:** A single unified scoring function or a simple extension-based lookup.

**Reason:** Real files arrive without reliable extensions. Extension-based detection is used as a confidence boost (`EXTENSION_TO_MODULE`), not as the primary signal. The scoring approach produces confidence-weighted detection — the `notes` field in the result explains when tie-breaking was needed, giving operators visibility into ambiguous inputs. The `score_as_passwords` function explicitly penalizes high CSV or HTML scores, preventing misrouting of structured data as password lists.

---

### Decision 3 — `dg_clean_entry.py` for import collision avoidance

**Chosen:** A separate `dg_clean_entry.py` that purges `sys.modules` of any cached `dataguard` entries and reloads from the local repo before calling `cli.main()`.

**Rejected:** Relying on `python -m dataguard` alone and hoping `sys.path` is correct.

**Reason:** If another package named `dataguard` is installed (from PyPI), `python -m dataguard` may import that package instead of this one. `dg_clean_entry.py` uses `importlib.util.spec_from_file_location` to force-load from the local filesystem, bypassing the installed package. The `_loaded_dataguard_package_root()` check avoids unnecessary purging when the correct package is already cached. This is the most advanced use of `importlib` in the portfolio.

---

### Decision 4 — `.dataguardrc` JSON config with coercion and validation

**Chosen:** `config.py` loads `.dataguardrc` from the current working directory, merges it with `DEFAULT_CONFIG`, and runs `coerce_config_value()` on every loaded value. Unknown keys are flagged as warnings, not errors. Invalid values raise `InputError`.

**Rejected:** Command-line flags only (no persistence), or TOML config.

**Reason:** Operators running DataGuard repeatedly in the same project need persistent defaults — a confidence threshold for contact extraction, a custom minimum password length, a preferred report format. The JSON format is stdlib-only (unlike TOML). The coercion layer ensures that `"true"`, `True`, `1`, and `"on"` all produce the same boolean value, and that numeric values are clamped to valid ranges rather than silently accepting out-of-range inputs.

---

### Decision 5 — `io_utils.py` reading as bytes then decoding

**Chosen:** All file and stdin reads are done in binary mode (`"rb"`). `decode_bytes()` tries UTF-8 first, then falls back to Latin-1 (which never fails). A warning is added to `metadata["read_warnings"]` on fallback.

**Rejected:** Opening files in text mode with `encoding="utf-8"` and failing on decode errors.

**Reason:** Files processed by DataGuard often arrive from diverse sources with unknown encoding. Text-mode UTF-8 raises `UnicodeDecodeError` on Latin-1 content. The bytes-first approach lets the module recover, surface a warning in the result metadata, and continue processing. The warning appears in the standardized result so downstream callers can log it without inspecting exceptions.

---

### Decision 6 — `compute_exit_code()` with three levels

**Chosen:** `0` (clean), `1` (warnings present, strict mode off), `2` (errors or strict mode + warnings), `3` (unexpected/infrastructure failure).

**Rejected:** Only `0` and `1`.

**Reason:** Shell scripts and CI pipelines need to distinguish between "warnings you can tolerate" and "errors you must fix". The three-level scheme maps naturally: `0` → proceed, `1` → investigate, `2` → block. Exit code `3` covers infrastructure failures (config parse errors, `handle_info` exceptions) that are distinct from module-level data errors.

---

### Decision 7 — `batch` command with per-file auto-detection

**Chosen:** `handle_batch()` iterates a directory, auto-detects each file, routes it to the correct module, writes the output to a per-file path in `output_dir`, and produces an optional JSON batch report.

**Rejected:** Requiring the operator to specify which module to use for a directory.

**Reason:** A directory of mixed files (some logs, some CSVs, some HTML) should be processable in one command. Per-file auto-detection inside batch is the correct extension of the single-file `auto` command to the directory case. The batch report gives operators a full audit trail of what was detected and processed per file.

---

## Consequences

**Positive:**
- Adding a seventh DataGuard module requires only one import and one dict entry — no structural changes.
- Auto-detection makes the tool usable without knowing file types.
- `dg_clean_entry.py` ensures the correct package is always loaded regardless of PyPI state.
- Bytes-first I/O with Latin-1 fallback prevents silent mojibake and produces surfaceable warnings.
- Three-level exit codes integrate cleanly with CI pipelines.

**Negative / Trade-offs:**
- Auto-detection is heuristic. Files with ambiguous content (e.g., a log file that looks like a CSV) may be misrouted. The `--dry-run` flag shows detection scores for debugging.
- The `.dataguardrc` config lives in the current working directory. Projects in different directories need separate config files. A global config (`~/.dataguardrc`) was intentionally not added to avoid user-global state side effects.
- `dg_clean_entry.py` purges all `dataguard.*` entries from `sys.modules` on mismatched imports — this could interact unexpectedly with test runners that cache imports across test files.

---

*Constitution reference: Articles 1, 2, 3. Amendment 1.2: Monorepo DRY structure is an architectural feature.*


---


# Technical Design Document
## App 07 — DataGuard Bootstrapper
**DataGuard Group | Document 2 of 5**

---

## Overview

The DataGuard Bootstrapper is the unified CLI and coordinator for the six-module DataGuard system. It provides a single `python -m dataguard` entry point, auto-detection routing, batch processing, persistent configuration, and module health diagnostics.

**Files:** `cli.py` (707 lines), `auto_detect.py` (auto-detection), `config.py` (configuration), `io_utils.py` (I/O), `dg_clean_entry.py` (import collision avoidance), `__init__.py`, `__main__.py`, `errors.py`, `formatter.py`
**Entry points:** `python -m dataguard` → `__main__.py` → `cli.main()`, or `dg-clean` → `dg_clean_entry.main()`
**Dependencies:** All six module runners, stdlib only

---

## Package Structure

```
dataguard/
├── __init__.py          # Version: "0.1.0"
├── __main__.py          # Entry: python -m dataguard
├── cli.py               # Unified CLI (707 lines)
├── auto_detect.py       # File type detection
├── config.py            # .dataguardrc loading/saving
├── io_utils.py          # Bytes-first file/stdin reading
├── dg_clean_entry.py    # Import collision avoidance (dg-clean)
├── errors.py            # Shared exceptions
├── formatter.py         # Shared output/report formatting
└── modules/
    ├── string_sanitizer.py
    ├── html_sanitizer.py
    ├── contact_extractor.py
    ├── csv_converter.py
    ├── log_parser.py
    └── password_checker.py
```

---

## CLI Command Map

```
dataguard
├── sanitize    → string_sanitizer.run()
├── contacts    → contact_extractor.run()
├── audit       → password_checker.run()
├── logs        → log_parser.run()
├── csv         → csv_converter.run()
├── html        → html_sanitizer.run()
├── auto        → detect_module() → run_named_module()
├── batch       → handle_batch() → per-file detect + route
├── config      → handle_config()
├── examples    → handle_examples()
└── info        → handle_info()
```

---

## Data Flow — Named Module Command

```
argv
  │
  ▼
build_parser()  →  args
  │
  ▼
resolve_runtime_config(args)  →  runtime_config
  (load_config() + CLI flag overrides)
  │
  ▼
validate_input_sources(args, command)
  │
  ▼
read_command_input(args)  →  (text, metadata)
  (io_utils.read_input_text → decode_bytes)
  │
  ▼
run_named_module(command, text, metadata, args, runtime_config)
  →  result dict
  │
  ▼
serialize_primary_output(result["output"], pipe_format)
  │
  ▼
write_primary_output_if_needed(output_text, output_path)
  │
  ▼
maybe_write_report(result, args, runtime_config)
  │
  ▼
compute_exit_code(result, strict_mode)
```

---

## Auto-Detection: `detect_module()`

```
text, file_path
        │
        ▼
sample_lines(text)   → up to 35 non-empty, non-comment lines
                        from first 250 scanned; raw prefix fallback
        │
        ▼
score_as_log()        → 0.0–1.0
score_as_csv()        → 0.0–1.0  (tries 4 delimiters)
score_as_html()       → 0.0–1.0
score_as_contacts()   → 0.0–1.0
score_as_passwords()  → 0.0–1.0  (penalized by csv/html scores)
score_as_plain_text() → 0.0–1.0
        │
        ├─ Extension boost: EXTENSION_TO_MODULE → max(score, 0.9)
        │
        ├─ Score < 0.3 → fallback: "sanitize"
        │
        └─ Tie (spread ≤ 0.1) → MODULE_PRIORITY ordering
                ["logs", "csv", "html", "contacts", "audit", "sanitize"]
        │
        ▼
{module, scores, reason, notes}
```

---

## Configuration: `config.py`

### `DEFAULT_CONFIG`
```python
{
    "default_output_format": "text",
    "color_enabled": True,
    "verbosity": 0,
    "strict_mode": False,
    "min_confidence_threshold": 0.3,
    "password_min_length": 8,
    "log_top_n": 10,
    "pipe_format": "text",
    "report_format": "text",
}
```

### Load hierarchy
1. `DEFAULT_CONFIG` values (fallback)
2. `.dataguardrc` in CWD (JSON, merged via `_merge_loaded_dict`)
3. CLI flags (applied in `resolve_runtime_config`)

### Coercion rules
- Booleans: `"true"`, `"1"`, `"yes"`, `"on"` → `True`; `"false"`, `"0"`, `"no"`, `"off"` → `False`
- `min_confidence_threshold`: clamped to `[0.0, 1.0]`
- `verbosity`: clamped to `[0, 10]`
- `password_min_length`: clamped to `[1, 256]`
- `pipe_format`: must be `"text"`, `"json"`, or `"raw"`
- `report_format`: must be `"text"`, `"json"`, or `"csv"`

---

## I/O: `io_utils.py`

### `decode_bytes(raw_bytes) → (text, encoding, warnings)`
1. Strip UTF-8 BOM if present → append BOM warning
2. Try `raw_bytes.decode("utf-8")` → return `(text, "utf-8", warnings)`
3. On `UnicodeDecodeError`: `raw_bytes.decode("latin-1")` → append Latin-1 fallback warning

### `read_input_text(file_path, use_stdin) → (text, InputReadMetadata)`
Priority:
1. `file_path` is set → `read_text_file(file_path)`
2. `use_stdin=True` or `stdin_has_data()` → `_read_stdin_decoded()`
3. Neither → raise `InputError("No input provided.")`

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Clean run, no errors or warnings |
| `1` | Warnings present, strict mode off |
| `2` | Errors present, or strict mode + warnings |
| `3` | Infrastructure failure (config parse, unexpected exception) |

---

## `run_named_module()` Config Mapping

| Command | Key config values passed |
|---|---|
| `sanitize` | `strip_bidi_format_marks` |
| `contacts` | `min_confidence` (resolved), `show_rejected`, `progress_callback` |
| `audit` | `single_password`, `show_password`, `min_length`, `no_dictionary`, `no_entropy` |
| `logs` | `format`, `top`, `threats_only` |
| `csv` | `delimiter`, `strict`, `no_types` |
| `html` | `mode`, `allowed_tags`, `show_diff` |

---

## Shared Runtime Flags

All commands (except `config`, `examples`, `info`) accept:

| Flag | Type | Description |
|---|---|---|
| `--report` | bool | Print standardized report to stderr |
| `--report-format` | choice | `text`/`json`/`csv` |
| `--report-file` | path | Write report to file instead of stderr |
| `--pipe-format` | choice | `text`/`json`/`raw` for stdout |
| `--no-color` | bool | Disable ANSI colors |
| `--quiet` | bool | Suppress non-error stderr |
| `--verbose` | count | Increase verbosity (`-vvv`) |
| `--strict` | bool | Promote warnings to exit code 2 |


---


# Interface Design Specification
## App 07 — DataGuard Bootstrapper
**DataGuard Group | Document 3 of 5**

---

## CLI Reference

### Invocation

```bash
python -m dataguard <command> [options]
dg-clean <command> [options]   # when another "dataguard" PyPI package is installed
```

---

### Command: `sanitize`
```bash
dataguard sanitize --input "text with \u200b artifacts"
dataguard sanitize --file dirty.txt --output clean.txt
dataguard sanitize --stdin < input.txt
dataguard sanitize --file input.txt --report --report-format json
dataguard sanitize --file input.txt --preserve-bidi-marks
```

### Command: `contacts`
```bash
dataguard contacts --file contacts.txt --output contacts.csv
dataguard contacts --file contacts.txt --min-confidence 0.8
dataguard contacts --file contacts.txt --show-rejected --report
dataguard contacts --stdin < email_dump.txt
```

### Command: `audit`
```bash
dataguard audit --password "myPassword123!"
dataguard audit --password "myPassword123!" --show --report
dataguard audit --file passwords.txt --min-length 12
dataguard audit --file passwords.txt --no-dictionary --export analysis.json
```

### Command: `logs`
```bash
dataguard logs --file access.log --top 20
dataguard logs --file access.log --format apache --threats-only
dataguard logs --file access.log --export parsed.json --report
dataguard logs --stdin < combined.log
```

### Command: `csv`
```bash
dataguard csv --file data.csv --output result.json
dataguard csv --file data.csv --delimiter ";" --no-types
dataguard csv --file data.csv --strict --quarantine rejected.csv
```

### Command: `html`
```bash
dataguard html --file page.html --mode plain --output text.txt
dataguard html --input "<p>text</p><script>evil()</script>" --mode safe
dataguard html --file page.html --mode safe --allow "p,a,strong,img" --show-diff
```

### Command: `auto`
```bash
dataguard auto --file mystery.txt
dataguard auto --file mystery.txt --dry-run       # show detection scores only
dataguard auto --file mystery.txt --report
```

### Command: `batch`
```bash
dataguard batch --dir incoming/ --pattern "*.txt" --output-dir cleaned/
dataguard batch --dir incoming/ --recursive --pattern "*.log" --output-dir cleaned/ --batch-report batch.json
```

### Command: `config`
```bash
dataguard config                                            # show current config
dataguard config --set min_confidence_threshold=0.7
dataguard config --set password_min_length=12 strict_mode=true
```

### Command: `info`
```bash
dataguard info          # JSON: version, python_version, platform, module health
```

### Command: `examples`
```bash
dataguard examples      # print example commands
```

---

## Auto-Detection Result

```python
{
    "module": str,       # "logs" | "csv" | "html" | "contacts" | "audit" | "sanitize"
    "scores": {          # 0.0–1.0 per module
        "logs": float,
        "csv": float,
        "html": float,
        "contacts": float,
        "audit": float,
        "sanitize": float,
    },
    "reason": str,       # "Detected logs with confidence 0.85"
    "notes": list[str],  # Tie-breaking or fallback explanations
}
```

---

## Batch Report Schema

```python
{
    "files_processed": int,
    "module_counts": {"logs": int, "csv": int, ...},
    "total_warnings": int,
    "total_errors": int,
    "results": [
        {
            "input_file": str,
            "detected_module": str,
            "output_file": str,
            "warnings": list[str],
            "errors": list[str],
            "summary": str,
        }
    ]
}
```

---

## Config Schema (`.dataguardrc`)

```json
{
  "default_output_format": "text",
  "color_enabled": true,
  "verbosity": 0,
  "strict_mode": false,
  "min_confidence_threshold": 0.3,
  "password_min_length": 8,
  "log_top_n": 10,
  "pipe_format": "text",
  "report_format": "text"
}
```

---

## Input/Output Examples

### Auto-detection dry run
```bash
dataguard auto --file access.log --dry-run
# stdout:
{
  "module": "logs",
  "scores": {"logs": 0.82, "csv": 0.0, "html": 0.0, "contacts": 0.2, "audit": 0.1, "sanitize": 0.35},
  "reason": "Detected logs with confidence 0.82",
  "notes": []
}
```

### Config update
```bash
dataguard config --set password_min_length=12 min_confidence_threshold=0.7
# stdout: full updated config as JSON
# writes to .dataguardrc in CWD
```

### Module health check
```bash
dataguard info
# stdout:
{
  "version": "0.1.0",
  "python_version": "3.11.4",
  "platform": "Linux-6.2.0-...",
  "modules": {
    "sanitize": "ok",
    "contacts": "ok",
    "audit": "ok",
    "logs": "ok",
    "csv": "ok",
    "html": "ok"
  }
}
```

### Batch processing
```bash
dataguard batch --dir incoming/ --pattern "*.txt" --output-dir cleaned/ --batch-report batch.json
# stdout: Files processed: 14 / Per-module counts: / - contacts: 6 / - csv: 3 / ...
# batch.json: full per-file records
```


---


# Runbook
## App 07 — DataGuard Bootstrapper
**DataGuard Group | Document 4 of 5**

---

## Requirements

- Python 3.10 or later
- No third-party dependencies
- All six module files must be importable from `dataguard.modules`

---

## Installation

```bash
git clone https://github.com/PrincetonAfeez/DataGuard
cd DataGuard
```

No `pip install` required. Run as `python -m dataguard` from the repo root.

If another PyPI package named `dataguard` is installed, use the `dg-clean` entry:
```bash
python dg_clean_entry.py <command> [options]
```

---

## First Run

```bash
# Verify all modules are healthy
python -m dataguard info

# View example commands
python -m dataguard examples

# Show default configuration
python -m dataguard config
```

---

## Common Workflows

### Process a single file of unknown type
```bash
python -m dataguard auto --file mystery.txt --report
```

### Set project-level defaults
```bash
python -m dataguard config --set password_min_length=12 min_confidence_threshold=0.7 strict_mode=true
```

### Batch process an incoming directory
```bash
python -m dataguard batch --dir incoming/ --recursive --pattern "*.txt" --output-dir cleaned/ --batch-report batch.json
```

### Pipe data from another tool
```bash
cat access.log | python -m dataguard logs --stdin --threats-only
curl -s https://example.com | python -m dataguard html --stdin --mode plain
```

### Use in CI/CD — exit non-zero on any issue
```bash
python -m dataguard audit --file passwords.txt --strict
echo "Exit: $?"   # 0 = all fair+, 2 = at least one issue in strict mode
```

### Export structured JSON for downstream processing
```bash
python -m dataguard contacts --file contacts.txt --pipe-format json > contacts_structured.json
python -m dataguard logs --file access.log --export entries.json
```

---

## Configuration

### Create a project config
```bash
python -m dataguard config --set password_min_length=12
# Creates .dataguardrc in CWD
```

### View current effective config
```bash
python -m dataguard config
```

### Known config keys
| Key | Type | Range/Options |
|---|---|---|
| `default_output_format` | string | any non-empty |
| `color_enabled` | bool | true/false |
| `verbosity` | int | 0–10 |
| `strict_mode` | bool | true/false |
| `min_confidence_threshold` | float | 0.0–1.0 |
| `password_min_length` | int | 1–256 |
| `log_top_n` | int | 1–10000 |
| `pipe_format` | string | text/json/raw |
| `report_format` | string | text/json/csv |

---

## Running Tests

```bash
pip install pytest
pytest -v   # from repo root
```

DataGuard has no dedicated bootstrapper-level test file in the uploaded set — tests for individual modules run from their respective test files. The `handle_info()` health check and integration smoke tests cover bootstrapper wiring.

---

## Troubleshooting

### `ModuleNotFoundError: No module named 'dataguard'`
Run from the repo root, or add the repo root to `PYTHONPATH`:
```bash
PYTHONPATH=/path/to/DataGuard python -m dataguard info
```

### Wrong `dataguard` package loaded (another PyPI install)
Use `dg-clean` instead of `python -m dataguard`:
```bash
python dg_clean_entry.py info
```

### Auto-detection routed to wrong module
Run with `--dry-run` to see scores:
```bash
python -m dataguard auto --file mystery.txt --dry-run
```
If the wrong module wins, check whether the file has a recognized extension (`.log`, `.csv`, `.html`). Extension boosts the score to 0.9, overriding content-based scores.

### Config key rejected with `InputError`
Use `dataguard config` (no `--set`) to see valid keys. Keys not in `DEFAULT_CONFIG` are rejected. Check spelling.

### Latin-1 fallback warning in output
The input file contained bytes that are not valid UTF-8. The file was decoded as Latin-1 instead. Convert to UTF-8 before processing for accurate results:
```bash
iconv -f latin-1 -t utf-8 input.txt > input_utf8.txt
```

### Exit code 3 unexpectedly
Exit code 3 indicates an infrastructure failure (config parse error, unexpected exception in `main()`). Check stderr for `[ERROR]` messages.


---


# Lessons Learned
## App 07 — DataGuard Bootstrapper
**DataGuard Group | Document 5 of 5**

---

## Why This Design Was Chosen

The `MODULE_RUNNERS` dispatch dict was the most consequential structural decision in this module. The first instinct was to write a long `if args.command == "sanitize": ...` chain in `main()`. The dict approach emerged from realizing that the chain would need to be updated in three places every time a new module was added: the `if-elif`, the subparser definitions, and the `handle_auto` routing. The dict collapses all three into one entry — add the import, add the dict entry, add the subparser definition. The `handle_info()` function then gets module health for free by iterating the same dict.

The bytes-first I/O approach in `io_utils.py` came from a specific failure. The first version opened files in text mode with `encoding="utf-8"` and crashed on a Latin-1 encoded contact file. Switching to binary read + `decode_bytes()` with a fallback chain produced a surfaceable warning instead of an exception. That change made the tool usable on real-world files that did not arrive in pristine UTF-8.

---

## What Was Intentionally Omitted

**Global config (`~/.dataguardrc`):** Only the CWD config file is supported. A global config would affect DataGuard behavior in every project on the system, which is a hidden side effect. Project-scoped config is explicit and auditable.

**Plugin architecture:** Adding a seventh module currently requires modifying `cli.py` (import + dict entry + subparser). A true plugin system where modules register themselves at startup would eliminate this. It was omitted because the current group size (6 modules) does not justify the complexity, and a plugin system would require a formal registry API that is not yet designed.

**GUI or web interface:** DataGuard is intentionally a CLI tool. Adding a web interface or GUI was out of scope for the academic portfolio but would be the next step for making it accessible to non-technical operators.

**Async processing:** `handle_batch()` processes files sequentially. For large directories, parallel processing using `concurrent.futures.ProcessPoolExecutor` would be faster. Omitted to keep the implementation readable and debuggable.

---

## Biggest Weakness

The auto-detection scoring functions are heuristic and have blind spots. The biggest known failure mode is a log file that uses CSV-style delimiters — such as an Apache log with a comma-separated header line injected by a log aggregator. In this case, `score_as_csv()` may exceed `score_as_log()` and route the file to the CSV converter, which will fail to parse it correctly.

The `notes` field in the detection result reports when tie-breaking was used, but it does not report when the winning score was close to the runner-up. An operator who sees a close detection and needs to override should use the named command directly (e.g., `dataguard logs --file mystery.log`) rather than `auto`.

---

## Scaling Considerations

**If the module count grows to 20+:** The dict-based dispatch scales cleanly — one import, one dict entry, one subparser definition per module. The `handle_info()` health check automatically includes new modules. The auto-detection system would need a new scoring function per module, which is the only non-trivial cost.

**If batch files grow to thousands:** `handle_batch()` currently processes files sequentially and keeps no state between files. Parallelizing with `ProcessPoolExecutor` (one process per file) would improve throughput linearly up to the CPU count. Each module's `run()` function is already stateless and side-effect-free, making parallelization safe.

**If the config system needs to support more environments:** The current `.dataguardrc` is project-scoped. A hierarchy (project → user → system) would require checking multiple paths in order and merging from lowest to highest priority. This is the standard config layering pattern and would not require structural changes to the coercion or validation logic.

---

## What the Next Refactor Would Be

1. **Parallel batch processing** — `ProcessPoolExecutor` for `handle_batch()`.
2. **Plugin registry** — `dataguard.modules` as a namespace package where modules self-register, eliminating `cli.py` changes for new modules.
3. **Global config** — `~/.dataguardrc` with project config taking precedence.
4. **Detection confidence threshold flag** — `dataguard auto --min-detection-confidence 0.5` to reject low-confidence routing explicitly.

---

## What This Project Taught

**A dispatch dict is an architecture, not a shortcut.** The dict-based `MODULE_RUNNERS` is not just a clean alternative to `if-elif` — it is a data structure that enables `handle_info()` to introspect the module set, enables `handle_batch()` to route to any module without special cases, and enables future additions without touching existing code. Recognizing when a dict is the right abstraction for a dispatch pattern is a system design skill that pays dividends every time a new module is added.

**Good error recovery produces surfaceable warnings, not exceptions.** The Latin-1 fallback in `decode_bytes()` does not crash the pipeline — it produces a warning that appears in `result["metadata"]["read_warnings"]` and in the CLI output. The operator gets their result and knows to check the encoding. This is the right behavior for a tool designed to process real-world data, which is frequently imperfect.

**Group-level documentation is more than the sum of module docs.** The DataGuard bootstrapper is where the system design decisions become visible — the shared result envelope contract, the consistent exit code semantics, the unified `--report` flag across all commands, the bytes-first I/O that every module benefits from. Writing this document required looking at all six modules simultaneously and articulating what makes them a system rather than a collection of scripts. That perspective is not available from any individual module's documentation.

---

*Constitution v2.0 checklist: This document satisfies Article 5 (trade-off documentation) for App 07.*
*Group A documentation complete.*
