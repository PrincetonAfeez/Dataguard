# DataGuard

DataGuard is a **standard-library-only Python CLI** for cleaning, validating, triaging, and transforming messy real-world data.

It is designed for command-line workflows where you want one tool that can:

- clean invisible or unsafe text artifacts
- extract contacts from unstructured text
- audit password quality with offline heuristics
- parse web/server access logs and flag suspicious patterns
- repair malformed CSV files and convert them to JSON
- sanitize HTML in plain-text or safe-tag mode
- auto-detect likely input type and route it to the right module
- batch-process directories of mixed files

> **Important:** DataGuard aims to be practical and portable, not “security magic.” Some modules intentionally use heuristic logic and best-effort parsing. For example, the HTML sanitizer is **not** a replacement for hardened browser-side or framework-grade sanitization.

---

## Why DataGuard?

Real-world data is messy.

You might receive:

- a text file with hidden Unicode characters
- a copied contact list with inconsistent formatting
- a password dump that needs offline quality scoring
- server logs that need quick triage
- a CSV with broken rows, duplicate headers, or mixed delimiters
- user-submitted HTML that needs cleanup before inspection or storage

DataGuard provides a single CLI with a consistent output model, shared runtime flags, optional reports, and JSON-friendly automation.

---

## Features

### `sanitize`
Clean text artifacts such as:

- BOM markers
- ANSI escape sequences
- control characters
- unusual Unicode whitespace
- smart quotes
- zero-width characters
- optional bidi / isolate formatting marks

Useful for copied text, generated logs, OCR output, or suspicious text payloads.

### `contacts`
Extract and validate contact information from messy text.

Capabilities include:

- email extraction with validation rules
- US/NANP phone normalization
- international phone normalization for `+`-prefixed numbers
- confidence scoring
- duplicate suppression
- optional rejected-candidate reporting

Output is CSV for easy spreadsheet import.

### `audit`
Audit password quality using offline heuristics.

Checks include:

- minimum length
- character-class diversity
- common-password matching
- leetspeak normalization
- weak suffix detection
- repeated characters
- ascending/descending sequences
- keyboard walk patterns
- a naive entropy estimate

> **Security note:** exported audit data can contain full plaintext passwords. Treat those files as sensitive.

### `logs`
Parse server logs and generate quick threat-oriented summaries.

Supported behavior includes:

- Apache / Nginx / generic format detection
- request parsing
- top IP and URL summaries
- parse-failure reporting
- heuristic detection for path traversal, SQL injection probes, scanner fingerprints, brute-force bursts, and rapid-fire request spikes

> **Security note:** this is a triage aid, not a SIEM, IDS/IPS, WAF, or formal incident analysis platform.

### `csv`
Repair broken CSV input and convert it to structured JSON.

Capabilities include:

- delimiter detection
- header detection / generation
- header normalization
- duplicate-header repair
- short-row padding
- long-row overflow handling
- strict-mode rejection
- optional quarantine file for rejected rows
- basic type inference and conversion
- column completeness profiling

### `html`
Clean and sanitize HTML in two modes:

- **plain**: strip markup and return plain text
- **safe**: preserve only allowlisted tags and allowed attributes

The module removes or neutralizes things like:

- `<script>` blocks
- dangerous URLs
- event handlers
- blocked tags such as `iframe`, `object`, `embed`, `form`, and `base`
- style-based attacks and meta refresh tricks

> **Security note:** this is best-effort sanitization for cleanup and inspection, not a hardened security boundary.

### `auto`
Inspect input content and route it to the most likely module.

Detection is based on content heuristics and, when available, filename extension hints.

### `batch`
Scan a directory, auto-detect each file’s type, and write cleaned output files plus an optional batch summary JSON report.

### `config`
Read or update defaults stored in `.dataguardrc`.

### `examples`
Print example commands.

### `info`
Print environment and module-health information.

---

## Tech stack

DataGuard keeps the implementation intentionally lightweight:

- **Language:** Python 3.10+
- **Packaging:** `pyproject.toml` with `setuptools`
- **Runtime dependencies:** none beyond the Python standard library
- **Test dependency:** `pytest`
- **CLI framework:** standard-library `argparse`
- **Parsing / transformation approach:** standard library modules such as `csv`, `json`, `html.parser`, `re`, `pathlib`, and related utilities
- **Schemas:** JSON Schema documents shipped under `schema/`

This makes the project easy to install in constrained environments and simple to audit.

---

## Installation

### Recommended: install from source in a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate
pip install -e .
```

Then verify the CLI:

```bash
dg-clean --help
```

### Why `dg-clean` instead of `python -m dataguard`?

This repository already warns about a potential package-name collision with another package named `dataguard` in some environments.

Use **`dg-clean`** when possible to ensure you are executing this project’s entry point.

You can still try:

```bash
python -m dataguard --help
```

But `dg-clean` is the safer default when working from a local clone or editable install.

---

## Quick start

### Sanitize suspicious text

```bash
dg-clean sanitize --input $'Hello\u200b world\ufeff'
```

### Extract contacts from a text file

```bash
dg-clean contacts --file contacts.txt --output contacts.csv --report
```

### Audit one password

```bash
dg-clean audit --password 'TrickyPass123!' --report
```

### Parse access logs

```bash
dg-clean logs --file access.log --top 5 --threats-only
```

### Repair CSV and export JSON

```bash
dg-clean csv --file broken.csv --output output.json --quarantine rejected.csv
```

### Sanitize HTML in safe mode

```bash
dg-clean html --file input.html --mode safe --allow p,a,strong,img --show-diff --report
```

### Auto-detect a file

```bash
dg-clean auto --file mystery.txt --report
```

### Batch-process a directory

```bash
dg-clean batch --dir incoming --pattern '*.txt' --output-dir cleaned --batch-report batch.json
```

---

## Command reference

## Global behavior

Many subcommands share runtime flags such as:

- `--report` to print a standardized report
- `--report-format text|json|csv`
- `--report-file <path>`
- `--pipe-format text|json|raw`
- `--no-color`
- `--quiet`
- `--verbose` / `-v -vv -vvv`
- `--strict`

### `sanitize`

```bash
dg-clean sanitize [--input TEXT | --file PATH | --stdin] [--output PATH] [--preserve-bidi-marks]
```

Use for cleaning invisible, unsafe, or normalization-worthy text artifacts.

### `contacts`

```bash
dg-clean contacts --file PATH|--stdin [--output PATH] [--min-confidence FLOAT] [--show-rejected]
```

Output is CSV with columns like:

- `name_if_found`
- `email`
- `phone`
- `source_line`
- `confidence_score`

### `audit`

```bash
dg-clean audit [--password TEXT | --file PATH | --stdin] [--show] [--min-length N] [--no-dictionary] [--no-entropy] [--export PATH]
```

Use `--show` carefully, because it prints the real password instead of masking it.

### `logs`

```bash
dg-clean logs --file PATH|--stdin [--format auto|apache|nginx|generic] [--top N] [--threats-only] [--export PATH]
```

`--export` writes parsed log entry JSON, which may contain sensitive operational data.

### `csv`

```bash
dg-clean csv --file PATH|--stdin [--output PATH] [--delimiter auto|,|;|||tab] [--quarantine PATH] [--no-types]
```

In strict mode, malformed rows are rejected instead of repaired.

### `html`

```bash
dg-clean html [--input TEXT | --file PATH | --stdin] [--mode plain|safe] [--allow TAG1,TAG2,...] [--output PATH] [--show-diff]
```

### `auto`

```bash
dg-clean auto --file PATH|--stdin [--output PATH] [--dry-run]
```

- `--dry-run` prints the detected module, confidence, and detection notes without running the module.

### `batch`

```bash
dg-clean batch --dir PATH [--recursive] [--pattern GLOB] --output-dir PATH [--batch-report PATH]
```

This command:

1. scans matching files
2. auto-detects each file’s likely module
3. runs the corresponding processor
4. writes per-file cleaned output
5. optionally writes a batch summary JSON file

### `config`

```bash
dg-clean config
dg-clean config --set verbosity=1 pipe_format=json
```

### `examples`

```bash
dg-clean examples
```

### `info`

```bash
dg-clean info
```

---

## Configuration

DataGuard supports an optional **`.dataguardrc`** file in the current working directory.

It is stored as JSON and merged with built-in defaults.

Example:

```json
{
  "color_enabled": true,
  "strict_mode": false,
  "pipe_format": "text",
  "report_format": "text",
  "min_confidence_threshold": 0.3,
  "password_min_length": 12,
  "log_top_n": 10,
  "verbosity": 1
}
```

Supported defaults include:

- `default_output_format`
- `color_enabled`
- `verbosity`
- `strict_mode`
- `min_confidence_threshold`
- `password_min_length`
- `log_top_n`
- `pipe_format`
- `report_format`

Unknown keys are ignored with warnings, and invalid values produce clear errors.

---

## Output model

Most module runners return a structured result with common concepts such as:

- `module_name`
- `title`
- `output`
- `findings`
- `warnings`
- `errors`
- `stats`
- `metadata`
- `summary`

This makes the CLI suitable both for human use and for shell / automation pipelines.

### Pipe formats

Primary output can be shaped with:

- `text`
- `json`
- `raw`

### Report formats

Standardized reports can be emitted as:

- `text`
- `json`
- `csv`

---

## Exit codes

DataGuard uses meaningful process exit codes:

- `0` = success with no warnings
- `1` = success with warnings
- `2` = processing failure, or warnings treated as failure in strict mode
- `3` = CLI / internal / handled execution error

This makes it easy to integrate with scripts and CI-style checks.

---

## Auto-detection behavior

The `auto` module scores content against likely module types such as:

- logs
- CSV
- HTML
- contacts
- password lists
- plain text / sanitization fallback

It uses:

- content sampling
- regex and structural heuristics
- extension-based confidence boosts for files like `.log`, `.csv`, `.tsv`, `.html`, and `.htm`
- tie-breaking priority rules when scores are close

This is useful for mixed-input directories and quick CLI workflows.

---

## JSON Schema support

The `schema/` directory contains machine-readable schema documents for:

- common definitions
- config payloads
- config CLI responses
- auto-detection responses
- batch summaries
- CLI info output
- unified module result shapes
- read metadata

Start with:

```text
schema/manifest.json
```

This is especially useful if you want to validate DataGuard output programmatically or build tooling around it.

---

## Project structure

A simplified layout looks like this:

```text
Dataguard/
├── cli.py
├── auto_detect.py
├── config.py
├── dg_clean_entry.py
├── formatter.py
├── io_utils.py
├── errors.py
├── common_passwords.py
├── modules/
│   ├── string_sanitizer.py
│   ├── contact_extractor.py
│   ├── password_checker.py
│   ├── log_parser.py
│   ├── csv_converter.py
│   └── html_sanitizer.py
├── schema/
├── tests/
├── pyproject.toml
└── requirements.txt
```

---

## Security and scope notes

DataGuard is intentionally transparent about what it does and does **not** do.

### HTML sanitization

The HTML module is useful for cleanup and inspection, but it is not a replacement for:

- a hardened HTML sanitizer
- trusted browser parsing
- CSP
- full application-layer XSS defense

### Password auditing

Password scoring is heuristic. The entropy metric is a **naive uniform-random estimate**, not a real attacker-cost model and not NIST verification.

### Log analysis

Threat findings are pattern-based hints for triage. They should not be treated as definitive incident conclusions.

### Contact extraction

Confidence scores help filter noisy text, but extracted results should still be reviewed before operational use.

---

## Development

### Install test dependency

```bash
pip install -r requirements.txt
```

### Run tests

```bash
pytest
```

### Suggested local checks

Examples of good local checks before opening a PR:

```bash
dg-clean info
dg-clean examples
pytest
```

---

## Suggested roadmap

Potential next improvements for the project:

- add CI workflows for tests and linting
- publish release notes / tagged versions
- add sample input and output fixtures in the README
- add contributor guidelines
- add benchmark notes for large-file processing
- document expected JSON outputs per module with examples
- add a comparison section explaining when to use DataGuard versus dedicated security or ETL tools

---

## Contributing

Contributions are welcome.

Good contribution areas include:

- new test coverage
- more sample fixtures
- improved docs and examples
- better log-format support
- tighter HTML allowlist behavior
- more robust data-type inference for CSV conversion
- clearer machine-readable schema documentation

A useful contribution flow is:

1. fork the repo
2. create a feature branch
3. add or update tests
4. run `pytest`
5. open a pull request with before/after examples

---

## License

Add the project license here once the repository includes one explicitly.

If you already have a license file in the repo, update this section to reference it directly.
