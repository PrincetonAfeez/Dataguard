"""Unified CLI entrypoint for DataGuard."""

# Enable modern type hinting features for compatibility with Python 3.10+
from __future__ import annotations

# Import standard library for CLI argument parsing
import argparse
# Import JSON for data serialization and config handling
import json
# Import OS for environment variables and file path logic
import os
# Import platform to detect the host operating system information
import platform
# Import sys to manage standard streams and exit codes
import sys
# Import fnmatch for Unix-style filename pattern matching
from fnmatch import fnmatch
# Import Callable for progress callback typing
from collections.abc import Callable
# Import Path for modern, cross-platform file system interactions
from pathlib import Path

# Internal imports: versioning info from the package root
from dataguard import __version__
# Internal imports: the detection logic you built in auto_detect.py
from dataguard.auto_detect import detect_module
# Internal imports: logic for handling the .dataguardrc configuration file
from dataguard.config import load_config, parse_set_arguments, persist_config_updates, resolve_contacts_min_confidence
# Internal imports: custom exception classes for standardized error reporting
from dataguard.errors import DataGuardError, InputError
# Internal imports: logic for turning raw data into pretty console output or reports
from dataguard.formatter import serialize_primary_output, write_report
# Internal imports: helpers for reading/writing text and handling stdin
from dataguard.io_utils import read_input_text, read_text_file, write_text_file
# Internal imports: the actual analysis "engines" for each data type
from dataguard.modules import contact_extractor, csv_converter, html_sanitizer, log_parser, password_checker, string_sanitizer


# Map command strings to the 'run' function of each specialized module
MODULE_RUNNERS = {
    "sanitize": string_sanitizer.run,
    "contacts": contact_extractor.run,
    "audit": password_checker.run,
    "logs": log_parser.run,
    "csv": csv_converter.run,
    "html": html_sanitizer.run,
}

# Define default file extensions for output files based on the active module
MODULE_OUTPUT_SUFFIX = {
    "sanitize": ".txt",
    "contacts": ".csv",
    "audit": ".txt",
    "logs": ".txt",
    "csv": ".json",
    "html": ".html",
}


# Utility to add shared flags (like --report or --verbose) to every subcommand parser
def add_runtime_flags(parser: argparse.ArgumentParser) -> None:
    # Flag to trigger a detailed summary report in stderr
    parser.add_argument("--report", action="store_true", help="Print the standardized report to stderr.")
    # Choose the file format for the generated report
    parser.add_argument("--report-format", choices=["text", "json", "csv"], help="Report output format.")
    # Redirect the report from stderr to a specific file path
    parser.add_argument("--report-file", help="Write the report to a file instead of stderr.")
    # Define how the primary data output is shaped (e.g., raw strings vs structured JSON)
    parser.add_argument(
        "--pipe-format",
        choices=["text", "json", "raw"],
        help="Stdout shape: text (default, indented JSON for dict/list), json (indented JSON), "
        "raw (single-line compact JSON for dict/list; plain str() for strings).",
    )
    # Strip ANSI color codes from the output (useful for logs or old terminals)
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors.")
    # Silence all non-essential messages during execution
    parser.add_argument("--quiet", action="store_true", help="Suppress non-error stderr output.")
    # Allow users to use -v, -vv, or -vvv to see more debugging information
    parser.add_argument("--verbose", action="count", default=0, help="Increase verbosity. Repeat for more detail.")
    # If set, the script will exit with an error even if only warnings were found
    parser.add_argument("--strict", action="store_true", help="Promote warnings to partial failures.")


# Construct the main argument parser and all subcommand definitions
def build_parser() -> argparse.ArgumentParser:
    # Create the root parser object with a description
    parser = argparse.ArgumentParser(description="DataGuard: a data validation and cleansing pipeline.")
    # Add a global flag to show the current version of the tool
    parser.add_argument("--version", action="version", version=f"DataGuard {__version__}")
    # Initialize subparsers to handle commands like 'sanitize' or 'audit'
    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- SANITIZE COMMAND SETUP ---
    sanitize_parser = subparsers.add_parser("sanitize", help="Clean invisible and unsafe text artifacts.")
    sanitize_parser.add_argument("--input", help="Direct input string.")
    sanitize_parser.add_argument("--file", help="Input text file.")
    sanitize_parser.add_argument("--stdin", action="store_true", help="Read from stdin.")
    sanitize_parser.add_argument("--output", help="Optional cleaned output file.")
    sanitize_parser.add_argument(
        "--preserve-bidi-marks",
        action="store_true",
        help="Keep LRM/RLM, bidi embeddings, PDF, isolates, and U+FEFF (leading BOM still removed).",
    )
    add_runtime_flags(sanitize_parser)

    # --- CONTACTS COMMAND SETUP ---
    contacts_parser = subparsers.add_parser("contacts", help="Extract and validate emails and phones.")
    contacts_parser.add_argument("--file", help="Input text file.")
    contacts_parser.add_argument("--stdin", action="store_true", help="Read from stdin.")
    contacts_parser.add_argument("--output", help="Optional CSV output file.")
    contacts_parser.add_argument(
        "--min-confidence",
        type=float,
        default=None,
        metavar="FLOAT",
        help="Minimum confidence for extracted contacts (default: min_confidence_threshold from .dataguardrc, else 0.3).",
    )
    contacts_parser.add_argument("--show-rejected", action="store_true", help="Include rejected candidates in the report.")
    add_runtime_flags(contacts_parser)

    # --- AUDIT COMMAND SETUP ---
    audit_parser = subparsers.add_parser("audit", help="Analyze password strength.")
    audit_parser.add_argument("--password", help="Analyze a single password.")
    audit_parser.add_argument("--file", help="Password file, one per line.")
    audit_parser.add_argument("--stdin", action="store_true", help="Read from stdin.")
    audit_parser.add_argument("--show", action="store_true", help="Show the real password in output.")
    audit_parser.add_argument("--min-length", type=int, help="Minimum target length.")
    audit_parser.add_argument("--no-dictionary", action="store_true", help="Skip dictionary checks.")
    audit_parser.add_argument("--no-entropy", action="store_true", help="Skip entropy scoring.")
    audit_parser.add_argument(
        "--export",
        help="Write per-password analysis JSON (includes full plaintext secrets; treat the file as sensitive).",
    )
    add_runtime_flags(audit_parser)

    # --- LOGS COMMAND SETUP ---
    logs_parser = subparsers.add_parser(
        "logs",
        help="Parse server logs and flag heuristic threats (triage aid; not a SIEM or WAF).",
    )
    logs_parser.add_argument("--file", help="Input log file.")
    logs_parser.add_argument("--stdin", action="store_true", help="Read from stdin.")
    logs_parser.add_argument("--format", choices=["auto", "apache", "nginx", "generic"], default="auto", help="Force a log format.")
    logs_parser.add_argument("--top", type=int, help="How many offenders to show.")
    logs_parser.add_argument("--threats-only", action="store_true", help="Only print detected threats.")
    logs_parser.add_argument(
        "--export",
        help="Write parsed log entries as JSON (URLs, IPs, user agents; treat the file as operational/sensitive).",
    )
    add_runtime_flags(logs_parser)

    # --- CSV COMMAND SETUP ---
    csv_parser = subparsers.add_parser("csv", help="Repair CSV data and convert it to JSON.")
    csv_parser.add_argument("--file", help="Input CSV file.")
    csv_parser.add_argument("--stdin", action="store_true", help="Read from stdin.")
    csv_parser.add_argument("--output", help="Optional JSON output file.")
    csv_parser.add_argument("--delimiter", choices=["auto", ",", ";", "|", "tab"], default="auto", help="Delimiter override.")
    csv_parser.add_argument("--quarantine", help="Optional CSV file for rejected rows.")
    csv_parser.add_argument("--no-types", action="store_true", help="Skip type inference.")
    add_runtime_flags(csv_parser)

    # --- HTML COMMAND SETUP ---
    html_parser = subparsers.add_parser(
        "html",
        help="Best-effort HTML cleanup via heuristics/regex (not a substitute for hardened HTML parsers or CSP).",
    )
    html_parser.add_argument("--input", help="Direct HTML string.")
    html_parser.add_argument("--file", help="Input HTML/text file.")
    html_parser.add_argument("--stdin", action="store_true", help="Read from stdin.")
    html_parser.add_argument("--mode", choices=["plain", "safe"], default="plain", help="Sanitization mode.")
    html_parser.add_argument("--allow", help="Comma-separated allowlist override for safe mode.")
    html_parser.add_argument("--output", help="Optional output file.")
    html_parser.add_argument("--show-diff", action="store_true", help="Include diff details in the report.")
    add_runtime_flags(html_parser)

    # --- AUTO COMMAND SETUP ---
    auto_parser = subparsers.add_parser("auto", help="Auto-detect input type and route it to the right module.")
    auto_parser.add_argument("--file", help="Input file to detect.")
    auto_parser.add_argument("--stdin", action="store_true", help="Read from stdin.")
    auto_parser.add_argument("--output", help="Optional output file for the routed module.")
    auto_parser.add_argument("--dry-run", action="store_true", help="Only show detection results without running a module.")
    add_runtime_flags(auto_parser)

    # --- BATCH COMMAND SETUP ---
    batch_parser = subparsers.add_parser("batch", help="Scan a directory and auto-process matching files.")
    batch_parser.add_argument("--dir", required=True, help="Directory to scan.")
    batch_parser.add_argument("--recursive", action="store_true", help="Scan subdirectories.")
    batch_parser.add_argument("--pattern", default="*", help="Glob pattern filter.")
    batch_parser.add_argument("--output-dir", required=True, help="Directory for per-file outputs.")
    batch_parser.add_argument("--batch-report", help="Optional JSON summary file.")
    add_runtime_flags(batch_parser)

    # --- CONFIG COMMAND SETUP ---
    config_parser = subparsers.add_parser("config", help="Show or update DataGuard defaults.")
    config_parser.add_argument("--set", nargs="+", help="Update config keys using key=value pairs.")

    # --- INFO & EXAMPLES COMMAND SETUP ---
    subparsers.add_parser("examples", help="Show example commands.")
    subparsers.add_parser("info", help="Show environment and module health information.")
    
    # Return the fully configured parser object
    return parser


# Merge command-line flags with the static .dataguardrc configuration file
def resolve_runtime_config(args: argparse.Namespace) -> dict:
    # Load settings from the local or global config file
    config, config_path, load_warnings = load_config()
    if load_warnings and not getattr(args, "quiet", False):
        for msg in load_warnings:
            sys.stderr.write(f"[WARN] config: {msg}\n")
    # Store the path to the config file for reporting purposes
    config["config_path"] = str(config_path)

    # Check if the user provided an output format flag
    if getattr(args, "pipe_format", None):
        config["pipe_format"] = args.pipe_format
    # Check if the user provided a report format flag
    if getattr(args, "report_format", None):
        config["report_format"] = args.report_format
    # Check if the user explicitly disabled colors via command line
    if getattr(args, "no_color", False):
        config["color_enabled"] = False
    # Check if the user provided a verbosity level (e.g. -vv)
    if getattr(args, "verbose", 0):
        config["verbosity"] = args.verbose
    # Check if the user enabled strict mode (failures on warnings)
    if getattr(args, "strict", False):
        config["strict_mode"] = True
    # Return the final merged dictionary of runtime settings
    return config


def validate_input_sources(args: argparse.Namespace, command: str) -> None:
    """Reject ambiguous combinations of --input / --password / --file / --stdin."""
    file_p = getattr(args, "file", None)
    use_stdin = bool(getattr(args, "stdin", False))
    input_val = getattr(args, "input", None)
    password = getattr(args, "password", None)

    if command == "audit":
        n = (1 if password is not None else 0) + (1 if file_p else 0) + (1 if use_stdin else 0)
        if n > 1:
            raise InputError("Use only one of --password, --file, or --stdin for audit.")
        return

    if command in ("sanitize", "html"):
        if input_val is not None and file_p:
            raise InputError("Use either --input or --file, not both.")
        if input_val is not None and use_stdin:
            raise InputError("Use either --input or --stdin, not both.")
        if file_p and use_stdin:
            raise InputError("Use either --file or --stdin, not both.")
        return

    if command in ("contacts", "logs", "csv", "auto"):
        if file_p and use_stdin:
            raise InputError("Use either --file or --stdin, not both.")


# Identify where the input data is coming from (String flag, Stdin, or File)
def read_command_input(args: argparse.Namespace) -> tuple[str, dict]:
    # Check if a direct string was passed via --input (for sanitize/html)
    if getattr(args, "input", None) is not None:
        return args.input, {"path": "<direct-input>", "encoding": "utf-8", "read_warnings": []}
    # Check if a single password was passed via --password (for audit)
    if getattr(args, "password", None) is not None:
        return args.password, {"path": "<direct-input>", "encoding": "utf-8", "read_warnings": []}
    # Otherwise, use the standard utility to resolve file path or standard input
    return read_input_text(file_path=getattr(args, "file", None), use_stdin=getattr(args, "stdin", False))


def emit_input_read_warnings(metadata: dict, *, quiet: bool) -> None:
    if quiet:
        return
    for msg in metadata.get("read_warnings") or []:
        sys.stderr.write(f"[WARN] input: {msg}\n")


def merge_input_read_warnings(result: dict, input_metadata: dict) -> None:
    warnings = input_metadata.get("read_warnings") or []
    if not warnings:
        return
    meta = result.setdefault("metadata", {})
    prior = meta.get("read_warnings")
    if prior is None:
        meta["read_warnings"] = list(warnings)
    elif isinstance(prior, list):
        meta["read_warnings"] = list(prior) + list(warnings)
    else:
        meta["read_warnings"] = [prior, *warnings]


# Create a callback function to report progress during long-running tasks
def progress_callback_factory(quiet: bool) -> Callable[[int], None] | None:
    # If quiet mode is on, we don't want any progress messages
    if quiet:
        return None

    # Define the actual callback that writes progress to the error stream
    def callback(line_number: int) -> None:
        sys.stderr.write(f"Processed {line_number} lines...\n")

    # Return the defined function for use in modules
    return callback


# Write the final processed data to either a file or the console's stdout
def write_primary_output_if_needed(output_text: str, output_path: str | None) -> None:
    # If a specific output file path was provided
    if output_path:
        # Write the text to the file system
        write_text_file(output_path, output_text)
        # Exit the function
        return
    # Otherwise, write the results directly to the standard output stream
    sys.stdout.write(output_text)
    # Ensure there is a trailing newline for clean console displays
    if output_text and not output_text.endswith("\n"):
        sys.stdout.write("\n")


# Decide whether to print the "Standardized Report" based on user flags
def maybe_write_report(result: dict, args: argparse.Namespace, runtime_config: dict) -> None:
    # If quiet mode is enabled, never write a report
    if getattr(args, "quiet", False):
        return
    # Write the report if --report is set or if we are in HTML mode showing diffs
    if getattr(args, "report", False) or getattr(args, "show_diff", False):
        try:
            write_report(
                result,
                report_format=runtime_config.get("report_format", "text"),
                color_enabled=bool(runtime_config.get("color_enabled", True)),
                report_file=getattr(args, "report_file", None),
            )
        except ValueError as exc:
            raise InputError(str(exc)) from exc


# Determine the final OS exit code based on whether errors or warnings occurred
def compute_exit_code(result: dict, strict_mode: bool) -> int:
    # If hard errors were found during processing
    if result.get("errors"):
        # Exit code 2 represents a failure
        return 2
    # If strict mode is ON and warnings were found
    if strict_mode and result.get("warnings"):
        # Exit code 2 represents a failure in strict mode
        return 2
    # If warnings were found but strict mode is OFF
    if result.get("warnings"):
        # Exit code 1 represents success but with alerts
        return 1
    # Perfect execution with no issues
    return 0


# Route the input data to the specific analysis module with the correct parameters
def run_named_module(module_name: str, text: str, metadata: dict, args: argparse.Namespace, runtime_config: dict) -> dict:
    # Prepare common metadata shared across all module runners
    common = {"source_name": metadata.get("path", "<input>")}
    # Logic for string sanitization
    if module_name == "sanitize":
        return string_sanitizer.run(
            text,
            {
                **common,
                "strip_bidi_format_marks": not getattr(args, "preserve_bidi_marks", False),
            },
        )
    # Logic for contact extraction (emails/phones)
    if module_name == "contacts":
        # Resolve the confidence threshold from flags or config files
        min_confidence = resolve_contacts_min_confidence(getattr(args, "min_confidence", None), runtime_config)
        return contact_extractor.run(
            text,
            {
                **common,
                "min_confidence": min_confidence,
                "show_rejected": getattr(args, "show_rejected", False),
                "progress_callback": progress_callback_factory(getattr(args, "quiet", False)),
            },
        )
    # Logic for password auditing
    if module_name == "audit":
        return password_checker.run(
            text,
            {
                **common,
                "single_password": getattr(args, "password", None),
                "show_password": getattr(args, "show", False),
                # Resolve min length from command line, then config, then default to 8
                "min_length": getattr(args, "min_length", runtime_config.get("password_min_length", 8)) or runtime_config.get("password_min_length", 8),
                "no_dictionary": getattr(args, "no_dictionary", False),
                "no_entropy": getattr(args, "no_entropy", False),
            },
        )
    # Logic for log file parsing
    if module_name == "logs":
        return log_parser.run(
            text,
            {
                **common,
                "format": getattr(args, "format", "auto"),
                # Show top N offenders based on config or flag
                "top": getattr(args, "top", runtime_config.get("log_top_n", 10)) or runtime_config.get("log_top_n", 10),
                "threats_only": getattr(args, "threats_only", False),
            },
        )
    # Logic for CSV repair and conversion
    if module_name == "csv":
        return csv_converter.run(
            text,
            {
                **common,
                "delimiter": getattr(args, "delimiter", "auto"),
                "strict": getattr(args, "strict", False),
                "no_types": getattr(args, "no_types", False),
            },
        )
    # Logic for HTML cleaning
    if module_name == "html":
        allowed_tags = None
        # Parse the comma-separated string of allowed tags into a list
        if getattr(args, "allow", None):
            allowed_tags = [item.strip().lower() for item in args.allow.split(",") if item.strip()]
        return html_sanitizer.run(
            text,
            {
                **common,
                "mode": getattr(args, "mode", "plain"),
                "allowed_tags": allowed_tags,
                "show_diff": getattr(args, "show_diff", False),
            },
        )
    # If a module name is passed that we don't recognize
    raise InputError(f"Unknown module: {module_name}")


# Implementation for the 'auto' subcommand which detects file type before running
def handle_auto(args: argparse.Namespace, runtime_config: dict) -> int:
    validate_input_sources(args, "auto")
    text, metadata = read_command_input(args)
    emit_input_read_warnings(metadata, quiet=getattr(args, "quiet", False))
    # Call the auto-detection module to get the best-fit module and confidence
    detection = detect_module(text, file_path=getattr(args, "file", None))
    # If the user only wanted to see the detection without processing
    if args.dry_run:
        # Format the detection dict as JSON and print
        output = json.dumps(detection, indent=2)
        write_primary_output_if_needed(output, getattr(args, "output", None))
        return 0

    # Route the text to the detected module
    routed_result = run_named_module(detection["module"], text, metadata, args, runtime_config)
    merge_input_read_warnings(routed_result, metadata)
    # Inject detection metadata into the final result record
    routed_result["metadata"]["detection_reason"] = detection["reason"]
    routed_result["metadata"]["detection_scores"] = detection["scores"]
    # Add detection details to the human-readable summary
    routed_result["summary"] = f"{detection['reason']}. {routed_result['summary']}"
    # Serialize the output based on pipe settings
    output_text = serialize_primary_output(routed_result["output"], pipe_format=runtime_config.get("pipe_format", "text"))
    # Finalize the output stream
    write_primary_output_if_needed(output_text, getattr(args, "output", None))
    # Optionally show the report
    maybe_write_report(routed_result, args, runtime_config)
    # Return calculated exit code
    return compute_exit_code(routed_result, runtime_config.get("strict_mode", False))


# Generate a standardized output filename for files processed in batch mode
def output_path_for_batch(output_dir: Path, input_path: Path, module_name: str) -> Path:
    # Look up the correct extension for the module (e.g. .csv for contacts)
    suffix = MODULE_OUTPUT_SUFFIX.get(module_name, ".txt")
    # Return the new path: /output/original_name_cleaned.extension
    return output_dir / f"{input_path.stem}_cleaned{suffix}"


# Implementation for processing an entire directory of files
def handle_batch(args: argparse.Namespace, runtime_config: dict) -> int:
    # Convert directory strings to Path objects
    target_dir = Path(args.dir)
    output_dir = Path(args.output_dir)
    # Ensure the output folder exists
    output_dir.mkdir(parents=True, exist_ok=True)

    # Validate that the source directory is actually a directory
    if not target_dir.exists() or not target_dir.is_dir():
        raise InputError(f"Batch directory does not exist: {target_dir}")

    # Use rglob if recursive scanning was requested, otherwise use standard glob
    iterator = target_dir.rglob("*") if args.recursive else target_dir.glob("*")
    # Filter for real files that match the provided naming pattern (e.g. *.log)
    files = [path for path in iterator if path.is_file() and fnmatch(path.name, args.pattern)]
    # Initialize trackers for results and stats
    results = []
    module_counts = {}
    warning_count = 0
    error_count = 0

    # Iterate through every matched file
    for file_path in files:
        # Read the file content
        text, metadata = read_text_file(str(file_path))
        emit_input_read_warnings(metadata, quiet=getattr(args, "quiet", False))
        # Detect the data type for this specific file
        detection = detect_module(text, file_path=str(file_path))
        # Run the analysis
        result = run_named_module(detection["module"], text, metadata, args, runtime_config)
        merge_input_read_warnings(result, metadata)
        # Determine where to save the cleaned result
        destination = output_path_for_batch(output_dir, file_path, detection["module"])
        # Save the primary cleaned data
        write_text_file(str(destination), serialize_primary_output(result["output"], pipe_format=runtime_config.get("pipe_format", "text")))
        # Build a record for the batch summary
        result_record = {
            "input_file": str(file_path),
            "detected_module": detection["module"],
            "output_file": str(destination),
            "warnings": result.get("warnings", []),
            "errors": result.get("errors", []),
            "summary": result.get("summary", ""),
        }
        # Append to master list and update running counts
        results.append(result_record)
        module_counts[detection["module"]] = module_counts.get(detection["module"], 0) + 1
        warning_count += len(result.get("warnings", []))
        error_count += len(result.get("errors", []))

    # Construct the final summary payload
    summary_payload = {
        "files_processed": len(files),
        "module_counts": module_counts,
        "total_warnings": warning_count,
        "total_errors": error_count,
        "results": results,
    }

    # If the user wants a JSON report of the entire batch operation
    if args.batch_report:
        write_text_file(args.batch_report, json.dumps(summary_payload, indent=2, ensure_ascii=False))

    # Build a human-readable summary for the console
    summary_lines = [
        f"Files processed: {len(files)}",
        "Per-module counts:",
    ]
    # Add per-module statistics
    for module_name in sorted(module_counts):
        summary_lines.append(f"- {module_name}: {module_counts[module_name]}")
    summary_lines.append(f"Total warnings: {warning_count}")
    summary_lines.append(f"Total errors: {error_count}")
    # Output the batch summary to the console
    write_primary_output_if_needed("\n".join(summary_lines), None)
    # Return failure if any file errored, warning if warnings exist, else success
    return 2 if error_count else (1 if warning_count else 0)


# Implementation for reading and updating the tool's persistent configuration
def handle_config(args: argparse.Namespace) -> int:
    # If the user used --set key=value
    if args.set:
        # Parse the input pairs into a dictionary
        updates = parse_set_arguments(args.set)
        # Save the updates to the .dataguardrc file
        updated, load_warnings = persist_config_updates(updates)
        for msg in load_warnings:
            sys.stderr.write(f"[WARN] config: {msg}\n")
        # Show the newly updated configuration as JSON
        sys.stdout.write(json.dumps(updated, indent=2, ensure_ascii=False))
        sys.stdout.write("\n")
        return 0

    # Otherwise, just load and show the current configuration settings
    config, config_path, load_warnings = load_config()
    for msg in load_warnings:
        sys.stderr.write(f"[WARN] config: {msg}\n")
    payload = {"config_path": str(config_path), "values": config}
    sys.stdout.write(json.dumps(payload, indent=2, ensure_ascii=False))
    sys.stdout.write("\n")
    return 0


# Display a set of helpful command-line examples to the user
def handle_examples() -> int:
    examples = """# Use `dg-clean` instead of `python -m dataguard` if another package named dataguard is installed.
python -m dataguard sanitize --input "Hi\\u200b there"
python -m dataguard contacts --file contacts.txt --output contacts.csv --report
python -m dataguard audit --password "TrickyPass123!" --report
python -m dataguard logs --file access.log --top 5 --threats-only
python -m dataguard csv --file broken.csv --output output.json --quarantine rejected.csv
python -m dataguard html --file user_input.html --mode safe --allow p,a,strong,img --report
python -m dataguard auto --file mystery.txt --report
python -m dataguard batch --dir incoming --pattern "*.txt" --output-dir cleaned --batch-report batch.json"""
    # Write the examples to stdout
    sys.stdout.write(examples + "\n")
    return 0


# Diagnostic command to check the health of the tool and its environment
def handle_info() -> int:
    module_health = {}
    # Check if each registered module runner is correctly imported and callable
    for name, runner in MODULE_RUNNERS.items():
        try:
            module_health[name] = "ok" if callable(runner) else "not-callable"
        except Exception as exc:
            module_health[name] = f"error: {exc}"
    # Gather system and version data
    payload = {
        "version": __version__,
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "modules": module_health,
    }
    # Output health report as JSON
    sys.stdout.write(json.dumps(payload, indent=2, ensure_ascii=False))
    sys.stdout.write("\n")
    return 0


# Main execution logic that ties the parser to the handlers
def main(argv: list[str] | None = None) -> int:
    # Build the parser definitions
    parser = build_parser()
    # Parse the arguments from sys.argv (or the passed argv list)
    args = parser.parse_args(argv)

    if args.command == "config":
        try:
            return handle_config(args)
        except (DataGuardError, ValueError) as exc:
            sys.stderr.write(f"[ERROR] config: {exc}\n")
            return 3
    if args.command == "examples":
        try:
            return handle_examples()
        except DataGuardError as exc:
            sys.stderr.write(f"[ERROR] examples: {exc}\n")
            return 3
    if args.command == "info":
        try:
            return handle_info()
        except DataGuardError as exc:
            sys.stderr.write(f"[ERROR] info: {exc}\n")
            return 3

    # Load the runtime configuration for functional commands
    runtime_config = resolve_runtime_config(args)

    try:
        # Dispatch to complex runners (auto, batch)
        if args.command == "auto":
            return handle_auto(args, runtime_config)
        if args.command == "batch":
            return handle_batch(args, runtime_config)

        validate_input_sources(args, args.command)
        text, metadata = read_command_input(args)
        emit_input_read_warnings(metadata, quiet=getattr(args, "quiet", False))
        result = run_named_module(args.command, text, metadata, args, runtime_config)
        merge_input_read_warnings(result, metadata)

        # Handle subcommand-specific file exports (Audit analysis, Log entries, CSV quarantine)
        if args.command == "audit" and getattr(args, "export", None):
            write_text_file(args.export, json.dumps(result["analyses"], indent=2, ensure_ascii=False))
            if not getattr(args, "quiet", False):
                sys.stderr.write(
                    "[NOTICE] audit --export wrote JSON with full plaintext passwords; keep the file private.\n"
                )
        if args.command == "logs" and getattr(args, "export", None):
            write_text_file(args.export, json.dumps(result["entries"], indent=2, ensure_ascii=False))
            if not getattr(args, "quiet", False):
                sys.stderr.write(
                    "[NOTICE] logs --export wrote JSON with parsed fields (URLs, IPs, user agents); "
                    "handle the file appropriately.\n"
                )
        if args.command == "csv" and getattr(args, "quarantine", None):
            quarantine_lines = []
            for row in result.get("quarantine_rows", []):
                quarantine_lines.append(",".join('' if value is None else str(value) for value in row))
            write_text_file(args.quarantine, "\n".join(quarantine_lines))

        # Format and output the primary result
        output_text = serialize_primary_output(result["output"], pipe_format=runtime_config.get("pipe_format", "text"))
        write_primary_output_if_needed(output_text, getattr(args, "output", None))
        # Final report generation
        maybe_write_report(result, args, runtime_config)
        # Determine the final exit status
        return compute_exit_code(result, runtime_config.get("strict_mode", False))
    
    # Catch-all for handled internal exceptions
    except DataGuardError as exc:
        sys.stderr.write(f"[ERROR] {args.command}: {exc}\n")
        return 3
    # Catch-all for unhandled generic failures
    except Exception as exc:
        sys.stderr.write(f"[ERROR] {args.command}: Unexpected failure: {exc}\n")
        return 3


# Standard boilerplate to execute the script when run directly
if __name__ == "__main__":
    # Use SystemExit to properly return the integer exit code to the shell
    raise SystemExit(main())