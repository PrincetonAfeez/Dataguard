"""Tests for the dg-clean bootstrap entrypoint."""

import subprocess
import sys
from pathlib import Path

import dg_clean_entry


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_ensure_local_idempotent_in_process() -> None:
    dg_clean_entry._ensure_local_dataguard()
    before = sys.modules["dataguard"]
    dg_clean_entry._ensure_local_dataguard()
    assert sys.modules["dataguard"] is before


def test_dg_clean_entry_script_version() -> None:
    script = REPO_ROOT / "dg_clean_entry.py"
    result = subprocess.run(
        [sys.executable, str(script), "--version"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "DataGuard" in result.stdout
