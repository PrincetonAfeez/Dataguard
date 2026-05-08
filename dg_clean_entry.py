"""Console entry that always loads this tree's `dataguard` package (avoids shadowing by same-named installs).

Use ``dg-clean`` (or ``python path/to/dg_clean_entry.py``) when another PyPI-style ``dataguard`` is installed:
``python -m dataguard`` may still import that other package depending on ``sys.path``.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _loaded_dataguard_package_root(module: object) -> Path | None:
    """Best-effort resolved filesystem root of an already-imported ``dataguard`` package."""
    init_file = getattr(module, "__file__", None)
    if init_file:
        try:
            return Path(init_file).resolve().parent
        except OSError:
            return None
    paths = getattr(module, "__path__", None)
    if paths:
        try:
            return Path(next(iter(paths))).resolve()
        except (OSError, StopIteration):
            return None
    return None

# purge all dataguard modules to ensure that the next import will load from this tree, even if some of the modules were already imported from elsewhere (e.g. by a test runner or an embedded run).
def _purge_dataguard_modules() -> None:
    for key in list(sys.modules):
        if key == "dataguard" or key.startswith("dataguard."):
            del sys.modules[key]

# Ensure that the local dataguard package is loaded, even if another dataguard package is already installed or imported.
def _ensure_local_dataguard() -> None:
    """If ``dataguard`` is missing or was imported from elsewhere, reload it from this checkout.

    Only clears ``sys.modules`` when the cached package is not already this tree, so embedded or
    multi-phase runs that already have the correct package pay a smaller cost.
    """
    repo_root = Path(__file__).resolve().parent
    init_path = repo_root / "__init__.py"
    if not init_path.is_file():
        raise ImportError(f"Expected DataGuard package at {repo_root} (missing __init__.py).")

    existing = sys.modules.get("dataguard")
    if existing is not None:
        loaded_root = _loaded_dataguard_package_root(existing)
        if loaded_root is not None and loaded_root == repo_root:
            return

    _purge_dataguard_modules()

    spec = importlib.util.spec_from_file_location(
        "dataguard",
        init_path,
        submodule_search_locations=[str(repo_root)],
    )
    if spec is None or spec.loader is None:
        raise ImportError("Could not create a loader for the local dataguard package.")

    package = importlib.util.module_from_spec(spec)
    sys.modules["dataguard"] = package
    spec.loader.exec_module(package)

# The main entry point for the ``dg-clean`` console script, which ensures that the local dataguard package is loaded before delegating to the CLI main function.
def main(argv: list[str] | None = None) -> int:
    _ensure_local_dataguard()
    from dataguard.cli import main as cli_main

    return cli_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
