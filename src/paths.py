"""Single source of truth for repo-relative resource locations.

Library modules live at varying depths under ``src/`` (``src/formats/xbe.py``,
``src/decomp/compile_tool.py``, …), so file-relative ``Path(__file__).parent.parent``
no longer reaches the repo root. Resolve it once here — from ``src/paths.py``, the
parent of ``src/`` is always the repo root — and derive every bundled-asset path from
it, so a module's depth never matters again.
"""

from pathlib import Path

# src/paths.py -> src/ -> <repo root>
REPO_ROOT = Path(__file__).resolve().parent.parent

DATA_DIR = REPO_ROOT / "data"
COMPILERS_DIR = REPO_ROOT / "compilers"
GHIDRA_SCRIPTS_DIR = REPO_ROOT / "ghidra_scripts"
GHIDRA_HOME = REPO_ROOT / "tools" / "ghidra_12.0.3_PUBLIC"
RECON_DIR = REPO_ROOT / "recon"
