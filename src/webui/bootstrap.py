"""Process bootstrap: repo root + bundled objdiff-cli env default.

Imported first by the package __init__ so the IVCS_OBJDIFF_CLI default is set
before any code that reads it runs. A UI-launched decomp run dies with
FileNotFoundError on first diff without this.
"""

import os

from src.paths import RECON_DIR, REPO_ROOT

_BUNDLED_OBJDIFF = RECON_DIR / "objdiff-smoke" / "objdiff-cli"
if "IVCS_OBJDIFF_CLI" not in os.environ and _BUNDLED_OBJDIFF.is_file():
	os.environ["IVCS_OBJDIFF_CLI"] = str(_BUNDLED_OBJDIFF)

__all__ = ["REPO_ROOT"]
