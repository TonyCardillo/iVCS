"""Shared frontend helpers: uniform not-found errors and project+XBE loading.

Each subcommand is a thin frontend; these keep the "manifest missing → ERROR,
exit 1" and "load project then its XBE" boilerplate in one place.
"""

from __future__ import annotations

import sys
from pathlib import Path

from src.core.project import Project, project_load
from src.formats.xbe import ParsedXbe, xbe_load


def path_exists_or_error(path: Path) -> bool:
	"""True if `path` is a file; otherwise print a uniform ERROR and return False."""
	if path.is_file():
		return True
	print(f"ERROR: {path} not found", file=sys.stderr)
	return False


def project_xbe_load(project_path: Path) -> tuple[Project, ParsedXbe] | None:
	"""Load a project manifest and its XBE, or print ERROR and return None."""
	if not path_exists_or_error(project_path):
		return None
	project = project_load(project_path)
	return project, xbe_load(project.xbe_path)
