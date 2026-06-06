"""The landing page: project discovery and the index view."""

from __future__ import annotations

import html
from pathlib import Path
from urllib.parse import quote

from src.core.project import project_load
from src.webui.bootstrap import REPO_ROOT
from src.webui.styles import LOGO
from src.webui.templates import (
	page,
	panel,
)


def view_index() -> str:
	projects = _discover_projects()
	if projects:
		proj_rows = "".join(
			f'<a class="proj-card" href="/progress?path={quote(path)}">'
			f'<div class="proj-name">{html.escape(name)}</div>'
			f'<div class="proj-meta">{count:,} functions</div>'
			f'<div class="proj-path muted">{html.escape(path.replace(str(REPO_ROOT) + "/", ""))}</div>'
			f"</a>"
			for path, name, count in projects
		)
		proj_panel = panel(
			"Projects",
			f'<div class="proj-grid">{proj_rows}</div>',
			meta=f"{len(projects)} detected · click to open dashboard",
		)
	else:
		proj_panel = panel(
			"Projects",
			'<p class="muted">No projects detected. Drop a '
			'<span class="cyan">project.json</span> under <span class="cyan">projects/</span> '
			"to get started.</p>",
		)

	body = f'<div class="ascii-logo">{LOGO}</div>\n{proj_panel}'
	return page("iVCS", body, current_path=None)


def _discover_projects() -> list[tuple[str, str, int]]:
	"""Find project manifests under projects/ and examples/.

	Returns a list of (manifest_path_str, project_name, function_count)
	tuples. Skips manifests that fail to load. Cheap enough to redo on
	every index render — there will rarely be more than a handful.
	"""
	found: list[tuple[str, str, int]] = []
	seen: set[Path] = set()
	for root in (REPO_ROOT / "projects", REPO_ROOT / "examples"):
		if not root.is_dir():
			continue
		for manifest in sorted(root.glob("*/project.json")):
			seen.add(manifest)
		for manifest in sorted(root.glob("*.project.json")):
			seen.add(manifest)
	for manifest in sorted(seen):
		try:
			project = project_load(manifest)
			found.append((str(manifest), project.name, len(project.functions)))
		except OSError, ValueError, KeyError:
			# A malformed manifest is skipped; a programming bug is left to surface.
			continue
	return found
