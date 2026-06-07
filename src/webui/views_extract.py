"""Standalone "extract from disc image" page.

Point it at an Xbox disc image (XISO), list the files at its root, and stream one
out to a destination on disk — the usual job being to recover a project's
`default.xbe` from its game disc. Extraction seeks straight to the file's sectors
and streams it, so it runs synchronously in the request (no worker thread).
"""

from __future__ import annotations

import html
import os
from pathlib import Path
from urllib.parse import quote

from src.formats.xiso import (
	XisoFormatError,
	xiso_image_file_extract,
	xiso_image_root_list,
)
from src.webui.bootstrap import REPO_ROOT
from src.webui.templates import (
	badge,
	crumbs,
	page,
	panel,
)

# Where to look for disc images to offer as one-click choices. Defaults to the
# user's Xbox folder; override with IVCS_DISC_DIR.
_DISC_DIR = Path(os.environ.get("IVCS_DISC_DIR", "~/Games/Xbox")).expanduser()
_DISC_GLOBS = ("*.iso", "*.xiso", "*.xiso.iso")
# Extracted files land here by default; the dest field is editable per row.
_EXTRACT_DIR = REPO_ROOT / "extracted"


def _size_human(n: int) -> str:
	value = float(n)
	for unit in ("B", "KB", "MB", "GB"):
		if value < 1024 or unit == "GB":
			return f"{value:,.0f} {unit}" if unit == "B" else f"{value:.2f} {unit}"
		value /= 1024
	return f"{n} B"


def _discover_disc_images() -> list[tuple[Path, int]]:
	"""Find candidate disc images under _DISC_DIR (best-effort, non-recursive)."""
	if not _DISC_DIR.is_dir():
		return []
	found: dict[Path, int] = {}
	for pattern in _DISC_GLOBS:
		for path in _DISC_DIR.glob(pattern):
			if path.is_file():
				found[path] = path.stat().st_size
	return sorted(found.items(), key=lambda item: item[0].name.lower())


def _status_banner(status: str) -> str:
	"""Render the post-extraction outcome banner from a `ok:...`/`err:...` token."""
	if not status:
		return ""
	kind, _, detail = status.partition(":")
	if kind == "ok":
		return f'<div class="rerun-notice">{badge("matched", "EXTRACTED")}<span>{html.escape(detail)}</span></div>'
	if kind == "err":
		return f'<div class="error">{html.escape(detail)}</div>'
	return ""


def _image_choices_html(selected: str) -> str:
	images = _discover_disc_images()
	if not images:
		return (
			f'<p class="muted">No disc images found under <span class="cyan">{html.escape(str(_DISC_DIR))}</span>. '
			'Type a full path above, or set <span class="cyan">IVCS_DISC_DIR</span>.</p>'
		)
	rows = []
	for path, size in images:
		is_sel = str(path) == selected
		mark = badge("pending", "SELECTED") if is_sel else ""
		rows.append(
			f'<a class="proj-card" href="/extract?image={quote(str(path))}">'
			f'<div class="proj-name">{html.escape(path.name)} {mark}</div>'
			f'<div class="proj-meta">{_size_human(size)}</div></a>'
		)
	return f'<div class="proj-grid">{"".join(rows)}</div>'


def _file_rows_html(image: str) -> str:
	"""List the image's root files, each with its own extract form. Returns an
	inline error notice if the image can't be read as an XISO."""
	try:
		entries = sorted(xiso_image_root_list(image), key=lambda e: e.name.lower())
	except (OSError, XisoFormatError) as e:
		return f'<div class="error">cannot read {html.escape(image)}: {html.escape(str(e))}</div>'

	rows = []
	for entry in entries:
		if entry.is_directory:
			rows.append(
				f'<div class="kv"><div class="k">{badge("", "DIR")}</div>'
				f'<div class="v muted">{html.escape(entry.name)}</div></div>'
			)
			continue
		default_dest = _EXTRACT_DIR / entry.name
		rows.append(
			f'<form method="post" action="/extract/run?image={quote(image)}" class="extract-row">'
			f'<input type="hidden" name="file" value="{html.escape(entry.name)}">'
			f'<span class="amber" style="min-width:14ch;display:inline-block;">{html.escape(entry.name)}</span>'
			f'<span class="muted num" style="min-width:11ch;display:inline-block;">{_size_human(entry.size)}</span>'
			f'<input type="text" name="dest" value="{html.escape(str(default_dest))}" size="48">'
			f'<button type="submit">extract</button>'
			"</form>"
		)
	return f'<div class="extract-list">{"".join(rows)}</div>'


def view_extract(image: str = "", status: str = "") -> str:
	"""The extract page: an image picker, plus the chosen image's file list."""
	image = image.strip()
	picker_form = (
		'<form method="get" action="/extract" class="extract-pick">'
		f'<input type="text" name="image" value="{html.escape(image)}" size="64" '
		'placeholder="/path/to/Game.xiso.iso">'
		'<button type="submit">list files</button>'
		"</form>"
	)
	body_parts = [
		crumbs(("home", "/"), ("extract", None)),
		_status_banner(status),
		panel(
			"Extract from disc image",
			picker_form + _image_choices_html(image),
			meta=f"scanning {_DISC_DIR}",
		),
	]
	if image:
		body_parts.append(panel(f"Files in {Path(image).name}", _file_rows_html(image)))
	return page("extract", "\n".join(body_parts), current_path=None)


def handle_extract_run(image: str, form: dict[str, str]) -> str:
	"""Extract the requested file and return the /extract redirect with a status
	token. Never raises for the expected failures — they ride back in the URL."""
	image = image.strip()
	name = form.get("file", "").strip()
	dest = form.get("dest", "").strip()
	back = f"/extract?image={quote(image)}"
	if not (image and name and dest):
		return f"{back}&status={quote('err:image, file and dest are all required')}"
	try:
		written = xiso_image_file_extract(image, name, dest)
	except (OSError, XisoFormatError) as e:
		return f"{back}&status={quote(f'err:{e}')}"
	return f"{back}&status={quote(f'ok:wrote {name} ({written:,} bytes) → {dest}')}"
