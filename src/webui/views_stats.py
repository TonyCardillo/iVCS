"""Stats view: per-model leaderboards and the whole-image coverage verifier."""

from __future__ import annotations

import html
import time
from urllib.parse import quote

from src.core.project import (
	model_attempt_stats,
	model_stats,
	project_aggregate,
	project_load,
)
from src.verify.integrator import (
	image_coverage,
	image_verify_cache_load,
)
from src.webui.state import (
	_verify_for,
	xbe_cached_load,
)
from src.webui.templates import (
	_progress_bar,
	crumbs,
	page,
	panel,
)
from src.webui.views_progress import (
	_model_attempt_table,
	_model_stats_table,
	_progress_link,
	_sdk_vas_for,
	_workspace_attempt_triples,
)


def _image_coverage_table(cov) -> str:
	"""Per-section whole-image byte breakdown: how much of each section (code and
	data) is reconstructed from source vs. carried verbatim as a gap."""
	rows = []
	for s in sorted(cov.sections, key=lambda s: -s.virtual_size):
		pct = (s.matched_bytes / s.virtual_size * 100.0) if s.virtual_size else 0.0
		# Classify by whether we enumerated functions here, NOT the exec flag —
		# this XBE marks .rdata/.data executable, so the flag lies (see docs).
		kind = "code" if s.enumerated_bytes else "data"
		rows.append(
			"<tr>"
			f"<td>{html.escape(s.name)}</td>"
			f'<td class="muted">{kind}</td>'
			f'<td class="num">{s.virtual_size:,}</td>'
			f'<td class="num green">{s.matched_bytes:,}</td>'
			f'<td class="num">{pct:.1f}%</td>'
			f'<td class="num muted">{s.gap_bytes:,}</td>'
			"</tr>"
		)
	return (
		"<table>"
		"<thead><tr><th>section</th><th>kind</th><th>size</th>"
		"<th>from source</th><th>%</th><th>gap / verbatim</th></tr></thead>"
		f"<tbody>{''.join(rows)}</tbody></table>"
		'<p class="muted tight" style="margin-top: 10px;">'
		"<b>from source</b> = bytes of matched functions (reconstructed C). "
		"<b>gap / verbatim</b> = padding, data, jump tables, and un-matched code — "
		"carried from the original, not yet from source. Data sections are entirely gap.</p>"
	)


def _verify_buttons(project_path_str: str) -> str:
	"""Run button: byte-splice verify with our own relocator."""
	path_q = quote(project_path_str)
	return (
		'<div class="hint-row" style="margin-top:10px;">'
		f'<form class="hint-form" method="post" action="/verify/launch?path={path_q}">'
		'<button type="submit" class="btn-run">▶ verify (splice)</button></form>'
		'<span class="muted">recompiles every matched function · needs Wine + toolchain</span>'
		"</div>"
	)


def _verify_panel(project_path_str: str) -> tuple[str, bool]:
	"""(panel_html, is_active). Live progress while a verify job runs; otherwise
	the cached result (or a prompt) plus run buttons. The verifier recompiles every
	matched function, so it's a background job — never computed on a page render."""
	job = _verify_for(project_path_str)
	if job is not None and job.is_active():
		pct = (job.done / job.total * 100.0) if job.total else 100.0
		current = (
			f' · <span class="muted">at {html.escape(job.current)}</span>' if job.current else ""
		)
		body = (
			'<div class="run-banner sweeping">'
			'<span class="badge pending">VERIFYING</span>'
			f'<span class="sweep-counts">{job.done}/{job.total} matched functions · '
			f"splice</span>{current}</div>"
			f'<div class="sweep-bar"><div class="sweep-bar-fill" style="width:{pct:.1f}%"></div></div>'
		)
		return panel("Splice-verified", body, meta=f"{pct:.0f}% · recompiling + splicing"), True

	failed_note = ""
	if job is not None and job.state == "error":
		failed_note = (
			f'<p class="muted tight">last verify errored: {html.escape(job.error or "")}</p>'
		)

	cache = image_verify_cache_load(project_path_str)
	if cache is None:
		body = (
			'<p class="muted">Not yet computed — recompiles every matched function '
			"(needs Wine + the toolchain). Run it as a background job:</p>"
			f"{_verify_buttons(project_path_str)}{failed_note}"
		)
		return panel("Splice-verified", body), False

	pct = cache.get("verified_percent", 0.0)
	checked = "—"
	gen = cache.get("generated_at")
	if isinstance(gen, (int, float)):
		secs = max(0, int(time.time() - gen))
		checked = f"{secs // 3600}h{(secs % 3600) // 60}m ago" if secs >= 60 else "just now"
	body = (
		'<div class="kv">'
		'<div class="k">verified</div>'
		f'<div class="v green">{cache.get("verified_bytes", 0):,} / '
		f"{cache.get('matched_bytes', 0):,} matched bytes ({pct:.1f}%)</div>"
		'<div class="k">functions</div>'
		f'<div class="v">{cache.get("functions_verified", 0)} / '
		f"{cache.get('functions', 0)} fully reproduced</div>"
		'<div class="k">checked</div>'
		f'<div class="v">{checked}</div>'
		"</div>"
		f"{_progress_bar(pct)}"
		'<p class="muted tight" style="margin-top:8px;">Matched functions recompiled, '
		"placed at their real VA, and byte-compared against the original image.</p>"
		f"{_verify_buttons(project_path_str)}{failed_note}"
	)
	return panel("Splice-verified", body), False


def view_stats(project_path_str: str) -> str:
	"""Per-model performance leaderboard for one project."""
	project = project_load(project_path_str)
	sdk_vas = _sdk_vas_for(project_path_str)
	stats = project_aggregate(project, sdk_vas=sdk_vas)
	rows = model_stats(stats.function_statuses)
	attempt_rows = model_attempt_stats(
		[_workspace_attempt_triples(s.workspace_path) for s in stats.function_statuses]
	)
	parsed = xbe_cached_load(str(project.xbe_path))
	cov = image_coverage(stats.function_statuses, parsed, sdk_vas=sdk_vas)

	attributed = sum(r.functions for r in rows)
	meta = f"{attributed} of {stats.game_functions:,} game functions attributed to a model"
	total_attempts = sum(r.attempts for r in attempt_rows)
	cov_meta = (
		f"{cov.matched_bytes:,} / {cov.total_bytes:,} bytes from source "
		f"({cov.from_source_percent:.1f}% of the whole image)"
	)
	verify_html, verify_active = _verify_panel(project_path_str)
	body = (
		crumbs(
			("home", "/"),
			("progress", "/progress"),
			(project.name, _progress_link(project_path_str)),
		)
		+ panel("Models — who won", _model_stats_table(rows), meta=meta)
		+ panel(
			"Models — effort per attempt",
			_model_attempt_table(attempt_rows),
			meta=f"{total_attempts:,} attempts across all functions",
		)
		+ panel(
			"Whole-image reconstruction",
			_image_budget_summary(cov) + _image_coverage_table(cov),
			meta=cov_meta,
		)
		+ verify_html
	)
	refresh = 4 if verify_active else None
	return page(f"stats · {project.name}", body, current_path=None, refresh_seconds=refresh)


def _image_budget_summary(cov) -> str:
	"""A one-line byte budget that separates the gap into 'code still to do' vs.
	'data/assets carried verbatim' — so a tiny from-source % reads as 'barely
	started decompiling', not 'barely reproduces'."""
	data_other = cov.gap_bytes
	cells = [
		("from source", cov.matched_bytes, "green"),
		("in progress", cov.partial_bytes, "amber"),
		("code to do", cov.todo_code_bytes, ""),
		("SDK (linked)", cov.sdk_bytes, "cyan"),
		("data / assets", data_other, "muted"),
	]
	spans = " · ".join(f'<span class="{cls}">{label}</span> {val:,}' for label, val, cls in cells)
	return (
		f'<p class="tight" style="margin-bottom:10px;">{spans}'
		f" &nbsp;=&nbsp; {cov.total_bytes:,} B total</p>"
	)
