"""Whole-project progress dashboard: the function table with filtering, sorting,
pagination, the histogram, and the sweep/autoname control sections."""

from __future__ import annotations

import html
from pathlib import Path
from urllib.parse import quote

from src.analysis.symbols import symbol_map_load
from src.core.project import (
	Project,
	ProjectStats,
	project_aggregate,
	project_load,
	project_sdk_vas,
)
from src.webui.diff import _attempts_listing
from src.webui.state import (
	_job_for,
	_sweep_for,
)
from src.webui.templates import (
	badge,
	crumbs,
	page,
	panel,
	sweep_bar,
)
from src.webui.views_index import _discover_projects


def view_progress_index(current_path: str | None) -> str:
	projects = _discover_projects()
	if projects:
		rows = "".join(
			f"<tr>"
			f'<td><a href="/progress?path={quote(path)}">{html.escape(name)}</a></td>'
			f'<td class="num">{count:,} fns</td>'
			f'<td class="muted">{html.escape(path)}</td>'
			f"</tr>"
			for path, name, count in projects
		)
		recent = panel(
			"Detected projects",
			f"<table><thead><tr><th>name</th><th>size</th><th>path</th></tr></thead>"
			f"<tbody>{rows}</tbody></table>",
			meta=f"{len(projects)} found · scans projects/ and examples/",
		)
	else:
		recent = ""

	open_form = panel(
		"Open project",
		"""
<form class="inline" action="/progress" method="get">
  <input type="text" name="path" placeholder="/path/to/project.json"{autofocus}>
  <button type="submit">Aggregate →</button>
</form>
<p class="muted" style="margin-top: 12px;">
  Point at a <span style="color: var(--cyan);">project.json</span> manifest.
  Generate one with <span style="color: var(--cyan);">python -m src enumerate</span>.
</p>
""".replace("{autofocus}", " autofocus" if not projects else ""),
	)
	body = crumbs(("home", "/"), ("progress", None)) + recent + open_form
	return page("progress", body, current_path=current_path)


def _sweep_section(project_path_str: str, stats: ProjectStats) -> tuple[str, bool]:
	"""Render the Ghidra-attempt-all control. Returns (panel_html, is_active).

	Active → a live progress banner + bar + stop button (the caller turns on
	auto-refresh). Idle → a launch button sized by the untouched count, plus a
	one-line summary of the previous sweep if one ran this server session.
	"""
	sweep = _sweep_for(project_path_str)
	active = sweep is not None and sweep.is_active()
	untouched = stats.untouched_functions
	path_q = quote(project_path_str)

	if active and sweep is not None:
		pct = (sweep.done / sweep.total * 100.0) if sweep.total else 100.0
		current = (
			f' · <span class="muted">at {html.escape(sweep.current)}</span>'
			if sweep.current
			else ""
		)
		body = (
			'<div class="run-banner sweeping">'
			f'{badge("pending", "SWEEPING")}'
			f'<span class="sweep-counts">{sweep.done}/{sweep.total} · '
			f'<span class="green">{sweep.matched} matched</span> · '
			f"{sweep.partial} partial · {sweep.no_match} no-match · {sweep.failed} failed</span>"
			f"{current}"
			f'<form class="inline sweep-stop" method="post" action="/sweep/stop?path={path_q}">'
			'<button type="submit">stop</button></form>'
			"</div>"
			f"{sweep_bar(pct)}"
		)
		return panel("Ghidra sweep", body, meta=f"{pct:.0f}% · serial baseline pass"), True

	finished = ""
	if sweep is not None and not active:
		if sweep.state == "error":
			finished = (
				f'<p class="muted tight" style="margin-top:10px;">last sweep errored: '
				f"{html.escape(sweep.error or '')}</p>"
			)
		else:
			verb = "stopped" if sweep.state == "stopped" else "finished"
			finished = (
				f'<p class="muted tight" style="margin-top:10px;">last sweep {verb}: '
				f"{sweep.done}/{sweep.total} done · "
				f'<span class="green">{sweep.matched} matched</span> · '
				f"{sweep.partial} partial · {sweep.no_match} no-match · {sweep.failed} failed</p>"
			)

	if untouched == 0:
		button = '<p class="muted">every function has a baseline — nothing untouched to sweep.</p>'
	else:
		button = (
			f'<form class="inline" method="post" action="/sweep/launch?path={path_q}">'
			'<button type="submit" class="btn-run">⚡ Ghidra attempt all</button>'
			f'<span class="muted" style="margin-left:10px;">{untouched:,} untouched · '
			"compiles each Ghidra warm-start, no LLM</span></form>"
		)
	return panel("Ghidra sweep", button + finished), False


def _autoname_section(project_path_str: str, named: int | None) -> str:
	"""The project-wide 'auto-name from strings' control + last-run notice.

	`named` is the count from a just-completed run (via the ?named= redirect),
	or None when the page wasn't reached from an auto-name."""
	path_q = quote(project_path_str)
	notice = ""
	if named is not None and named > 0:
		notice = (
			f'<div class="run-banner done">{badge("matched", "NAMED")}'
			f'<span>auto-named <span class="green">{named}</span> '
			f"function{'s' if named != 1 else ''} from referenced strings</span></div>"
		)
	elif named is not None:
		notice = (
			f'<div class="run-banner">{badge("pending", "—")}'
			'<span class="muted">no new high-confidence names found</span></div>'
		)
	button = (
		f'<form class="inline" method="post" action="/autoname?path={path_q}">'
		'<button type="submit" class="btn-run">✎ Auto-name stubs from strings</button>'
		'<span class="muted" style="margin-left:10px;">names tiny functions whose single '
		"referenced string is unambiguous · clean-room, re-runnable</span></form>"
	)
	return panel("Auto-name", notice + button)


def view_progress(
	project_path_str: str,
	current_path: str | None,
	*,
	page_n: int = 1,
	page_size: int = 100,
	filters: dict[str, str] | None = None,
	named: int | None = None,
) -> str:
	project = project_load(project_path_str)
	stats = project_aggregate(project, sdk_vas=_sdk_vas_for(project_path_str))
	symbols = symbol_map_load(project_path_str)
	filters = filters or {}

	all_statuses = list(stats.function_statuses)
	filtered = _apply_filters(all_statuses, filters, symbols)
	filtered = _apply_sort(filtered, filters.get("sort", "va"), filters.get("order", "asc"))

	total_unfiltered = stats.total_functions
	total = len(filtered)
	total_pages = max(1, (total + page_size - 1) // page_size)
	page_n = max(1, min(page_n, total_pages))
	start = (page_n - 1) * page_size
	page_slice = filtered[start : start + page_size]

	summary = _progress_summary(project, stats)
	histogram = _progress_histogram(stats)
	filter_bar = _progress_filter_bar(project_path_str, filters, page_size, total, total_unfiltered)
	table = _progress_function_table(
		page_slice,
		project_path_str,
		symbols=symbols,
		page=page_n,
		total_pages=total_pages,
		total=total,
		page_size=page_size,
		filters=filters,
	)

	sweep_html, sweep_active = _sweep_section(project_path_str, stats)

	rng = f"{start + 1}–{min(start + page_size, total)} of {total}" if total else "0 of 0"
	body = (
		crumbs(("home", "/"), ("progress", "/progress"), (project.name, None))
		+ f'<div class="page-actions"><a href="/stats?path={quote(project_path_str)}">'
		"📊 model stats →</a></div>"
		+ panel(
			"Project", summary, meta=f"{total_unfiltered} functions · {stats.total_bytes:,} bytes"
		)
		+ sweep_html
		+ _autoname_section(project_path_str, named)
		+ panel("Match distribution", histogram, meta="function count per 10% bucket")
		+ panel("Functions", filter_bar + table, meta=f"{rng} · page {page_n}/{total_pages}")
	)
	# Refresh only while the sweep is live; server drops data-live to stop the poller.
	refresh = 4 if sweep_active else None
	return page(
		f"progress · {project.name}", body, current_path=current_path, refresh_seconds=refresh
	)


def _model_stats_table(rows: list) -> str:
	"""Per-model leaderboard table. Each model is credited for the functions
	whose best.c it currently owns."""
	if not rows:
		return (
			'<div class="muted center" style="padding: 18px;">'
			"no model attributions yet — run a function to populate this</div>"
		)
	body_rows = []
	for r in rows:
		win_pct = (r.matched / r.functions * 100.0) if r.functions else 0.0
		body_rows.append(
			"<tr>"
			f'<td><span class="cyan">{html.escape(r.model)}</span></td>'
			f'<td class="num">{r.functions}</td>'
			f'<td class="num green">{r.matched}</td>'
			f'<td class="num">{r.partial}</td>'
			f'<td class="num">{win_pct:.0f}%</td>'
			f'<td class="num">{r.avg_best_percent:.2f}%</td>'
			"</tr>"
		)
	return (
		"<table>"
		"<thead><tr>"
		"<th>model</th><th>functions</th><th>matched</th><th>partial</th>"
		"<th>match rate</th><th>avg best</th>"
		"</tr></thead>"
		f"<tbody>{''.join(body_rows)}</tbody>"
		"</table>"
		'<p class="muted tight" style="margin-top: 10px;">'
		"A model is credited for a function when its attempt produced the standing "
		"best.c. Re-running with another model reassigns credit only if it beats the "
		'current best. <span class="cyan">propagated</span> = byte-identical twins '
		'auto-finished from a solved representative; <span class="cyan">ghidra</span> '
		"= matched straight from the warm-start.</p>"
	)


def _workspace_attempt_triples(root: Path) -> list[tuple[int, str | None, float | None]]:
	"""(attempt_number, model, match_percent) for one workspace's attempts.

	Reads only what's on disk (no objdiff derivation) so a whole-project scan
	stays cheap — the diff JSON already exists for any attempt that ran."""
	return [
		(a["n"], a["model"], a["match_percent"])
		for a in _attempts_listing(root, derive_missing=False)
	]


def _model_attempt_table(rows: list) -> str:
	"""Per-model effort table: attempts spent vs. attempts that moved the needle."""
	if not rows:
		return '<div class="muted center" style="padding: 18px;">no per-attempt history yet</div>'
	body_rows = [
		(
			"<tr>"
			f'<td><span class="cyan">{html.escape(r.model)}</span></td>'
			f'<td class="num">{r.attempts}</td>'
			f'<td class="num">{r.improved}</td>'
			f'<td class="num green">{r.matched}</td>'
			f'<td class="num">{r.improve_rate:.0f}%</td>'
			"</tr>"
		)
		for r in rows
	]
	return (
		"<table>"
		"<thead><tr>"
		"<th>model</th><th>attempts</th><th>improved</th><th>100% hits</th><th>improve rate</th>"
		"</tr></thead>"
		f"<tbody>{''.join(body_rows)}</tbody>"
		"</table>"
		'<p class="muted tight" style="margin-top: 10px;">'
		'Counted from the per-attempt <span class="cyan">.model</span> sidecars. '
		"<b>attempts</b> = compiles tagged to the model; <b>improved</b> = those that "
		"raised the function's running best; <b>improve rate</b> = improved ÷ attempts "
		"(efficiency — a model can win few functions cheaply or many by grinding).</p>"
	)


def _progress_link(project_path_str: str) -> str:
	return f"/progress?path={quote(project_path_str)}"


_STATE_SORT_ORDER = {"matched": 0, "partial": 1, "untouched": 2}


def _apply_filters(statuses: list, f: dict[str, str], symbols=None) -> list:
	out = statuses
	state = f.get("state") or ""
	if state in ("matched", "partial", "untouched"):
		out = [s for s in out if s.state == state]
	query = (f.get("q") or "").strip().lower()
	if query:
		# Match machine name or human label so search finds either.
		def hit(s) -> bool:
			label = symbols.label_for(s.va).lower() if symbols else ""
			return query in s.name.lower() or query in label

		out = [s for s in out if hit(s)]
	try:
		min_size = int(f.get("min_size") or "")
		out = [s for s in out if s.size >= min_size]
	except ValueError:
		pass
	try:
		max_size = int(f.get("max_size") or "")
		out = [s for s in out if s.size <= max_size]
	except ValueError:
		pass
	return out


def _apply_sort(statuses: list, sort_key: str, order: str) -> list:
	reverse = order == "desc"

	def keyer(s):
		if sort_key == "name":
			return s.name
		if sort_key == "size":
			return s.size
		if sort_key == "best":
			return s.best_match_percent if s.best_match_percent is not None else -1.0
		if sort_key == "iters":
			return s.iterations
		if sort_key == "state":
			return _STATE_SORT_ORDER.get(s.state, 99)
		return s.va  # default: VA

	return sorted(statuses, key=keyer, reverse=reverse)


def _progress_filter_bar(
	project_path_str: str,
	f: dict[str, str],
	page_size: int,
	total_filtered: int,
	total_unfiltered: int,
) -> str:
	def opt(value: str, label: str, selected: str) -> str:
		sel = " selected" if value == selected else ""
		return f'<option value="{value}"{sel}>{label}</option>'

	state_sel = f.get("state", "")
	sort_sel = f.get("sort", "va")
	order_sel = f.get("order", "asc")

	state_options = "".join(
		opt(v, label, state_sel)
		for v, label in (
			("", "all"),
			("matched", "matched"),
			("partial", "partial"),
			("untouched", "untouched"),
		)
	)
	sort_options = "".join(
		opt(v, label, sort_sel)
		for v, label in (
			("va", "VA"),
			("name", "name"),
			("size", "size"),
			("best", "best %"),
			("iters", "iters"),
			("state", "state"),
		)
	)
	order_options = "".join(
		opt(v, label, order_sel)
		for v, label in (
			("asc", "↑ asc"),
			("desc", "↓ desc"),
		)
	)

	count_chip = (
		f'<span class="muted">{total_filtered:,} match'
		+ (f" · {total_unfiltered:,} total" if total_filtered != total_unfiltered else "")
		+ "</span>"
	)

	# Auto-apply: selects/number inputs submit on change; the text box debounces
	# so it filters as you type. Handlers are inline so they survive the live
	# poller's <main> innerHTML swap (which would drop addEventListener bindings).
	# requestSubmit() is guarded against a form detached by a mid-debounce swap.
	# The <noscript> apply button keeps the form usable with JS off.
	on_change = 'onchange="this.form.requestSubmit()"'
	on_type = (
		'oninput="clearTimeout(window._fbq);var f=this.form;'
		'window._fbq=setTimeout(function(){if(f.isConnected)f.requestSubmit();},400)"'
	)
	return f"""
<form class="filter-bar" method="get" action="/progress">
  <input type="hidden" name="path"      value="{html.escape(project_path_str)}">
  <input type="hidden" name="page_size" value="{page_size}">
  <label>state <select name="state" {on_change}>{state_options}</select></label>
  <label>name contains <input type="text" name="q" value="{html.escape(f.get("q", ""))}" placeholder="fn_002D" {on_type}></label>
  <label>size <input type="number" name="min_size" value="{html.escape(f.get("min_size", ""))}" placeholder="min" min="0" {on_change}>
    <span class="muted">–</span>
    <input type="number" name="max_size" value="{html.escape(f.get("max_size", ""))}" placeholder="max" min="0" {on_change}></label>
  <label>sort <select name="sort" {on_change}>{sort_options}</select> <select name="order" {on_change}>{order_options}</select></label>
  <noscript><button type="submit">apply</button></noscript>
  <a href="/progress?path={quote(project_path_str)}" class="clear-filters">clear</a>
  {count_chip}
</form>
"""


_SDK_SWATCH = "#5b7da6"  # distinct from the matched/partial/untouched scale


def _sdk_vas_for(project_path_str: str) -> frozenset[int]:
	"""SDK VAs from the sdk.json beside project.json (see `libmatch --save`), or
	empty → progress is reported over the whole image. Thin alias for the shared
	core helper so the web UI, CLI, and batch all read the manifest the same way."""
	return project_sdk_vas(project_path_str)


def _progress_summary(project: Project, stats: ProjectStats) -> str:
	m = stats.matched_functions
	p = stats.partial_functions
	u = stats.untouched_functions
	sdk = stats.sdk_functions
	total = stats.total_functions or 1
	# Bar spans the whole image; progress % below is measured against the game target (image minus SDK).
	game = stats.game_functions or 1

	seg_html = []
	for label, count, cls, inline in (
		("matched", m, "seg-matched", ""),
		("partial", p, "seg-partial", ""),
		("untouched", u, "seg-untouched", ""),
		("sdk", sdk, "", f"background:{_SDK_SWATCH};"),
	):
		pct = count / total * 100
		if pct <= 0:
			continue
		text = f"{label} {count}" if pct > 7 else ""
		cls_attr = f' class="{cls}"' if cls else ""
		seg_html.append(f'<div{cls_attr} style="flex: {pct:.4f};{inline}">{text}</div>')

	bar = '<div class="stacked-bar">' + "".join(seg_html) + "</div>"
	legend_items = [
		f'<span><span class="swatch matched"></span>matched · {m} ({m / game * 100:.1f}%)</span>',
		f'<span><span class="swatch partial"></span>partial · {p} ({p / game * 100:.1f}%)</span>',
		f'<span><span class="swatch untouched"></span>untouched · {u} ({u / game * 100:.1f}%)</span>',
	]
	if sdk:
		legend_items.append(
			f'<span><span class="swatch" style="background:{_SDK_SWATCH};"></span>'
			f"SDK · {sdk} (linked, not a target)</span>"
		)
	legend = '<div class="legend">' + "".join(legend_items) + "</div>"

	sdk_row = ""
	if sdk:
		sdk_row = (
			'  <div class="k">SDK (XDK, excluded)</div>'
			f'  <div class="v" style="color:{_SDK_SWATCH};">{sdk:,} functions / '
			f"{stats.sdk_bytes:,} bytes</div>\n"
		)

	return f"""
<div class="kv">
  <div class="k">name</div>           <div class="v amber">{html.escape(project.name)}</div>
  <div class="k">xbe</div>            <div class="v">{html.escape(str(project.xbe_path))}</div>
  <div class="k">workspaces</div>     <div class="v">{html.escape(str(project.workspace_root))}</div>
  <div class="k">game target</div>    <div class="v">{stats.game_functions:,} functions / {stats.game_bytes:,} bytes</div>
{sdk_row}  <div class="k">functions matched</div><div class="v green">{m} / {stats.game_functions}  ({m / game * 100:.2f}%)</div>
  <div class="k">bytes matched</div>  <div class="v green">{stats.matched_bytes:,} / {stats.game_bytes:,}  ({stats.game_matched_byte_percent:.2f}%)</div>
</div>
{bar}
{legend}
"""


def _progress_histogram(stats: ProjectStats) -> str:
	if stats.total_functions == 0:
		return '<div class="muted center" style="padding: 18px;">empty project</div>'

	# 11 buckets: 0% (untouched), 1-10, 11-20, ..., 91-100
	buckets = [0] * 11
	for s in stats.function_statuses:
		bp = s.best_match_percent
		if bp is None or bp <= 0.0:
			buckets[0] += 1
		elif bp >= 100.0:
			buckets[10] += 1
		else:
			idx = int(bp // 10) + 1
			buckets[min(idx, 10)] += 1

	max_count = max(buckets) or 1
	width = 800
	height = 160
	pad_l = 36
	pad_b = 28
	pad_t = 8
	pad_r = 8
	bar_area_w = width - pad_l - pad_r
	bar_area_h = height - pad_t - pad_b
	n_buckets = len(buckets)
	bar_w = bar_area_w / n_buckets

	bars = []
	labels = []
	for i, count in enumerate(buckets):
		if count == 0:
			continue
		h = (count / max_count) * bar_area_h
		x = pad_l + i * bar_w + 2
		y = pad_t + (bar_area_h - h)
		if i == 0:
			color = "var(--fg-faint)"
		elif i == 10:
			color = "var(--green)"
		elif i >= 7:
			color = "var(--amber)"
		else:
			color = "var(--cyan)"
		bars.append(
			f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w - 4:.1f}" height="{h:.1f}" '
			f'fill="{color}" opacity="0.85"/>'
		)
		bars.append(
			f'<text x="{x + (bar_w - 4) / 2:.1f}" y="{y - 4:.1f}" '
			f'fill="var(--fg)" font-size="10" text-anchor="middle">{count}</text>'
		)

	bucket_labels = [
		"0",
		"1-10",
		"11-20",
		"21-30",
		"31-40",
		"41-50",
		"51-60",
		"61-70",
		"71-80",
		"81-90",
		"91-100",
	]
	for i, lbl in enumerate(bucket_labels):
		cx = pad_l + i * bar_w + bar_w / 2
		labels.append(
			f'<text x="{cx:.1f}" y="{height - 10:.1f}" '
			f'fill="var(--fg-faint)" font-size="9" text-anchor="middle">{lbl}</text>'
		)

	# Y-axis ticks at 0, max/2, max
	y_ticks = []
	for v in (0, max_count // 2, max_count):
		y = pad_t + bar_area_h - (v / max_count * bar_area_h)
		y_ticks.append(
			f'<text x="{pad_l - 6:.1f}" y="{y + 3:.1f}" '
			f'fill="var(--fg-faint)" font-size="9" text-anchor="end">{v}</text>'
		)
		y_ticks.append(
			f'<line x1="{pad_l:.1f}" y1="{y:.1f}" x2="{width - pad_r:.1f}" y2="{y:.1f}" '
			f'stroke="rgba(180,196,212,0.06)"/>'
		)

	return (
		f'<svg class="hist" viewBox="0 0 {width} {height}" preserveAspectRatio="none">'
		+ "".join(y_ticks)
		+ "".join(bars)
		+ "".join(labels)
		+ '<text x="'
		+ str(pad_l)
		+ '" y="'
		+ str(height - 2)
		+ '" '
		'fill="var(--fg-faint)" font-size="9">match %</text>' + "</svg>"
	)


_PROVENANCE_TAG = {
	"user": '<span class="prov user" title="renamed by you">✎</span>',
	"sdk": '<span class="prov sdk" title="XDK library name (libmatch)">SDK</span>',
}


def _name_cell(s, symbols) -> str:
	"""Render the function name column: the human label up front, the machine
	`fn_<va>` name underneath when they differ, plus a provenance tag."""
	if symbols is None:
		return html.escape(s.name)
	label = symbols.label_for(s.va)
	provenance = symbols.provenance(s.va)
	tag = _PROVENANCE_TAG.get(provenance, "")
	if label == s.name:  # not renamed
		return html.escape(s.name)
	return (
		f'<span class="fn-label">{html.escape(label)}</span> {tag}'
		f'<div class="muted tight mono">{html.escape(s.name)}</div>'
	)


def _progress_function_table(
	page_slice,
	project_path_str: str,
	*,
	symbols=None,
	page: int,
	total_pages: int,
	total: int,
	page_size: int,
	filters: dict[str, str] | None = None,
) -> str:
	rows = []
	for s in page_slice:
		best_str = (
			f"{s.best_match_percent:.2f}%"
			if isinstance(s.best_match_percent, (int, float))
			else "—"
		)
		job = _job_for(s.workspace_path)
		if job and job.is_active():
			state_label = '<span class="fn-state partial">running</span>'
			action = (
				f'<a href="/decomp/run?root={html.escape(str(s.workspace_path))}'
				f'&amp;path={quote(project_path_str)}">iter {job.iterations_completed}/{job.max_iterations} →</a>'
			)
		else:
			state_label = f'<span class="fn-state {s.state}">{s.state}</span>'
			if s.state != "untouched" or s.iterations > 0:
				action = (
					f'<a href="/decomp/run?root={html.escape(str(s.workspace_path))}'
					f'&amp;path={quote(project_path_str)}">view →</a>'
					f'  <a href="/decomp/launch?path={quote(project_path_str)}'
					f'&amp;va={s.va:#x}" class="action-rerun">↻ rerun</a>'
				)
			else:
				action = (
					f'<a href="/decomp/launch?path={quote(project_path_str)}'
					f'&amp;va={s.va:#x}">▶ run</a>'
				)
		model = s.model or (job.model if job else "") or ""
		rows.append(
			f"<tr>"
			f"<td>{_name_cell(s, symbols)}</td>"
			f'<td class="num">0x{s.va:08x}</td>'
			f'<td class="size">{s.size}</td>'
			f"<td>{state_label}</td>"
			f"<td>{best_str}</td>"
			f'<td class="num">{s.iterations}</td>'
			f'<td class="muted">{html.escape(model)}</td>'
			f"<td>{action}</td>"
			f"</tr>"
		)

	pager = _progress_pager(
		project_path_str,
		page=page,
		total_pages=total_pages,
		total=total,
		page_size=page_size,
		filters=filters or {},
	)
	empty_msg = (
		"no functions match these filters" if filters and any(filters.values()) else "empty project"
	)
	return (
		"<table>"
		"<thead><tr>"
		"<th>name</th><th>VA</th><th>size</th><th>state</th>"
		"<th>best</th><th>iters</th><th>model</th><th></th>"
		"</tr></thead>"
		f"<tbody>{''.join(rows) or f'<tr><td colspan=8 class="muted center">{empty_msg}</td></tr>'}</tbody>"
		"</table>" + pager
	)


def _progress_pager(
	project_path_str: str,
	*,
	page: int,
	total_pages: int,
	total: int,
	page_size: int,
	filters: dict[str, str] | None = None,
) -> str:
	if total_pages <= 1:
		return ""

	filter_qs = _filters_to_qs(filters or {})

	def link(p: int, label: str, cls: str = "") -> str:
		qs = f"path={quote(project_path_str)}&page={p}&page_size={page_size}" + filter_qs
		if cls:
			return f'<a href="/progress?{qs}" class="{cls}">{label}</a>'
		return f'<a href="/progress?{qs}">{label}</a>'

	pages: list[str] = []
	if page > 1:
		pages.append(link(1, "« first"))
		pages.append(link(page - 1, "‹ prev"))
	else:
		pages.append('<span class="pg-disabled">« first</span>')
		pages.append('<span class="pg-disabled">‹ prev</span>')

	window = _pager_window(page, total_pages)
	last = 0
	for p in window:
		if last and p > last + 1:
			pages.append('<span class="pg-ellipsis">…</span>')
		if p == page:
			pages.append(f'<span class="pg-cur">{p}</span>')
		else:
			pages.append(link(p, str(p)))
		last = p

	if page < total_pages:
		pages.append(link(page + 1, "next ›"))
		pages.append(link(total_pages, "last »"))
	else:
		pages.append('<span class="pg-disabled">next ›</span>')
		pages.append('<span class="pg-disabled">last »</span>')

	hidden_filters = "".join(
		f'<input type="hidden" name="{k}" value="{html.escape(v)}">'
		for k, v in (filters or {}).items()
		if v
	)
	jump = (
		f'<form class="pg-jump" method="get" action="/progress">'
		f'<input type="hidden" name="path" value="{html.escape(project_path_str)}">'
		f'<input type="hidden" name="page_size" value="{page_size}">'
		f"{hidden_filters}"
		f'<span class="muted">jump</span>'
		f'<input type="number" name="page" min="1" max="{total_pages}" value="{page}">'
		f"</form>"
	)

	return (
		f'<div class="pager">'
		f'<span class="muted">{total:,} entries · page {page}/{total_pages} · {page_size}/page</span>'
		f'<div class="pages">{"".join(pages)}</div>'
		f"{jump}"
		f"</div>"
	)


def _filters_to_qs(filters: dict[str, str]) -> str:
	"""Encode active filter values as `&key=value` pairs for pagination links."""
	out = []
	for k, v in filters.items():
		if v:
			out.append(f"&{k}={quote(str(v))}")
	return "".join(out)


def _pager_window(page: int, total_pages: int, radius: int = 2) -> list[int]:
	"""Return sorted page numbers to display: always first/last plus a window around current."""
	pages = {1, total_pages, page}
	for d in range(1, radius + 1):
		if page - d >= 1:
			pages.add(page - d)
		if page + d <= total_pages:
			pages.add(page + d)
	return sorted(pages)
