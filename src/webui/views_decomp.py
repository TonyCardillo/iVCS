"""Decomp workspace views: one function's run timeline and a single attempt's
source + diff, with the symbol/notes and string-hint side panels."""

from __future__ import annotations

import html
import time
from pathlib import Path
from urllib.parse import quote

from src.analysis.notes import notes_load
from src.analysis.strings_xref import (
	function_string_refs,
	string_label_sanitize,
)
from src.analysis.symbols import symbol_map_load
from src.core.project import (
	json_load_or_none,
	project_load,
)
from src.drivers.launcher import JobInfo
from src.webui.diff import (
	_asm_dual_columns,
	_attempt_info,
	_attempt_model_label,
	_attempts_listing,
	_best_attempt,
	_guess_function_name,
	_va_from_workspace,
)
from src.webui.state import (
	_job_for,
	xbe_cached_load,
)
from src.webui.templates import (
	_progress_bar,
	badge,
	crumbs,
	page,
	panel,
)


def _path_query_suffix(current_path: str | None) -> str:
	"""`&path=<quoted>` if a project is in scope, else empty. Keeps the
	project breadcrumb resolvable as the user clicks through decomp pages."""
	return f"&path={quote(current_path)}" if current_path else ""


def _project_crumb(current_path: str | None) -> tuple[str, str | None]:
	"""Middle breadcrumb for decomp views. Falls back to a non-linked
	'workspace' label when there is no project context (e.g., direct URL
	without `?path=...`), since the old `/decomp` index page is gone."""
	if current_path:
		try:
			project = project_load(current_path)
			return (project.name, f"/progress?path={quote(current_path)}")
		except OSError, ValueError, KeyError:
			# A malformed/missing manifest falls back gracefully; a programming
			# bug (AttributeError/TypeError) is left to surface, not swallowed.
			pass
	return ("workspace", None)


def _status_badge(result_json: dict | None) -> str:
	if result_json is None:
		return badge("pending", "in progress")
	reason = result_json.get("termination_reason", "?")
	success = result_json.get("success", False)
	cls = (
		"matched"
		if success
		else ("failed" if reason in ("hard_timeout", "llm_no_progress") else "partial")
	)
	return badge(cls, reason)


def _sparkline_svg(attempts: list[dict]) -> str:
	series = [a["match_percent"] for a in attempts]
	if not series:
		return '<div class="muted center" style="padding: 18px;">no attempts yet</div>'
	pts: list[tuple[float, float]] = []
	n = len(series)
	width = 800
	height = 56
	for i, mp in enumerate(series):
		x = (i / max(n - 1, 1)) * (width - 8) + 4
		v = mp if mp is not None else 0.0
		y = height - 4 - (v / 100.0) * (height - 12)
		pts.append((x, y))
	path = "M " + " L ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
	dots = "".join(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="2.5" fill="#5fd7ff"/>' for x, y in pts)
	grid = "".join(
		f'<line x1="0" x2="{width}" y1="{height - 4 - p / 100 * (height - 12):.1f}" '
		f'y2="{height - 4 - p / 100 * (height - 12):.1f}" '
		f'stroke="rgba(180,196,212,0.08)" stroke-width="1"/>'
		for p in (25, 50, 75, 100)
	)
	return (
		f'<svg class="spark" viewBox="0 0 {width} {height}" preserveAspectRatio="none">'
		f"{grid}"
		f'<path d="{path}" stroke="#5fd7ff" stroke-width="1.5" fill="none" opacity="0.9"/>'
		f"{dots}"
		"</svg>"
	)


def _symbol_notes_panel(root: Path, current_path: str | None) -> str:
	"""Rename box + free-text notes for the function this workspace decompiles.

	The rename is a display label only — the machine symbol stays `fn_<va>`, so
	nothing here touches the matching or verify path. Notes are keyed by the
	workspace dir, so they work even without a project path; rename needs the
	project path to locate `symbols.json`.
	"""
	va = _va_from_workspace(root)
	notes_text = notes_load(root)

	rename_form = ""
	if current_path and va is not None:
		symbols = symbol_map_load(current_path)
		label = symbols.label_for(va)
		provenance = symbols.provenance(va)
		current = (
			f'<span class="muted tight">current: <span class="amber">{html.escape(label)}</span>'
			f" · {provenance}</span>"
			if provenance != "default"
			else '<span class="muted tight">no custom name yet</span>'
		)
		rename_form = f"""
<form class="rename-form" method="post" action="/symbol/rename">
  <input type="hidden" name="path" value="{html.escape(current_path)}">
  <input type="hidden" name="va"   value="0x{va:08X}">
  <input type="hidden" name="root" value="{html.escape(str(root))}">
  <label>name <input type="text" name="label" value="{html.escape(label)}" placeholder="CPlayer__Update"></label>
  <button type="submit">rename</button>
  <span class="muted tight">blank to revert to fn_{va:08X}</span>
  {current}
</form>
"""

	notes_form = f"""
<form class="notes-form" method="post" action="/notes/save">
  <input type="hidden" name="root" value="{html.escape(str(root))}">
  <input type="hidden" name="path" value="{html.escape(current_path or "")}">
  <textarea name="notes" rows="5" placeholder="calling convention, struct layout, what this function does…">{html.escape(notes_text)}</textarea>
  <button type="submit">save notes</button>
</form>
"""
	hints = _string_hints_html(root, current_path, va)
	meta = "display label · machine symbol stays fn_<va>" if va is not None else "notes"
	return panel("Symbol & notes", rename_form + hints + notes_form, meta=meta)


def _string_hints_html(root: Path, current_path: str | None, va: int | None) -> str:
	"""Naming hints from the string literals this function references.

	Each sanitizable string becomes a one-click button that adopts it as the
	display label (POST to /symbol/rename). Binary-derived and clean-room — a
	"quick start" for naming an unknown function from what it prints/asserts.
	Silent (empty) when there's no project path, no matching function, or no
	referenced strings.
	"""
	if not current_path or va is None:
		return ""
	try:
		project = project_load(current_path)
		fn = next((f for f in project.functions if f.va == va), None)
		if fn is None:
			return ""
		parsed = xbe_cached_load(str(project.xbe_path))
		refs = function_string_refs(parsed, fn.va, fn.size)
	except OSError, ValueError, KeyError:
		# Hints are best-effort for a malformed/missing manifest or XBE; a real
		# programming bug is left to surface rather than silently blanking the panel.
		return ""
	if not refs:
		return ""

	shown, rows = refs[:12], []
	for s in shown:
		disp = html.escape(s if len(s) <= 48 else s[:45] + "…")
		label = string_label_sanitize(s)
		if label:
			rows.append(
				'<form class="hint-form" method="post" action="/symbol/rename">'
				f'<input type="hidden" name="path" value="{html.escape(current_path)}">'
				f'<input type="hidden" name="va" value="0x{va:08X}">'
				f'<input type="hidden" name="root" value="{html.escape(str(root))}">'
				f'<input type="hidden" name="label" value="{html.escape(label)}">'
				f'<button type="submit" class="hint" title="adopt: {html.escape(s)}">'
				f'{disp} → <span class="cyan">{html.escape(label)}</span></button>'
				"</form>"
			)
		else:
			rows.append(f'<span class="hint muted" title="{html.escape(s)}">{disp}</span>')
	more = f'<span class="muted tight">+{len(refs) - 12} more</span>' if len(refs) > 12 else ""
	return (
		'<div class="string-hints">'
		'<div class="muted tight">referenced strings — click to adopt as the name:</div>'
		f'<div class="hint-row">{"".join(rows)}{more}</div>'
		"</div>"
	)


def view_decomp_run(root_str: str, current_path: str | None) -> str:
	root = Path(root_str)
	if not root.is_dir():
		raise FileNotFoundError(f"workspace not a directory: {root}")

	job = _job_for(root)
	result = json_load_or_none(root / "result.json")
	attempts = _attempts_listing(root)
	best = (result or {}).get("best_match_percent")
	if best is None:
		best = max((a["match_percent"] or 0 for a in attempts), default=None)
	fn_name = (
		(result or {}).get("function_name")
		or (job.function_name if job else None)
		or _guess_function_name(root)
		or "?"
	)

	best_at = _best_attempt(attempts)
	best_model = (result or {}).get("model") or (best_at["model"] if best_at else None)
	best_model_row = ""
	if best_model:
		where = f" · #{best_at['n']:04d}" if best_at else ""
		best_model_row = (
			'  <div class="k">best by</div>         '
			f'<div class="v cyan">{html.escape(best_model)}{where}</div>\n'
		)

	header_body = f"""
<div class="kv">
  <div class="k">workspace</div>      <div class="v">{html.escape(str(root))}</div>
  <div class="k">function</div>       <div class="v amber">{html.escape(fn_name)}</div>
  <div class="k">attempts</div>       <div class="v">{len(attempts)}</div>
  <div class="k">best match</div>     <div class="v green">{(f"{best:.2f}%" if isinstance(best, (int, float)) else "—")}</div>
{best_model_row}  <div class="k">status</div>         <div class="v">{_status_badge(result)}</div>
</div>
{_progress_bar(best)}
{_sparkline_svg(attempts)}
<div class="muted tight" style="margin-top: 8px;">match % across attempts</div>
"""

	last_n = attempts[-1]["n"] if attempts else 0
	job_active = bool(job and job.is_active())

	timeline_rows = []
	for a in attempts:
		is_in_flight = job_active and a["n"] == last_n
		label, badge_cls, badge_text = _attempt_status_labels(a, is_in_flight=is_in_flight)
		if label is not None:
			mp_html = f'<span class="muted">{label}</span>'
			status_html = badge(badge_cls, badge_text)
		else:
			mp = a["match_percent"]
			cls = "" if mp > 0 else "zero"
			mp_html = f'<span class="mp {cls}">{mp:.2f}%</span>'
			status_html = badge("matched", "100%") if mp == 100.0 else badge("partial", "partial")
		ghidra_tag = (
			'<span class="badge partial" title="Ghidra warm-start baseline">ghidra</span>'
			if a["n"] == 0
			else ""
		)
		attempt_model = _attempt_model_label(a, (result or {}).get("model"))
		model_chip = (
			f'<span class="attempt-model" title="model for this attempt">'
			f"{html.escape(attempt_model)}</span>"
			if attempt_model
			else ""
		)
		timeline_rows.append(
			f'<div class="attempt-row">'
			f'<span class="n">#{a["n"]:04d}</span>'
			f'<a class="openrow" href="/decomp/attempt?root={html.escape(str(root))}&n={a["n"]}">view source &amp; diff →</a>'
			f"{model_chip}"
			f'<span class="status">{mp_html}</span>'
			f'<span class="status">{ghidra_tag}{status_html}</span>'
			f"</div>"
		)
	timeline = (
		"".join(timeline_rows)
		or '<div class="muted center" style="padding: 18px;">no attempts on disk yet</div>'
	)

	ctx_h = (root / "ctx.h").read_text() if (root / "ctx.h").is_file() else "(missing)"
	best_c = (root / "best.c").read_text() if (root / "best.c").is_file() else "(no best.c yet)"

	banner = ""
	refresh = None
	if job:
		if job.is_active():
			refresh = 3
			elapsed = (
				int((time.time() if job.started_at else 0) - job.started_at)
				if job.started_at
				else 0
			)
			banner = (
				f'<div class="run-banner running">'
				f"{badge('pending', job.state.upper())}"
				f'<span>iter <span class="amber">{job.iterations_completed}</span>/{job.max_iterations}'
				f" · elapsed {elapsed}s / {int(job.hard_timeout_seconds)}s"
				f' · model <span class="cyan">{html.escape(job.model)}</span></span>'
				f'<span class="muted">auto-refreshing every 3s</span>'
				f"</div>"
			)
		elif job.state == "error":
			banner = (
				f'<div class="run-banner failed">'
				f"{badge('failed', 'ERROR')}"
				f'<span class="muted">{html.escape(job.error or "")}</span>'
				f"</div>"
			)
		else:
			reason = job.termination_reason or "done"
			best_str = (
				f"{job.best_match_percent:.2f}%"
				if isinstance(job.best_match_percent, (int, float))
				else "—"
			)
			banner = (
				f'<div class="run-banner done">'
				f"{badge('matched', 'FINISHED')}"
				f'<span>reason <span class="amber">{html.escape(reason)}</span>'
				f' · best <span class="green">{best_str}</span>'
				f" · iter {job.iterations_completed}/{job.max_iterations}</span>"
				f"</div>"
			)
	elif _run_interrupted(job, result, attempts):
		banner = _interrupted_banner(root, current_path)

	body = (
		crumbs(("home", "/"), _project_crumb(current_path), (root.name, None))
		+ banner
		+ _run_action_bar(root, current_path, job, has_attempts=bool(attempts))
		+ panel("Run", header_body, meta=fn_name)
		+ _symbol_notes_panel(root, current_path)
		+ panel("Attempts", timeline, meta=f"{len(attempts)} total")
		+ '<div class="split">'
		+ panel(
			"ctx.h",
			f'<pre class="code">{html.escape(ctx_h)}</pre>',
			meta="context header · prepended to every attempt",
		)
		+ panel(
			"best.c",
			f'<pre class="code">{html.escape(best_c)}</pre>',
			meta="highest-match attempt so far",
		)
		+ "</div>"
	)
	return page(
		f"decomp · {root.name}",
		body,
		current_path=current_path,
		refresh_seconds=refresh,
	)


def view_decomp_attempt(root_str: str, n: int, current_path: str | None) -> str:
	root = Path(root_str)
	if not root.is_dir():
		raise FileNotFoundError(f"workspace not a directory: {root}")

	info = _attempt_info(root, n)
	c_text = info["c_path"].read_text() if info["c_path"].is_file() else "(missing)"

	compile_error = ""
	if not info["diff_path"].is_file() and not info["compiled"]:
		stderr_path = info["c_path"].with_suffix(".stderr")
		compile_error = (
			stderr_path.read_text()
			if stderr_path.is_file()
			else "compile failed (no diff produced, no stderr captured)"
		)

	mp = info["match_percent"]
	mp_str = f"{mp:.2f}%" if isinstance(mp, (int, float)) else "—"

	head_body = f"""
<div class="kv">
  <div class="k">attempt</div>        <div class="v">#{n:04d}</div>
  <div class="k">workspace</div>      <div class="v muted">{html.escape(str(root))}</div>
  <div class="k">symbol</div>         <div class="v amber">{html.escape(info["function_symbol_name"] or "?")}</div>
  <div class="k">match</div>          <div class="v green">{mp_str}</div>
  <div class="k">compiled</div>       <div class="v">{"yes" if info["compiled"] else "no"}</div>
</div>
{_progress_bar(mp)}
"""

	sections = [
		crumbs(
			("home", "/"),
			_project_crumb(current_path),
			(
				root.name,
				f"/decomp/run?root={html.escape(str(root))}{_path_query_suffix(current_path)}",
			),
			(f"#{n:04d}", None),
		),
		panel(f"Attempt #{n:04d}", head_body),
	]
	if compile_error:
		sections.append(
			panel("Compile error", f'<pre class="code">{html.escape(compile_error)}</pre>')
		)
		sections.append(panel(f"{n:04d}.c", f'<pre class="code">{html.escape(c_text)}</pre>'))
	else:
		target_col, current_col, stats = _asm_dual_columns(
			info["diff_path"], info["function_symbol_name"]
		)
		matched, differs, target_name, current_name = stats
		sections.append(
			panel(
				"Compilation",
				(
					'<div class="codedual">'
					f'<div class="col left">'
					f'<div class="col-head"><span>target · {html.escape(target_name)}</span><span class="sub">{matched} match · {differs} diff</span></div>'
					f"{target_col}"
					"</div>"
					f'<div class="col right">'
					f'<div class="col-head"><span>current · {html.escape(current_name)}</span><span class="sub">&lt; del · &gt; ins · | repl · o op · r arg</span></div>'
					f"{current_col}"
					"</div>"
					"</div>"
				),
				meta=f"{n:04d}.obj vs target.obj",
			)
		)
		sections.append(
			panel(
				f"{n:04d}.c",
				f'<pre class="code">{_numbered_c(c_text)}</pre>',
				meta=f"{len(c_text.splitlines())} lines",
			)
		)

	nav = []
	if n > 1:
		nav.append(f'<a href="/decomp/attempt?root={html.escape(str(root))}&n={n - 1}">← prev</a>')
	nav.append(f'<a href="/decomp/run?root={html.escape(str(root))}">↑ run</a>')
	if (root / "history" / f"{n + 1:04d}.c").is_file():
		nav.append(f'<a href="/decomp/attempt?root={html.escape(str(root))}&n={n + 1}">next →</a>')
	sections.append(
		f'<p class="tight" style="display: flex; gap: 18px; padding: 4px 0;">{"  ".join(nav)}</p>'
	)

	return page(f"#{n:04d}", body="".join(sections), current_path=current_path)


def _numbered_c(c_text: str) -> str:
	out = []
	for i, line in enumerate(c_text.splitlines() or [""], start=1):
		out.append(
			f'<span style="display: inline-block; width: 36px; color: var(--fg-faint); '
			f'text-align: right; padding-right: 12px;">{i}</span>{html.escape(line)}'
		)
	return "\n".join(out)


def _attempt_status_labels(attempt: dict, *, is_in_flight: bool) -> tuple[str | None, str, str]:
	"""Pick (mp_label, badge_class, badge_text) for one attempt row.

	Returns (None, _, _) when match_percent is set and the caller should
	render the percentage normally. Otherwise the label distinguishes
	transient mid-iteration states (compiling/diffing) from terminal
	failures (compile failed, diff failed, symbol mismatch).
	"""
	if attempt["match_percent"] is not None:
		return None, "", ""
	if not attempt["compiled"]:
		return (
			("compiling…", "pending", "compiling")
			if is_in_flight
			else ("compile failed", "failed", "compile")
		)
	if not attempt["diff_path"].is_file():
		return (
			("diffing…", "pending", "diffing")
			if is_in_flight
			else ("diff failed", "failed", "diff")
		)
	return "symbol mismatch", "failed", "no match"


def _run_interrupted(job: JobInfo | None, result: dict | None, attempts: list[dict]) -> bool:
	"""True when a run was orphaned — the model attempted at least once (#0001+ on
	disk) but there's no terminal result.json and no live job tracking it.

	This is the 'server restarted mid-run' case: the daemon thread died, so its
	in-memory JobInfo is gone and the loop never reached _finalize. The attempt
	history and best.c survive on disk, so the run is resumable.
	"""
	if job is not None or result is not None:
		return False
	return any(a["n"] >= 1 for a in attempts)


def _interrupted_banner(root: Path, current_path: str | None) -> str:
	"""Banner for an orphaned run: explain the interruption and offer a Resume
	link to the prefilled launch form. Resume reuses this workspace, so attempt
	numbering continues and best.c is preserved — no progress is thrown away."""
	va = _va_from_workspace(root)
	resume = ""
	if va is not None and current_path:
		href = f"/decomp/launch?path={quote(current_path)}&va={va:#x}"
		resume = f'<a class="resume" href="{href}">resume run →</a>'
	return (
		'<div class="run-banner interrupted">'
		f"{badge('failed', 'INTERRUPTED')}"
		'<span class="muted">run stopped mid-flight (server restarted) · '
		"attempts and best.c preserved on disk</span>"
		f"{resume}"
		"</div>"
	)


def _run_action_bar(root: Path, current_path: str | None, job, *, has_attempts: bool) -> str:
	"""A run / re-run button on the decomp page → the prefilled launch form.

	Hidden while a job is live (the banner already shows progress) or when we
	lack the project path needed to build the launch link. Labelled by history:
	`▶ run` for a fresh function, `↻ re-run` once attempts exist — re-running
	lets another model attack the same workspace.
	"""
	va = _va_from_workspace(root)
	if not current_path or va is None or (job and job.is_active()):
		return ""
	label = "↻ re-run" if has_attempts else "▶ run"
	href = f"/decomp/launch?path={quote(current_path)}&va={va:#x}"
	return f'<div class="run-actions"><a class="btn-run" href="{href}">{label}</a></div>'
