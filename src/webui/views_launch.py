"""Launch form + POST action handlers (symbol rename, notes save)."""

from __future__ import annotations

import html
import os
from urllib.parse import quote

from src.analysis.notes import notes_save
from src.analysis.symbols import symbol_rename
from src.core.project import (
	json_load_or_none,
	project_load,
)
from src.webui.state import (
	_MAX_CONCURRENT_JOBS,
	_active_jobs,
	_job_for,
)
from src.webui.templates import (
	crumbs,
	page,
	panel,
	view_error,
)


def view_launch_form(project_path_str: str, va_str: str) -> str:
	project = project_load(project_path_str)
	va = int(va_str, 0)
	fn = next((f for f in project.functions if f.va == va), None)
	if fn is None:
		return view_error(f"function VA {va:#x} not in {project.name}")

	workspace_path = project.workspace_for(fn)
	existing_job = _job_for(workspace_path)
	api_key_set = bool(os.environ.get("ANTHROPIC_API_KEY"))
	active = len(_active_jobs())

	warnings = []
	if not api_key_set:
		warnings.append(
			'<div class="error">ANTHROPIC_API_KEY is not set in the server\'s '
			"environment. Restart the web UI with it exported.</div>"
		)
	if active >= _MAX_CONCURRENT_JOBS:
		warnings.append(
			f'<div class="error">already at capacity: {active}/'
			f"{_MAX_CONCURRENT_JOBS} concurrent jobs. Wait for one to finish "
			f"or raise IVCS_MAX_CONCURRENT_JOBS.</div>"
		)
	if existing_job and existing_job.is_active():
		warnings.append(
			f'<div class="error">a job is already running for this workspace '
			f"(state: {existing_job.state}, iter {existing_job.iterations_completed}"
			f"/{existing_job.max_iterations}).</div>"
		)

	can_launch = (
		api_key_set
		and active < _MAX_CONCURRENT_JOBS
		and not (existing_job and existing_job.is_active())
	)

	# Surface existing on-disk state so the user knows what they'd overwrite.
	existing_attempts = []
	if (workspace_path / "history").is_dir():
		existing_attempts = sorted(int(p.stem) for p in (workspace_path / "history").glob("*.c"))
	existing_result = json_load_or_none(workspace_path / "result.json")
	existing_state_html = ""
	ctx_h_exists = (workspace_path / "ctx.h").is_file()
	if existing_attempts or existing_result or ctx_h_exists:
		best = (existing_result or {}).get("best_match_percent")
		best_str = f"{best:.2f}%" if isinstance(best, (int, float)) else "—"
		reason = (existing_result or {}).get("termination_reason") or "no result.json"
		existing_state_html = f"""
<div class="rerun-notice">
  <span class="badge partial">PRIOR RUN</span>
  <span>attempts on disk: <span class="amber">{len(existing_attempts)}</span>
        · best: <span class="green">{best_str}</span>
        · last reason: <span class="cyan">{html.escape(reason)}</span></span>
</div>
<label class="kv-checkbox">
  <input type="checkbox" name="wipe_history" value="1">
  wipe history before running (clears attempts, result.json, best.c; keeps ctx.h)
</label>
<label class="kv-checkbox">
  <input type="checkbox" name="reset_ctx_h" value="1"{" disabled" if not ctx_h_exists else ""}>
  regenerate ctx.h from auto-stub (discards hand-edits; uses current launcher rules)
</label>
"""

	model_choices = (
		("claude-haiku-4-5", "claude-haiku-4-5"),
		("claude-sonnet-4-6", "claude-sonnet-4-6"),
		("claude-opus-4-7", "claude-opus-4-7"),
		("local", "local (LM Studio)"),
		("ghidra", "ghidra"),
	)
	model_options = "".join(
		f'<option value="{value}"{" selected" if value == "claude-haiku-4-5" else ""}>{label}</option>'
		for value, label in model_choices
	)

	warmstart_exists = (workspace_path / "ghidra_warmstart.c").is_file()
	warmstart_label = (
		"use Ghidra warm-start (cached)"
		if warmstart_exists
		else "use Ghidra warm-start (adds ~3s; first XBE bootstrap costs ~100s)"
	)
	warmstart_html = f"""
<label class="kv-checkbox">
  <input type="checkbox" name="use_ghidra_warmstart" value="1">
  {warmstart_label}
</label>
"""

	launch_label = "▶ re-run" if existing_attempts else "▶ launch"

	form = f"""
<form method="post" action="/decomp/launch?path={quote(project_path_str)}&amp;va={va:#x}">
  <div class="kv">
    <div class="k">function</div>         <div class="v amber">{html.escape(fn.name)}</div>
    <div class="k">virtual address</div>  <div class="v num">0x{fn.va:08x}</div>
    <div class="k">size</div>             <div class="v">{fn.size} bytes</div>
    <div class="k">workspace</div>        <div class="v">{html.escape(str(workspace_path))}</div>
    <div class="k">model</div>            <div class="v">
      <select name="model">{model_options}</select>
    </div>
    <div class="k">max iterations</div>   <div class="v">
      <input type="number" name="max_iterations" value="8" min="1" max="50">
    </div>
    <div class="k">hard timeout (s)</div> <div class="v">
      <input type="number" name="hard_timeout_seconds" value="300" min="10" max="3600">
    </div>
  </div>
  {existing_state_html}
  {warmstart_html}
  <div style="margin-top: 14px;">
    <button type="submit"{" disabled" if not can_launch else ""}>{launch_label}</button>
    <a href="/progress?path={quote(project_path_str)}" style="margin-left: 12px;">cancel</a>
  </div>
</form>
"""
	body = (
		crumbs(
			("home", "/"),
			("progress", "/progress"),
			(project.name, f"/progress?path={quote(project_path_str)}"),
			("launch", None),
		)
		+ "".join(warnings)
		+ panel("Launch decomp run", form, meta=f"active jobs: {active}/{_MAX_CONCURRENT_JOBS}")
	)
	return page(f"launch · {fn.name}", body, current_path=None)


def _run_redirect(root: str, path: str) -> str:
	"""Redirect back to a workspace's run page, preserving the project path."""
	suffix = f"&path={quote(path)}" if path else ""
	return f"/decomp/run?root={quote(root)}{suffix}"


def _handle_symbol_rename(form: dict[str, str]) -> str:
	"""Persist a display-label rename, then return the run-page redirect."""
	path = form.get("path", "").strip()
	root = form.get("root", "").strip()
	va = int(form["va"], 0)
	symbol_rename(path, va, form.get("label", ""))
	return _run_redirect(root, path)


def _handle_notes_save(form: dict[str, str]) -> str:
	"""Persist per-function notes, then return the run-page redirect."""
	root = form["root"].strip()
	notes_save(root, form.get("notes", ""))
	return _run_redirect(root, form.get("path", "").strip())
