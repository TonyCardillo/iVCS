"""Background-thread workers: launch a decomp job, run/stop a baseline sweep,
the synchronous autoname pass, and the whole-image verify run."""

from __future__ import annotations

import os
import sys
import threading
import time
import traceback
from urllib.parse import quote

from src.analysis.strings_xref import (
	autoname_resolve,
	function_autoname_label,
)
from src.analysis.symbols import (
	symbol_map_load,
	symbol_rename,
)
from src.core.project import (
	project_aggregate,
	project_load,
)
from src.drivers.launcher import (
	JobInfo,
	ghidra_sweep_attempt_one,
	launch_decomp_job,
)
from src.drivers.sweep import (
	SweepOutcome,
	sweep_queue,
	sweep_run,
)
from src.verify.splice_verify import (
	image_splice_verify,
	image_verify_cache_write,
)
from src.webui.state import (
	SweepState,
	VerifyState,
	_active_workspace_paths,
	_register_job,
	_sweep_for,
	_unregister_job,
	_verify_for,
	job_admit,
	sweep_register_if_idle,
	verify_register_if_idle,
	xbe_cached_load,
)
from src.webui.views_progress import _sdk_vas_for


def launch_job_from_form(
	project_path_str: str, va_str: str, form: dict[str, str]
) -> tuple[str, JobInfo]:
	"""Validate caps and form fields, then spawn a job. Returns (redirect_url, job)."""
	project = project_load(project_path_str)
	va = int(va_str, 0)
	fn = next((f for f in project.functions if f.va == va), None)
	if fn is None:
		raise ValueError(f"function VA {va:#x} not in {project.name}")

	model = form.get("model", "claude-haiku-4-5").strip() or "claude-haiku-4-5"
	max_iter = max(1, min(50, int(form.get("max_iterations", "8") or "8")))
	timeout = max(10.0, min(3600.0, float(form.get("hard_timeout_seconds", "300") or "300")))
	wipe = form.get("wipe_history", "").lower() in ("1", "on", "true", "yes")
	reset_ctx = form.get("reset_ctx_h", "").lower() in ("1", "on", "true", "yes")
	use_ghidra = form.get("use_ghidra_warmstart", "").lower() in ("1", "on", "true", "yes")

	# Reserve the slot atomically before launching: launch_decomp_job starts the
	# worker thread, so the cap/per-workspace guard must win first. A pending
	# JobInfo holds the slot until the live job replaces it; on launch failure we
	# release it so a wedged attempt doesn't permanently block the workspace.
	pending = JobInfo(
		workspace_path=project.workspace_for(fn),
		function_name=fn.name,
		va=fn.va,
		size=fn.size,
		model=model,
		max_iterations=max_iter,
		hard_timeout_seconds=timeout,
	)
	job_admit(pending)

	try:
		parsed = xbe_cached_load(str(project.xbe_path))
		symbols = symbol_map_load(project_path_str)
		job = launch_decomp_job(
			project,
			fn,
			model=model,
			max_iterations=max_iter,
			hard_timeout_seconds=timeout,
			parsed_xbe=parsed,
			wipe_history=wipe,
			reset_ctx_h=reset_ctx,
			use_ghidra_warmstart=use_ghidra,
			label_for=symbols.label_for,
		)
	except BaseException:
		_unregister_job(pending.workspace_path)
		raise
	_register_job(job)
	redirect = f"/decomp/run?root={quote(str(job.workspace_path))}&path={quote(project_path_str)}"
	return redirect, job


def sweep_launch(project_path_str: str) -> SweepState:
	"""Start a project-wide Ghidra baseline sweep in a daemon thread.

	Plans the queue (untouched, non-SDK, not-actively-running functions), then
	walks it serially — Ghidra headless is the bottleneck, so concurrency would
	only thrash it. Returns immediately; the SweepState mutates as work lands.
	Raises if a sweep is already live for this project.
	"""
	existing = _sweep_for(project_path_str)
	if existing and existing.is_active():
		return existing  # idempotent: a sweep is already walking this project

	project = project_load(project_path_str)
	sdk_vas = _sdk_vas_for(project_path_str)
	stats = project_aggregate(project, sdk_vas=sdk_vas)

	ws_by_va = {f.va: project.workspace_for(f).resolve() for f in project.functions}
	active_ws = _active_workspace_paths()
	queue = sweep_queue(
		stats.function_statuses,
		sdk_vas=sdk_vas,
		is_active=lambda va: ws_by_va.get(va) in active_ws,
	)

	state = SweepState(
		project_path=project_path_str,
		project_name=project.name,
		total=len(queue),
	)
	registered = sweep_register_if_idle(state)
	if registered is not state:
		return registered  # lost the race: another launch is already sweeping this project

	parsed = xbe_cached_load(str(project.xbe_path))
	symbols = symbol_map_load(project_path_str)

	def attempt_one(fn):
		state.current = fn.name
		try:
			return ghidra_sweep_attempt_one(project, fn, parsed=parsed, label_for=symbols.label_for)
		except Exception as e:  # noqa: BLE001 — one bad function must not kill the sweep
			sys.stderr.write(f"[sweep] {fn.name} failed: {type(e).__name__}: {e}\n")
			return SweepOutcome(fn.va, fn.name, "failed", None, f"{type(e).__name__}: {e}")

	def log(outcome) -> None:
		state.done += 1
		if outcome.state == "matched":
			state.matched += 1
		elif outcome.state == "partial":
			state.partial += 1
		elif outcome.state == "failed":
			state.failed += 1

	def _run() -> None:
		state.started_at = time.time()
		try:
			sweep_run(
				queue,
				attempt_one=attempt_one,
				should_stop=lambda: state.stop_requested,
				log=log,
			)
			state.state = "stopped" if state.stop_requested else "done"
		except Exception as e:  # noqa: BLE001 — a worker thread must not die; report to the UI
			# Log the traceback so a real bug isn't invisible behind the one-line state.error.
			sys.stderr.write(f"[sweep] orchestration failed: {type(e).__name__}: {e}\n")
			traceback.print_exc()
			state.error = f"{type(e).__name__}: {e}"
			state.state = "error"
		finally:
			state.current = None

	threading.Thread(target=_run, daemon=True, name=f"sweep-{project.name}").start()
	return state


def sweep_stop(project_path_str: str) -> None:
	"""Request a graceful stop: the worker finishes the current function, then
	halts at the next kill-switch poll."""
	sweep = _sweep_for(project_path_str)
	if sweep is not None and sweep.is_active():
		sweep.stop_requested = True


_AUTONAME_MAX_SIZE = int(os.environ.get("IVCS_AUTONAME_MAX_SIZE", "24"))


def autoname_run(project_path_str: str, *, max_size: int = _AUTONAME_MAX_SIZE) -> int:
	"""Bulk-apply high-confidence string-derived names across a project.

	Names only unnamed, non-SDK, tiny functions whose single referenced string
	resolves to a unique, not-yet-taken label. Skips anything ambiguous (multiple
	strings, colliding labels) or already named — so it's safe to re-run and never
	clobbers a human rename. Fast (only small functions are disassembled); runs
	synchronously. Returns the number of functions newly named.
	"""
	project = project_load(project_path_str)
	parsed = xbe_cached_load(str(project.xbe_path))
	symbols = symbol_map_load(project_path_str)
	sdk_vas = _sdk_vas_for(project_path_str)

	candidates: list[tuple[int, str]] = []
	for fn in project.functions:
		if fn.size > max_size or fn.va in sdk_vas or symbols.provenance(fn.va) != "default":
			continue
		label = function_autoname_label(parsed, fn.va, fn.size)
		if label:
			candidates.append((fn.va, label))

	taken = frozenset(
		symbols.label_for(f.va) for f in project.functions if symbols.provenance(f.va) != "default"
	)
	plan = autoname_resolve(candidates, taken_labels=taken)
	for suggestion in plan:
		symbol_rename(project_path_str, suggestion.va, suggestion.label)
	return len(plan)


def verify_launch(project_path_str: str) -> VerifyState:
	"""Byte-splice verify every matched function in a daemon thread, caching the
	result on completion.

	Recompiles each matched function, relocates it with our own relocator, and
	byte-compares against the original image. Returns immediately; the VerifyState
	advances done/current as functions are checked. Idempotent while one is already
	running for this project. This recompiles every matched function, which is
	exactly why it's a background job and not computed on a page render."""
	existing = _verify_for(project_path_str)
	if existing and existing.is_active():
		return existing

	project = project_load(project_path_str)
	parsed = xbe_cached_load(str(project.xbe_path))
	stats = project_aggregate(project, sdk_vas=_sdk_vas_for(project_path_str))
	total = sum(1 for s in stats.function_statuses if s.state == "matched")

	state = VerifyState(project_path=project_path_str, total=total)
	registered = verify_register_if_idle(state)
	if registered is not state:
		return registered  # lost the race: another launch is already verifying this project

	def on_result(fv) -> None:
		state.done += 1
		state.current = fv.name

	def _run() -> None:
		state.started_at = time.time()
		try:
			result = image_splice_verify(project, parsed, on_result=on_result)
			image_verify_cache_write(project_path_str, result, when=time.time())
			state.state = "done"
		except Exception as e:  # noqa: BLE001 — a worker thread must not die; report to the UI
			# Log the traceback so a real bug isn't invisible behind the one-line state.error.
			sys.stderr.write(f"[verify] failed: {type(e).__name__}: {e}\n")
			traceback.print_exc()
			state.error = f"{type(e).__name__}: {e}"
			state.state = "error"
		finally:
			state.current = None

	threading.Thread(target=_run, daemon=True, name=f"verify-{project.name}").start()
	return state
