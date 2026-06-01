"""`batch` subcommand: grind the agent loop over a whole project unattended.

The run-wiring (LLM client + workspace prep + agent loop) around the pure
planning logic in src.drivers.batch. Built for a free local model (LM Studio).
Smallest functions first; byte-identical duplicates are solved once and the
solution is propagated (verified) to its twins. Resume is implicit; already-
matched functions are skipped, so re-running picks up where it left off.

Stop it gracefully overnight by creating a STOP file next to project.json
(`touch <project_dir>/STOP`); it exits after the function in flight. Every
outcome is appended to <project_dir>/batch.log as JSON, one line per function.

Targets LM Studio at IVCS_LLM_API_BASE (default http://127.0.0.1:1234/v1),
model IVCS_LLM_MODEL (else the loaded model, auto-detected). Needs Wine + the
XDK toolchain.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

from src.analysis.fingerprint import project_fingerprints
from src.analysis.symbols import symbol_map_load
from src.core.project import FunctionEntry, function_status, project_load, project_sdk_vas
from src.decomp.agent_loop import AgentConfig, agent_loop_run
from src.decomp.compile_tool import default_compile_fn, default_diff_fn
from src.decomp.llm_clients import llm_client_for, llm_recorded_model
from src.drivers.batch import (
	QueueItem,
	RunOutcome,
	batch_queue,
	batch_run,
	propagate_to_twins,
)
from src.drivers.launcher import prepare_decomp_workspace
from src.formats.relocs import relocs_discover
from src.formats.xbe import xbe_function_carve, xbe_load
from src.paths import RECON_DIR

# Prefer bundled objdiff-cli; don't override an explicit env setting.
_BUNDLED_OBJDIFF = RECON_DIR / "objdiff-smoke" / "objdiff-cli"
if "IVCS_OBJDIFF_CLI" not in os.environ and _BUNDLED_OBJDIFF.is_file():
	os.environ["IVCS_OBJDIFF_CLI"] = str(_BUNDLED_OBJDIFF)


def add_parser(subparsers) -> None:
	parser = subparsers.add_parser("batch", help="Overnight batch harness over a whole project")
	parser.add_argument("project", type=Path)
	parser.add_argument("--max-iterations", type=int, default=12)
	parser.add_argument("--timeout", type=float, default=300.0, help="per-fn hard timeout (s)")
	parser.add_argument("--limit", type=int, default=0, help="process at most N items (0 = all)")
	parser.add_argument("--dry-run", action="store_true", help="print the queue and exit")
	parser.set_defaults(func=_run)


def _matched_vas(project) -> set[int]:
	return {fn.va for fn in project.functions if function_status(project, fn).state == "matched"}


def _make_run_one(project, parsed, symbols, *, max_iterations: int, timeout: float, client):
	"""A runner that prepares the workspace and drives the agent loop on one
	function. Any failure is caught and returned as an unmatched outcome so a
	single bad function never aborts the night."""

	def run_one(fn: FunctionEntry) -> RunOutcome:
		try:
			workspace, target_asm = prepare_decomp_workspace(
				project, fn, parsed=parsed, label_for=symbols.label_for
			)
			config = AgentConfig(
				model=llm_recorded_model("local"),
				api_base="",
				max_iterations=max_iterations,
				hard_timeout_seconds=timeout,
			)
			result = agent_loop_run(
				workspace=workspace,
				target_asm=target_asm,
				config=config,
				llm_client=client,
				compile_fn=default_compile_fn,
				diff_fn=default_diff_fn,
			)
			return RunOutcome(
				va=fn.va,
				name=fn.name,
				matched=result.success,
				best_match_percent=result.best_match_percent,
				iterations=result.iterations,
				reason=result.termination_reason,
				source="model",
			)
		except Exception as e:  # noqa: BLE001 keep the batch alive
			return RunOutcome(
				va=fn.va,
				name=fn.name,
				matched=False,
				best_match_percent=None,
				iterations=0,
				reason=f"error: {type(e).__name__}: {e}",
				source="model",
			)

	return run_one


def _make_propagate(project, parsed, symbols):
	"""Propagate a matched representative's solution to its leaf twins (verified)."""

	def is_leaf(fn: FunctionEntry) -> bool:
		body = xbe_function_carve(parsed, fn.va, fn.size)
		return len(relocs_discover(body, fn.va)) == 0

	def prepare(twin: FunctionEntry):
		workspace, _asm = prepare_decomp_workspace(
			project, twin, parsed=parsed, label_for=symbols.label_for
		)
		return workspace

	def propagate(rep: FunctionEntry, twins) -> list[RunOutcome]:
		best_c = project.workspace_for(rep) / "best.c"
		rep_source = best_c.read_text() if best_c.is_file() else None
		try:
			return propagate_to_twins(
				rep,
				twins,
				rep_source=rep_source,
				is_leaf=is_leaf,
				prepare=prepare,
				compile_fn=default_compile_fn,
				diff_fn=default_diff_fn,
			)
		except Exception as e:  # noqa: BLE001 a twin failure shouldn't abort the night
			return [
				RunOutcome(
					va=t.va,
					name=t.name,
					matched=False,
					best_match_percent=None,
					iterations=0,
					reason=f"propagation error: {type(e).__name__}: {e}",
					source="flagged",
				)
				for t in twins
			]

	return propagate


def _make_logger(log_path: Path):
	"""Append each outcome to batch.log as JSON and echo a concise line to stderr."""

	def log(outcome: RunOutcome) -> None:
		record = {
			"ts": time.time(),
			"va": f"0x{outcome.va:08X}",
			"name": outcome.name,
			"matched": outcome.matched,
			"best": outcome.best_match_percent,
			"iterations": outcome.iterations,
			"reason": outcome.reason,
			"source": outcome.source,
		}
		with log_path.open("a") as f:
			f.write(json.dumps(record) + "\n")
		mark = "✓" if outcome.matched else "·"
		pct = outcome.best_match_percent
		best = f"{pct:.1f}%" if pct is not None else "—"
		sys.stderr.write(
			f"  {mark} {outcome.name}  {best:>7}  [{outcome.source}] {outcome.reason}\n"
		)
		sys.stderr.flush()

	return log


def _print_queue(queue: list[QueueItem]) -> None:
	total_twins = sum(len(i.twins) for i in queue)
	sys.stderr.write(f"Queue: {len(queue)} items, {total_twins} twins for propagation\n")
	for i, item in enumerate(queue):
		tag = " [resume]" if item.already_matched else ""
		twins = f" (+{len(item.twins)} twins)" if item.twins else ""
		sys.stderr.write(f"  {i + 1:>4}. {item.fn.name}  {item.fn.size:>5}B{twins}{tag}\n")


def _run(args) -> int:
	project = project_load(args.project)
	parsed = xbe_load(project.xbe_path)
	sdk_vas = project_sdk_vas(args.project)

	sys.stderr.write("Fingerprinting + planning queue…\n")
	fingerprints = project_fingerprints(project, parsed)
	matched = _matched_vas(project)
	queue = batch_queue(
		project.functions, fingerprints, sdk_vas=sdk_vas, is_matched=matched.__contains__
	)
	if args.limit > 0:
		queue = queue[: args.limit]

	if args.dry_run:
		_print_queue(queue)
		return 0

	stop_file = args.project.parent / "STOP"
	log_path = args.project.parent / "batch.log"
	sys.stderr.write(
		f"{len(queue)} functions queued · stop with `touch {stop_file}` · log → {log_path}\n"
	)

	client = llm_client_for("local")
	summary = batch_run(
		queue,
		run_one=_make_run_one(
			project,
			parsed,
			symbol_map_load(args.project),
			max_iterations=args.max_iterations,
			timeout=args.timeout,
			client=client,
		),
		propagate=_make_propagate(project, parsed, symbol_map_load(args.project)),
		should_stop=stop_file.exists,
		log=_make_logger(log_path),
	)

	sys.stderr.write(
		"\n── morning summary ──\n"
		f"  ran      {summary.attempted}\n"
		f"  matched  {summary.matched} (model)\n"
		f"  propagated {summary.propagated} (verified twins)\n"
		f"  flagged  {summary.flagged} (manual follow-up)\n"
		f"  {'STOPPED EARLY (STOP file)' if summary.stopped_early else 'completed queue'}\n"
	)
	if stop_file.exists():
		sys.stderr.write(f"  (remove {stop_file} before the next run)\n")
	return 0
