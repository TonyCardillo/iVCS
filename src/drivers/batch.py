"""Overnight batch harness: grind the agent loop over a whole project unattended.

Built for a slow, free local model (LM Studio). The scarcest resource is model
attempts, so the queue is **cluster-aware**: byte-identical functions are solved
once via a representative and the solution is propagated to its twins, never
re-derived. Ordering is smallest-first; a weak model succeeds most reliably on
small leaves, so you wake up to the largest number of verified matches.

Resume is implicit: already-matched functions are skipped, so re-running the
batch picks up where it left off. This module holds the pure planning logic;
the real run wiring (prep + agent loop + LM Studio) lives in src/cli/batch.py.
"""

import json
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from src.analysis.fingerprint import Fingerprint, fingerprint_clusters
from src.core.project import FunctionEntry
from src.core.workspace import FunctionWorkspace
from src.decomp.compile_tool import CompileFn, DiffFn, compile_and_view_assembly


@dataclass(frozen=True)
class QueueItem:
	"""One unit of overnight work: a function to solve, plus the byte-identical
	twins its solution should propagate to. `already_matched` marks a resume
	case; the representative was solved a prior night, so skip the model and go
	straight to propagating its existing solution to the still-open twins."""

	fn: FunctionEntry
	twins: tuple[FunctionEntry, ...] = field(default_factory=tuple)
	already_matched: bool = False


def batch_queue(
	functions: Sequence[FunctionEntry],
	fingerprints: Sequence[Fingerprint],
	*,
	sdk_vas: frozenset[int] = frozenset(),
	is_matched: Callable[[int], bool] = lambda _va: False,
) -> list[QueueItem]:
	"""Plan the overnight queue: one item per representative/singleton, twins
	attached for propagation, smallest-first.

	Excludes SDK functions and already-matched ones. Byte-identical functions
	(same exact hash) collapse to their lowest-VA representative; the others
	ride along as `twins`. A representative that's already matched but still has
	open twins becomes a propagation-only item (sorted first; it's free work).
	"""
	by_va = {fn.va: fn for fn in functions}

	rep_of: dict[int, int] = {}
	twins_of: dict[int, list[int]] = {}
	for cluster in fingerprint_clusters(list(fingerprints), by="exact", min_size=2):
		members = [m.va for m in cluster.members if m.va in by_va]
		if not members:
			continue
		rep_va, *twin_vas = members  # VA-sorted, so lowest is the representative
		twins_of[rep_va] = twin_vas
		for tv in twin_vas:
			rep_of[tv] = rep_va

	items: list[QueueItem] = []
	for fn in functions:
		if fn.va in sdk_vas or fn.va in rep_of:
			continue  # SDK code, or a twin handled via its representative

		open_twins = tuple(
			by_va[tv] for tv in twins_of.get(fn.va, ()) if tv not in sdk_vas and not is_matched(tv)
		)
		matched = is_matched(fn.va)
		if matched and not open_twins:
			continue
		items.append(QueueItem(fn=fn, twins=open_twins, already_matched=matched))

	# Free propagation-only items first, then smallest-first.
	items.sort(key=lambda i: (not i.already_matched, i.fn.size, i.fn.va))
	return items


@dataclass(frozen=True)
class RunOutcome:
	"""The result of working one function: a model run, a propagated twin, or a
	flagged twin. `source` distinguishes them for the log and the summary."""

	va: int
	name: str
	matched: bool
	best_match_percent: float | None
	iterations: int
	reason: str
	source: str  # "model" | "propagated" | "flagged"


@dataclass(frozen=True)
class BatchSummary:
	attempted: int  # model runs performed
	matched: int  # functions newly matched by the model
	propagated: int  # twins auto-finished (verified) without the model
	flagged: int  # twins left for manual follow-up (not auto-propagatable)
	stopped_early: bool  # the kill-switch fired
	outcomes: tuple[RunOutcome, ...]


def batch_run(
	queue: Sequence[QueueItem],
	*,
	run_one: Callable[[FunctionEntry], RunOutcome],
	propagate: Callable[[FunctionEntry, Sequence[FunctionEntry]], list[RunOutcome]],
	should_stop: Callable[[], bool] = lambda: False,
	log: Callable[[RunOutcome], None] = lambda _o: None,
) -> BatchSummary:
	"""Drive the queue: solve each item, then propagate its solution to twins.

	`run_one` runs the agent loop on one function; `propagate` carries a matched
	representative's solution to its byte-identical twins (verified). Both are
	injected so the orchestration is testable without Wine or a model. The
	kill-switch (`should_stop`) is polled between items for a graceful overnight
	stop; every outcome is handed to `log` as it happens.
	"""
	attempted = matched = propagated = flagged = 0
	outcomes: list[RunOutcome] = []
	stopped_early = False

	def record(outcome: RunOutcome) -> None:
		outcomes.append(outcome)
		log(outcome)

	for item in queue:
		if should_stop():
			stopped_early = True
			break

		rep_matched = item.already_matched
		if not item.already_matched:
			outcome = run_one(item.fn)
			attempted += 1
			rep_matched = outcome.matched
			matched += int(outcome.matched)
			record(outcome)

		if rep_matched and item.twins:
			for twin_outcome in propagate(item.fn, item.twins):
				propagated += int(twin_outcome.matched)
				flagged += int(not twin_outcome.matched)
				record(twin_outcome)

	return BatchSummary(
		attempted=attempted,
		matched=matched,
		propagated=propagated,
		flagged=flagged,
		stopped_early=stopped_early,
		outcomes=tuple(outcomes),
	)


def _rename_to_twin(source: str, rep_va: int, twin_va: int) -> str:
	"""Rewrite the representative's defined function to the twin's canonical name.

	A leaf's solution names its function after the representative's address; but
	the prefix and case vary by origin (`fn_00175F40` from the agent/normalizer,
	`FUN_00175f40` from a raw Ghidra draft). We rewrite any such token to the
	twin's canonical `fn_<TWIN_VA>` so the compiled symbol is `_fn_<twin_va>` and
	objdiff pairs it with the twin's target. Safe because we only ever propagate
	leaves, whose body holds no other address references.
	"""
	pattern = re.compile(rf"(?:FUN_|fn_|sub_)?{rep_va:08x}", re.IGNORECASE)
	return pattern.sub(f"fn_{twin_va:08X}", source)


def _flagged(twin: FunctionEntry, reason: str) -> RunOutcome:
	"""A twin we couldn't (or wouldn't) auto-finish; left for manual follow-up."""
	return RunOutcome(
		va=twin.va,
		name=twin.name,
		matched=False,
		best_match_percent=None,
		iterations=0,
		reason=reason,
		source="flagged",
	)


def _write_propagated_result(workspace: FunctionWorkspace, match_percent: float) -> None:
	"""Persist a verified-propagated match in the same shape the agent loop writes,
	tagged model='propagated' so reports never credit it to the model."""
	workspace.result_json.write_text(
		json.dumps(
			{
				"success": True,
				"best_match_percent": match_percent,
				"iterations": 0,
				"termination_reason": "propagated",
				"function_name": workspace.function_name,
				"model": "propagated",
			},
			indent=2,
		)
	)


def propagate_to_twins(
	rep: FunctionEntry,
	twins: Sequence[FunctionEntry],
	*,
	rep_source: str | None,
	is_leaf: Callable[[FunctionEntry], bool],
	prepare: Callable[[FunctionEntry], FunctionWorkspace],
	compile_fn: CompileFn,
	diff_fn: DiffFn,
) -> list[RunOutcome]:
	"""Carry a matched representative's solution to its byte-identical twins.

	Only *leaf* twins (no calls / no data refs; propagation is a pure function
	rename) are auto-finished, and only after a real recompile + diff confirms
	100%. Everything else is flagged for manual follow-up. No model is used, and
	nothing is claimed that the diff didn't verify.
	"""
	outcomes: list[RunOutcome] = []
	for twin in twins:
		if rep_source is None:
			outcomes.append(_flagged(twin, "representative has no saved solution"))
			continue
		if not is_leaf(twin):
			outcomes.append(_flagged(twin, "non-leaf twin — needs manual decomp"))
			continue

		workspace = prepare(twin)
		twin_source = _rename_to_twin(rep_source, rep.va, twin.va)
		result = compile_and_view_assembly(
			workspace=workspace, c_code=twin_source, compile_fn=compile_fn, diff_fn=diff_fn
		)
		workspace.attempt_model_path(result.attempt_number).write_text("propagated")
		pct = result.match_percent
		if result.success and pct is not None and pct >= 100.0:
			workspace.best_c.write_text(twin_source)
			_write_propagated_result(workspace, pct)
			outcomes.append(
				RunOutcome(
					va=twin.va,
					name=twin.name,
					matched=True,
					best_match_percent=pct,
					iterations=0,
					reason="propagated",
					source="propagated",
				)
			)
		else:
			if not result.success:
				detail = "compile failed"
			elif pct is None:
				detail = "no paired symbol in diff"
			else:
				detail = f"matched only {pct:.1f}%"
			outcomes.append(_flagged(twin, f"propagation {detail}"))
	return outcomes
