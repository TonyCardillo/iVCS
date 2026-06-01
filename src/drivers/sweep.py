"""Project-wide Ghidra baseline sweep: warm-start every untouched function.

A one-shot pass that compiles + diffs each function's Ghidra warm-start (no LLM)
to surface the free matches and seed warm-starts across the whole project. The
scarcest resource is the Ghidra headless decompile per function, so the queue is
smallest-first — a sweep that's interrupted still banks the most leaves.

This module holds the pure planning, classification, and run-loop logic; the
threaded wiring (registry + live progress + Ghidra/Wine) lives in scripts/webui.py.
"""

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from src.core.project import FunctionEntry, FunctionStatus
from src.decomp.agent_loop import AgentResult


@dataclass(frozen=True)
class SweepOutcome:
	"""The result of baselining one function. `state` mirrors the project's
	function states plus `no_match` (compiled, paired, but 0%) and `failed`
	(compile failed or no warm-start to compile)."""

	va: int
	name: str
	state: str  # "matched" | "partial" | "no_match" | "failed"
	best_match_percent: float | None
	reason: str


@dataclass(frozen=True)
class SweepSummary:
	total: int
	processed: int
	matched: int
	partial: int
	no_match: int
	failed: int
	stopped_early: bool
	outcomes: tuple[SweepOutcome, ...]


def sweep_queue(
	statuses: Sequence[FunctionStatus],
	*,
	sdk_vas: frozenset[int] = frozenset(),
	is_active: Callable[[int], bool] = lambda _va: False,
) -> list[FunctionEntry]:
	"""Plan the sweep: untouched, non-SDK, not-currently-running functions,
	smallest-first.

	Already matched/partial functions are skipped — they have a baseline (or
	better) already. SDK code is linked from the XDK, not decompiled. Functions
	with a live per-function job are left alone to avoid racing on their files.
	"""
	items = [
		FunctionEntry(name=s.name, va=s.va, size=s.size)
		for s in statuses
		if s.state == "untouched" and s.va not in sdk_vas and not is_active(s.va)
	]
	items.sort(key=lambda f: (f.size, f.va))
	return items


def sweep_outcome_classify(va: int, name: str, result: AgentResult) -> SweepOutcome:
	"""Map a ghidra_only_run AgentResult onto a sweep outcome state."""
	pct = result.best_match_percent
	if result.termination_reason in ("compile_failed", "ghidra_unavailable"):
		state = "failed"
	elif pct is not None and pct >= 100.0:
		state = "matched"
	elif pct is not None and pct > 0.0:
		state = "partial"
	else:
		state = "no_match"
	return SweepOutcome(
		va=va,
		name=name,
		state=state,
		best_match_percent=pct,
		reason=result.termination_reason,
	)


def sweep_run(
	queue: Sequence[FunctionEntry],
	*,
	attempt_one: Callable[[FunctionEntry], SweepOutcome],
	should_stop: Callable[[], bool] = lambda: False,
	log: Callable[[SweepOutcome], None] = lambda _o: None,
) -> SweepSummary:
	"""Baseline each queued function in order, polling the kill-switch between
	items for a graceful stop. `attempt_one` (the Ghidra prep + compile + diff)
	is injected so orchestration is testable without Ghidra or Wine; every
	outcome is handed to `log` as it lands."""
	outcomes: list[SweepOutcome] = []
	stopped_early = False
	for fn in queue:
		if should_stop():
			stopped_early = True
			break
		outcome = attempt_one(fn)
		outcomes.append(outcome)
		log(outcome)

	def count(state: str) -> int:
		return sum(1 for o in outcomes if o.state == state)

	return SweepSummary(
		total=len(queue),
		processed=len(outcomes),
		matched=count("matched"),
		partial=count("partial"),
		no_match=count("no_match"),
		failed=count("failed"),
		stopped_early=stopped_early,
		outcomes=tuple(outcomes),
	)
