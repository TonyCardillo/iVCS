"""Tests for the project-wide Ghidra baseline sweep (src.drivers.sweep).

The sweep planning and run loop are pure (dependencies injected), so we can
exercise queueing, classification, and orchestration without Ghidra or Wine.
"""

from pathlib import Path

from src.core.project import FunctionStatus
from src.decomp.agent_loop import AgentResult
from src.drivers.sweep import (
	SweepOutcome,
	sweep_outcome_classify,
	sweep_queue,
	sweep_run,
)


def _status(state, *, name="fn", va=0x1000, size=16):
	return FunctionStatus(
		name=name,
		va=va,
		size=size,
		state=state,
		best_match_percent=None,
		iterations=0,
		workspace_path=Path("/ws") / name,
		termination_reason=None,
	)


def _result(reason, best):
	return AgentResult(
		success=reason == "matched",
		best_match_percent=best,
		iterations=0,
		termination_reason=reason,
	)


class TestSweepQueue:
	def test_keeps_only_untouched(self):
		statuses = [
			_status("matched", name="a", va=0x10),
			_status("partial", name="b", va=0x20),
			_status("untouched", name="c", va=0x30),
		]
		queue = sweep_queue(statuses)
		assert [f.name for f in queue] == ["c"]

	def test_excludes_sdk(self):
		statuses = [
			_status("untouched", name="a", va=0x10, size=8),
			_status("untouched", name="b", va=0x20, size=8),
		]
		queue = sweep_queue(statuses, sdk_vas=frozenset({0x10}))
		assert [f.va for f in queue] == [0x20]

	def test_excludes_active(self):
		statuses = [
			_status("untouched", name="a", va=0x10),
			_status("untouched", name="b", va=0x20),
		]
		queue = sweep_queue(statuses, is_active=lambda va: va == 0x20)
		assert [f.va for f in queue] == [0x10]

	def test_smallest_first(self):
		statuses = [
			_status("untouched", name="big", va=0x10, size=400),
			_status("untouched", name="small", va=0x20, size=8),
			_status("untouched", name="mid", va=0x30, size=80),
		]
		queue = sweep_queue(statuses)
		assert [f.name for f in queue] == ["small", "mid", "big"]


class TestSweepOutcomeClassify:
	def test_matched(self):
		out = sweep_outcome_classify(0x10, "a", _result("matched", 100.0))
		assert out.state == "matched"

	def test_partial(self):
		out = sweep_outcome_classify(0x10, "a", _result("ghidra_only", 55.0))
		assert out.state == "partial"

	def test_no_match_when_zero(self):
		out = sweep_outcome_classify(0x10, "a", _result("ghidra_only", 0.0))
		assert out.state == "no_match"

	def test_failed_when_match_unscored(self):
		# A None percent means the symbol was never paired/scored in the diff —
		# the function couldn't be evaluated, which is a failure, not a true 0%
		# no-match (which requires the symbol be compiled, paired, and scored 0).
		out = sweep_outcome_classify(0x10, "a", _result("ghidra_only", None))
		assert out.state == "failed"

	def test_failed_on_compile_failure(self):
		out = sweep_outcome_classify(0x10, "a", _result("compile_failed", None))
		assert out.state == "failed"

	def test_failed_when_ghidra_unavailable(self):
		out = sweep_outcome_classify(0x10, "a", _result("ghidra_unavailable", None))
		assert out.state == "failed"


class TestSweepRun:
	def test_processes_whole_queue_and_aggregates(self):
		from src.core.project import FunctionEntry

		queue = [FunctionEntry(name=f"f{v}", va=v, size=8) for v in (1, 2, 3, 4)]
		scripted = {
			1: SweepOutcome(1, "f1", "matched", 100.0, "matched"),
			2: SweepOutcome(2, "f2", "partial", 40.0, "ghidra_only"),
			3: SweepOutcome(3, "f3", "no_match", 0.0, "ghidra_only"),
			4: SweepOutcome(4, "f4", "failed", None, "compile_failed"),
		}
		seen = []
		summary = sweep_run(
			queue,
			attempt_one=lambda fn: scripted[fn.va],
			log=seen.append,
		)
		assert summary.total == 4
		assert summary.processed == 4
		assert summary.matched == 1
		assert summary.partial == 1
		assert summary.no_match == 1
		assert summary.failed == 1
		assert summary.stopped_early is False
		assert [o.va for o in seen] == [1, 2, 3, 4]

	def test_stops_early_when_kill_switch_fires(self):
		from src.core.project import FunctionEntry

		queue = [FunctionEntry(name=f"f{v}", va=v, size=8) for v in (1, 2, 3)]
		processed = []

		def attempt(fn):
			processed.append(fn.va)
			return SweepOutcome(fn.va, fn.name, "matched", 100.0, "matched")

		# Stop after the first item has been processed.
		summary = sweep_run(
			queue,
			attempt_one=attempt,
			should_stop=lambda: len(processed) >= 1,
		)
		assert summary.stopped_early is True
		assert summary.processed == 1
		assert processed == [1]
