"""Tests for the overnight batch queue ordering (cluster-aware, smallest-first)."""

import json
from pathlib import Path

from src.batch import (
	QueueItem,
	RunOutcome,
	batch_queue,
	batch_run,
	propagate_to_twins,
)
from src.compile_tool import CompileOutput
from src.fingerprint import Fingerprint
from src.objdiff import (
	SYMBOL_KIND_FUNCTION,
	DiffInstruction,
	DiffInstructionRow,
	DiffKind,
	DiffResult,
	DiffSide,
	DiffSymbol,
)
from src.project import FunctionEntry
from src.workspace import FunctionWorkspace


def _fn(va: int, size: int) -> FunctionEntry:
	return FunctionEntry(name=f"fn_{va:08X}", va=va, size=size)


def _fn(va: int, size: int) -> FunctionEntry:
	return FunctionEntry(name=f"fn_{va:08X}", va=va, size=size)


def _outcome(fn: FunctionEntry, *, matched: bool, source: str = "model") -> RunOutcome:
	return RunOutcome(
		va=fn.va,
		name=fn.name,
		matched=matched,
		best_match_percent=100.0 if matched else 40.0,
		iterations=1,
		reason="matched" if matched else "budget_exhausted",
		source=source,
	)


def _fp(va: int, size: int, *, exact: int) -> Fingerprint:
	# Only exact_hash matters for byte-identical clustering; the rest are filler.
	return Fingerprint(
		name=f"fn_{va:08X}",
		va=va,
		size=size,
		exact_hash=exact,
		opcode_hash=exact,
		equiv_hash=exact,
		opcodes=(),
	)


class TestOrdering:
	def test_smallest_first(self):
		fns = [_fn(0x3000, 90), _fn(0x1000, 10), _fn(0x2000, 50)]
		fps = [_fp(f.va, f.size, exact=f.va) for f in fns]  # all distinct → no clusters
		queue = batch_queue(fns, fps)
		assert [i.fn.va for i in queue] == [0x1000, 0x2000, 0x3000]
		assert all(i.twins == () for i in queue)

	def test_size_tie_broken_by_va(self):
		fns = [_fn(0x2000, 10), _fn(0x1000, 10)]
		fps = [_fp(f.va, f.size, exact=f.va) for f in fns]
		assert [i.fn.va for i in batch_queue(fns, fps)] == [0x1000, 0x2000]


class TestExclusions:
	def test_sdk_excluded(self):
		fns = [_fn(0x1000, 10), _fn(0x2000, 20)]
		fps = [_fp(f.va, f.size, exact=f.va) for f in fns]
		queue = batch_queue(fns, fps, sdk_vas=frozenset({0x2000}))
		assert [i.fn.va for i in queue] == [0x1000]

	def test_matched_excluded(self):
		fns = [_fn(0x1000, 10), _fn(0x2000, 20)]
		fps = [_fp(f.va, f.size, exact=f.va) for f in fns]
		queue = batch_queue(fns, fps, is_matched=lambda va: va == 0x1000)
		assert [i.fn.va for i in queue] == [0x2000]


class TestClustering:
	def test_one_representative_per_exact_cluster(self):
		# Three byte-identical functions (same exact hash) → one queue item.
		fns = [_fn(0x1000, 40), _fn(0x2000, 40), _fn(0x3000, 40)]
		fps = [_fp(f.va, f.size, exact=0xDEAD) for f in fns]
		queue = batch_queue(fns, fps)
		assert len(queue) == 1
		rep = queue[0]
		assert rep.fn.va == 0x1000  # lowest VA is the representative
		assert tuple(t.va for t in rep.twins) == (0x2000, 0x3000)

	def test_twins_not_queued_separately(self):
		fns = [_fn(0x1000, 40), _fn(0x2000, 40), _fn(0x5000, 8)]
		fps = [_fp(0x1000, 40, exact=0xAA), _fp(0x2000, 40, exact=0xAA), _fp(0x5000, 8, exact=0xBB)]
		queue = batch_queue(fns, fps)
		# The 8-byte singleton sorts first; the cluster representative second.
		assert [i.fn.va for i in queue] == [0x5000, 0x1000]

	def test_matched_twin_dropped_from_propagation_list(self):
		fns = [_fn(0x1000, 40), _fn(0x2000, 40), _fn(0x3000, 40)]
		fps = [_fp(f.va, f.size, exact=0xCC) for f in fns]
		queue = batch_queue(fns, fps, is_matched=lambda va: va == 0x2000)
		assert len(queue) == 1
		assert tuple(t.va for t in queue[0].twins) == (0x3000,)  # 0x2000 already done

	def test_already_matched_representative_still_propagates(self):
		# Resume case: the rep was solved a prior night; its twin is still open.
		# Emit a propagation-only item so the twin isn't stranded.
		fns = [_fn(0x1000, 40), _fn(0x2000, 40)]
		fps = [_fp(f.va, f.size, exact=0xEE) for f in fns]
		queue = batch_queue(fns, fps, is_matched=lambda va: va == 0x1000)
		assert len(queue) == 1
		item = queue[0]
		assert item.fn.va == 0x1000
		assert item.already_matched is True
		assert tuple(t.va for t in item.twins) == (0x2000,)

	def test_fully_matched_cluster_dropped(self):
		fns = [_fn(0x1000, 40), _fn(0x2000, 40)]
		fps = [_fp(f.va, f.size, exact=0xFF) for f in fns]
		queue = batch_queue(fns, fps, is_matched=lambda va: True)
		assert queue == []

	def test_propagation_only_items_sort_first(self):
		# An already-solved rep with an open twin is free work → goes before runs.
		fns = [_fn(0x1000, 40), _fn(0x2000, 40), _fn(0x9000, 5)]
		fps = [_fp(0x1000, 40, exact=0xA1), _fp(0x2000, 40, exact=0xA1), _fp(0x9000, 5, exact=0xB2)]
		queue = batch_queue(fns, fps, is_matched=lambda va: va == 0x1000)
		assert queue[0].fn.va == 0x1000  # propagation-only, free
		assert queue[0].already_matched is True
		assert queue[1].fn.va == 0x9000  # then smallest run


class TestQueueItem:
	def test_singleton_defaults(self):
		item = QueueItem(fn=_fn(0x1000, 10))
		assert item.twins == ()
		assert item.already_matched is False


def _compile_ok(c_path: Path, obj_path: Path, root: Path) -> CompileOutput:
	obj_path.write_bytes(b"\x90" * 8)
	return CompileOutput(success=True)


def _compile_fail(c_path: Path, obj_path: Path, root: Path) -> CompileOutput:
	return CompileOutput(success=False, stderr="error C2143\n")


def _diff_at(pct: float):
	def diff_fn(target, base, symbol):
		return DiffResult(
			left=DiffSide(
				symbols=(
					DiffSymbol(
						name=symbol,
						kind=SYMBOL_KIND_FUNCTION,
						match_percent=pct,
						instructions=(
							DiffInstructionRow(
								diff_kind=DiffKind.NONE,
								instruction=DiffInstruction(formatted="ret", mnemonic="ret"),
							),
						),
					),
				)
			)
		)

	return diff_fn


def _twin_workspace(tmp_path: Path):
	def prepare(twin: FunctionEntry) -> FunctionWorkspace:
		ws = FunctionWorkspace(root=tmp_path / twin.name, function_name=f"_{twin.name}")
		ws.initialize()
		ws.ctx_h.write_text("// ctx\n")
		ws.target_obj.write_bytes(b"\x00" * 8)
		return ws

	return prepare


class TestPropagation:
	REP = _fn(0x1000, 40)
	TWIN = _fn(0x2000, 40)
	REP_SRC = "int fn_00001000(void) { return 0; }"

	def test_leaf_twin_verified_match_is_recorded(self, tmp_path: Path):
		prepare = _twin_workspace(tmp_path)
		out = propagate_to_twins(
			self.REP,
			[self.TWIN],
			rep_source=self.REP_SRC,
			is_leaf=lambda fn: True,
			prepare=prepare,
			compile_fn=_compile_ok,
			diff_fn=_diff_at(100.0),
		)
		assert len(out) == 1
		assert out[0].matched is True
		assert out[0].source == "propagated"
		# best.c carries the renamed source; result.json marks it propagated.
		ws_root = tmp_path / self.TWIN.name
		assert "fn_00002000" in (ws_root / "best.c").read_text()
		assert "fn_00001000" not in (ws_root / "best.c").read_text()
		result = json.loads((ws_root / "result.json").read_text())
		assert result["success"] is True
		assert result["model"] == "propagated"

	def test_leaf_twin_below_100_is_flagged_not_claimed(self, tmp_path: Path):
		out = propagate_to_twins(
			self.REP,
			[self.TWIN],
			rep_source=self.REP_SRC,
			is_leaf=lambda fn: True,
			prepare=_twin_workspace(tmp_path),
			compile_fn=_compile_ok,
			diff_fn=_diff_at(96.0),
		)
		assert out[0].matched is False
		assert out[0].source == "flagged"
		assert not (tmp_path / self.TWIN.name / "result.json").exists()

	def test_compile_failure_is_flagged(self, tmp_path: Path):
		out = propagate_to_twins(
			self.REP,
			[self.TWIN],
			rep_source=self.REP_SRC,
			is_leaf=lambda fn: True,
			prepare=_twin_workspace(tmp_path),
			compile_fn=_compile_fail,
			diff_fn=_diff_at(100.0),
		)
		assert out[0].matched is False
		assert out[0].source == "flagged"

	def test_non_leaf_twin_flagged_without_compiling(self, tmp_path: Path):
		prepared: list[int] = []

		def prepare(twin):
			prepared.append(twin.va)
			return _twin_workspace(tmp_path)(twin)

		out = propagate_to_twins(
			self.REP,
			[self.TWIN],
			rep_source=self.REP_SRC,
			is_leaf=lambda fn: False,
			prepare=prepare,
			compile_fn=_compile_ok,
			diff_fn=_diff_at(100.0),
		)
		assert out[0].matched is False
		assert out[0].source == "flagged"
		assert prepared == []  # never even set up a workspace for a non-leaf

	def test_missing_rep_source_flags_all(self, tmp_path: Path):
		out = propagate_to_twins(
			self.REP,
			[self.TWIN, _fn(0x3000, 40)],
			rep_source=None,
			is_leaf=lambda fn: True,
			prepare=_twin_workspace(tmp_path),
			compile_fn=_compile_ok,
			diff_fn=_diff_at(100.0),
		)
		assert [o.matched for o in out] == [False, False]
		assert all(o.source == "flagged" for o in out)


class TestBatchRun:
	def test_runs_each_item_and_logs(self):
		queue = [QueueItem(_fn(0x1000, 10)), QueueItem(_fn(0x2000, 20))]
		logged: list[RunOutcome] = []
		summary = batch_run(
			queue,
			run_one=lambda fn: _outcome(fn, matched=True),
			propagate=lambda fn, twins: [],
			log=logged.append,
		)
		assert summary.attempted == 2
		assert summary.matched == 2
		assert [o.va for o in logged] == [0x1000, 0x2000]
		assert summary.stopped_early is False

	def test_unmatched_counts_attempted_not_matched(self):
		queue = [QueueItem(_fn(0x1000, 10))]
		summary = batch_run(
			queue,
			run_one=lambda fn: _outcome(fn, matched=False),
			propagate=lambda fn, twins: [],
		)
		assert summary.attempted == 1
		assert summary.matched == 0

	def test_propagation_runs_only_after_a_match(self):
		rep = _fn(0x1000, 40)
		twin = _fn(0x2000, 40)
		calls: list[int] = []

		def propagate(fn, twins):
			calls.append(fn.va)
			return [_outcome(twins[0], matched=True, source="propagated")]

		# Matched representative → propagate.
		s = batch_run(
			[QueueItem(rep, twins=(twin,))],
			run_one=lambda fn: _outcome(fn, matched=True),
			propagate=propagate,
		)
		assert calls == [0x1000]
		assert s.propagated == 1

		# Unmatched representative → no propagation.
		calls.clear()
		s2 = batch_run(
			[QueueItem(rep, twins=(twin,))],
			run_one=lambda fn: _outcome(fn, matched=False),
			propagate=propagate,
		)
		assert calls == []
		assert s2.propagated == 0

	def test_already_matched_item_skips_model_but_propagates(self):
		rep = _fn(0x1000, 40)
		twin = _fn(0x2000, 40)
		ran: list[int] = []

		def run_one(fn):
			ran.append(fn.va)
			return _outcome(fn, matched=True)

		summary = batch_run(
			[QueueItem(rep, twins=(twin,), already_matched=True)],
			run_one=run_one,
			propagate=lambda fn, twins: [_outcome(twins[0], matched=True, source="propagated")],
		)
		assert ran == []  # model not invoked for an already-solved representative
		assert summary.attempted == 0
		assert summary.propagated == 1

	def test_flagged_twin_counted(self):
		rep = _fn(0x1000, 40)
		twin = _fn(0x2000, 40)
		summary = batch_run(
			[QueueItem(rep, twins=(twin,))],
			run_one=lambda fn: _outcome(fn, matched=True),
			propagate=lambda fn, twins: [_outcome(twins[0], matched=False, source="flagged")],
		)
		assert summary.propagated == 0
		assert summary.flagged == 1

	def test_kill_switch_stops_between_items(self):
		queue = [QueueItem(_fn(0x1000, 10)), QueueItem(_fn(0x2000, 20)), QueueItem(_fn(0x3000, 30))]
		ran: list[int] = []

		def run_one(fn):
			ran.append(fn.va)
			return _outcome(fn, matched=True)

		# Stop once the first function is done.
		summary = batch_run(
			queue,
			run_one=run_one,
			propagate=lambda fn, twins: [],
			should_stop=lambda: len(ran) >= 1,
		)
		assert ran == [0x1000]
		assert summary.stopped_early is True
		assert summary.attempted == 1
