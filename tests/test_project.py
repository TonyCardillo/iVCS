"""Tests for the project manifest loader + aggregator."""

import json
from pathlib import Path

import pytest

from src.core.project import (
	FunctionEntry,
	FunctionStatus,
	model_attempt_stats,
	model_stats,
	project_aggregate,
	project_load,
)


def _status(model, state, best, *, name="fn", va=0x1000, size=16):
	return FunctionStatus(
		name=name,
		va=va,
		size=size,
		state=state,
		best_match_percent=best,
		iterations=1,
		workspace_path=Path("/ws") / name,
		termination_reason=None,
		model=model,
	)


class TestModelStats:
	def test_skips_functions_with_no_model(self):
		rows = model_stats([_status(None, "untouched", None), _status(None, "partial", 40.0)])
		assert rows == []

	def test_groups_and_counts_by_model(self):
		rows = model_stats(
			[
				_status("opus", "matched", 100.0),
				_status("opus", "partial", 50.0),
				_status("haiku", "matched", 100.0),
			]
		)
		by_model = {r.model: r for r in rows}
		assert by_model["opus"].functions == 2
		assert by_model["opus"].matched == 1
		assert by_model["opus"].partial == 1
		assert by_model["opus"].avg_best_percent == 75.0
		assert by_model["haiku"].functions == 1
		assert by_model["haiku"].matched == 1

	def test_sorted_by_matched_then_functions(self):
		rows = model_stats(
			[
				_status("a", "partial", 40.0),
				_status("a", "partial", 60.0),
				_status("b", "matched", 100.0),
			]
		)
		# b has a match, so it leads despite a having more functions.
		assert [r.model for r in rows] == ["b", "a"]

	def test_none_best_counts_as_zero_in_average(self):
		rows = model_stats([_status("x", "untouched", None), _status("x", "partial", 80.0)])
		assert rows[0].avg_best_percent == 40.0


def _write_manifest(tmp_path: Path, extra: dict | None = None) -> Path:
	manifest = {
		"name": "demo",
		"xbe_path": "./demo.xbe",
		"workspace_root": "./functions",
		"functions": [
			{"name": "fn_matched", "va": "0x1000", "size": 32},
			{"name": "fn_partial", "va": 0x1100, "size": 64},
			{"name": "fn_partial_lo", "va": "0x1200", "size": 16},
			{"name": "fn_untouched_dir", "va": "0x1300", "size": 8},
			{"name": "fn_no_workspace", "va": "0x1400", "size": 128},
		],
	}
	if extra:
		manifest.update(extra)
	path = tmp_path / "project.json"
	path.write_text(json.dumps(manifest))
	return path


def _setup_workspaces(tmp_path: Path) -> None:
	fns_root = tmp_path / "functions"
	fns_root.mkdir()

	# matched
	matched = fns_root / "fn_matched"
	matched.mkdir()
	(matched / "result.json").write_text(
		json.dumps(
			{
				"success": True,
				"best_match_percent": 100.0,
				"iterations": 3,
				"termination_reason": "matched",
				"function_name": "_fn_matched",
			}
		)
	)

	# partial (mid)
	partial = fns_root / "fn_partial"
	partial.mkdir()
	(partial / "result.json").write_text(
		json.dumps(
			{
				"success": False,
				"best_match_percent": 42.5,
				"iterations": 8,
				"termination_reason": "budget_exhausted",
				"function_name": "_fn_partial",
			}
		)
	)

	# partial (low)
	partial_lo = fns_root / "fn_partial_lo"
	partial_lo.mkdir()
	(partial_lo / "result.json").write_text(
		json.dumps(
			{
				"success": False,
				"best_match_percent": 12.0,
				"iterations": 4,
				"termination_reason": "budget_exhausted",
				"function_name": "_fn_partial_lo",
			}
		)
	)

	# untouched with directory but no successful attempt (best=None)
	untouched_dir = fns_root / "fn_untouched_dir"
	untouched_dir.mkdir()
	(untouched_dir / "result.json").write_text(
		json.dumps(
			{
				"success": False,
				"best_match_percent": None,
				"iterations": 1,
				"termination_reason": "llm_no_progress",
				"function_name": "_fn_untouched_dir",
			}
		)
	)

	# fn_no_workspace: deliberately no directory


class TestProjectLoad:
	def test_loads_function_entries_with_hex_and_int_va(self, tmp_path: Path):
		path = _write_manifest(tmp_path)
		project = project_load(path)
		assert project.name == "demo"
		assert len(project.functions) == 5
		assert project.functions[0] == FunctionEntry("fn_matched", 0x1000, 32)
		assert project.functions[1] == FunctionEntry("fn_partial", 0x1100, 64)

	def test_resolves_relative_paths_against_manifest(self, tmp_path: Path):
		path = _write_manifest(tmp_path)
		project = project_load(path)
		assert project.xbe_path == (tmp_path / "demo.xbe").resolve()
		assert project.workspace_root == (tmp_path / "functions").resolve()

	def test_honors_absolute_paths(self, tmp_path: Path):
		path = _write_manifest(
			tmp_path,
			extra={
				"xbe_path": "/abs/path/x.xbe",
				"workspace_root": "/abs/workspaces",
			},
		)
		project = project_load(path)
		assert project.xbe_path == Path("/abs/path/x.xbe")
		assert project.workspace_root == Path("/abs/workspaces")

	def test_duplicate_function_names_rejected(self, tmp_path: Path):
		path = tmp_path / "project.json"
		path.write_text(
			json.dumps(
				{
					"name": "x",
					"xbe_path": "./x.xbe",
					"functions": [
						{"name": "dup", "va": "0x1", "size": 4},
						{"name": "dup", "va": "0x2", "size": 4},
					],
				}
			)
		)
		with pytest.raises(ValueError, match="duplicate function name"):
			project_load(path)

	def test_non_positive_size_rejected(self, tmp_path: Path):
		path = tmp_path / "project.json"
		path.write_text(
			json.dumps(
				{
					"name": "x",
					"xbe_path": "./x.xbe",
					"functions": [{"name": "bad", "va": "0x1", "size": 0}],
				}
			)
		)
		with pytest.raises(ValueError, match="non-positive size"):
			project_load(path)

	def test_workspace_for_uses_function_name(self, tmp_path: Path):
		path = _write_manifest(tmp_path)
		project = project_load(path)
		fn = project.functions[0]
		assert project.workspace_for(fn) == project.workspace_root / "fn_matched"


class TestProjectAggregate:
	def test_classifies_each_state(self, tmp_path: Path):
		path = _write_manifest(tmp_path)
		_setup_workspaces(tmp_path)
		project = project_load(path)
		stats = project_aggregate(project)

		assert stats.total_functions == 5
		assert stats.matched_functions == 1
		assert stats.partial_functions == 2
		assert stats.untouched_functions == 2  # one no-dir, one with best=None

	def test_byte_accounting(self, tmp_path: Path):
		path = _write_manifest(tmp_path)
		_setup_workspaces(tmp_path)
		project = project_load(path)
		stats = project_aggregate(project)

		assert stats.total_bytes == 32 + 64 + 16 + 8 + 128
		assert stats.matched_bytes == 32
		assert stats.partial_bytes == 64 + 16

	def test_percentages(self, tmp_path: Path):
		path = _write_manifest(tmp_path)
		_setup_workspaces(tmp_path)
		project = project_load(path)
		stats = project_aggregate(project)

		assert stats.matched_function_percent == pytest.approx(20.0)
		assert stats.matched_byte_percent == pytest.approx(32 / 248 * 100)

	def test_no_sdk_set_is_unchanged(self, tmp_path: Path):
		path = _write_manifest(tmp_path)
		_setup_workspaces(tmp_path)
		stats = project_aggregate(project_load(path))
		assert stats.sdk_functions == 0
		assert stats.sdk_bytes == 0
		assert stats.game_functions == stats.total_functions
		assert stats.game_bytes == stats.total_bytes

	def test_sdk_functions_excluded_from_target(self, tmp_path: Path):
		path = _write_manifest(tmp_path)
		_setup_workspaces(tmp_path)
		project = project_load(path)
		# Mark the untouched 8-byte function at 0x1300 as identified SDK code.
		stats = project_aggregate(project, sdk_vas=frozenset({0x1300}))

		assert stats.sdk_functions == 1
		assert stats.sdk_bytes == 8
		assert stats.untouched_functions == 1  # was 2; the SDK one no longer counts
		assert stats.total_functions == 5  # total still counts everything
		assert stats.game_functions == 4
		assert stats.game_bytes == 248 - 8
		# Honest progress is measured against the game target, not the whole image.
		assert stats.game_matched_byte_percent == pytest.approx(32 / (248 - 8) * 100)

	def test_function_status_carries_workspace_path(self, tmp_path: Path):
		path = _write_manifest(tmp_path)
		_setup_workspaces(tmp_path)
		project = project_load(path)
		stats = project_aggregate(project)

		matched = next(s for s in stats.function_statuses if s.name == "fn_matched")
		assert matched.state == "matched"
		assert matched.best_match_percent == 100.0
		assert matched.iterations == 3
		assert matched.workspace_path == project.workspace_root / "fn_matched"
		assert matched.termination_reason == "matched"

	def test_missing_workspace_counts_as_untouched(self, tmp_path: Path):
		path = _write_manifest(tmp_path)
		_setup_workspaces(tmp_path)
		project = project_load(path)
		stats = project_aggregate(project)

		no_ws = next(s for s in stats.function_statuses if s.name == "fn_no_workspace")
		assert no_ws.state == "untouched"
		assert no_ws.best_match_percent is None
		assert no_ws.iterations == 0
		assert no_ws.termination_reason is None

	def test_success_flag_alone_is_sufficient_for_matched(self, tmp_path: Path):
		# A result with success=True should be matched even if best_match_percent is missing.
		path = _write_manifest(
			tmp_path,
			extra={
				"functions": [{"name": "fn", "va": "0x1", "size": 4}],
			},
		)
		fns_root = tmp_path / "functions"
		fns_root.mkdir()
		(fns_root / "fn").mkdir()
		(fns_root / "fn" / "result.json").write_text(
			json.dumps(
				{
					"success": True,
					"iterations": 1,
					"termination_reason": "matched",
				}
			)
		)
		stats = project_aggregate(project_load(path))
		assert stats.matched_functions == 1

	def test_empty_project(self, tmp_path: Path):
		path = tmp_path / "project.json"
		path.write_text(
			json.dumps(
				{
					"name": "empty",
					"xbe_path": "./x.xbe",
					"functions": [],
				}
			)
		)
		stats = project_aggregate(project_load(path))
		assert stats.total_functions == 0
		assert stats.matched_function_percent == 0.0
		assert stats.matched_byte_percent == 0.0


class TestModelAttemptStats:
	def test_tracks_attempts_improved_matched_per_model(self):
		# One function: ghidra baseline 10%, qwen 10% (no gain) then 55%, haiku 100%.
		ws = [[(0, "ghidra", 10.0), (1, "qwen", 10.0), (2, "qwen", 55.0), (3, "haiku", 100.0)]]
		rows = {r.model: r for r in model_attempt_stats(ws)}

		def trip(r):
			return (r.attempts, r.improved, r.matched)

		assert trip(rows["ghidra"]) == (1, 1, 0)
		assert trip(rows["qwen"]) == (2, 1, 0)
		assert trip(rows["haiku"]) == (1, 1, 1)

	def test_compile_failure_counts_as_attempt_not_improvement(self):
		ws = [[(1, "qwen", None), (2, "qwen", 30.0)]]
		(row,) = model_attempt_stats(ws)
		assert (row.attempts, row.improved, row.matched) == (2, 1, 0)

	def test_tie_with_running_best_is_not_an_improvement(self):
		ws = [[(1, "a", 40.0), (2, "b", 40.0)]]
		rows = {r.model: r for r in model_attempt_stats(ws)}
		assert rows["a"].improved == 1  # 40 > 0
		assert rows["b"].improved == 0  # 40 not > 40

	def test_unmodeled_attempt_skipped_but_still_raises_the_bar(self):
		# The None-model attempt isn't tallied, but its 50% is the bar qwen must beat.
		ws = [[(0, None, 50.0), (1, "qwen", 60.0), (2, "qwen", 50.0)]]
		(row,) = model_attempt_stats(ws)
		assert (row.attempts, row.improved) == (2, 1)  # only 60% improved; the 50% didn't

	def test_improve_rate(self):
		(row,) = model_attempt_stats([[(1, "qwen", 0.0), (2, "qwen", 30.0)]])
		assert row.attempts == 2
		assert row.improve_rate == 50.0

	def test_sorted_by_matched_then_improved_then_name(self):
		ws = [
			[(0, "ghidra", 12.0)],
			[(0, "ghidra", 0.0), (1, "alpha", 100.0)],
		]
		rows = model_attempt_stats(ws)
		assert rows[0].model == "alpha"  # the only matcher leads

	def test_empty(self):
		assert model_attempt_stats([]) == []
