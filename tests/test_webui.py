"""Tests for the few pure helpers in scripts/webui.py."""

import sys
from pathlib import Path

# Make scripts/ importable without installing it
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from webui import (  # noqa: E402
	_attempt_model_label,
	_attempt_status_labels,
	_best_attempt,
	_handle_notes_save,
	_handle_symbol_rename,
	_path_query_suffix,
	_project_crumb,
	_run_action_bar,
	_run_interrupted,
	_va_from_workspace,
)

from src.notes import notes_load  # noqa: E402
from src.symbols import symbol_map_load  # noqa: E402


def _attempt(*, compiled: bool, diff_exists: bool, match_percent: float | None):
	return {
		"match_percent": match_percent,
		"compiled": compiled,
		"diff_path": _FakePath(exists=diff_exists),
	}


class _FakePath:
	def __init__(self, *, exists: bool) -> None:
		self._exists = exists

	def is_file(self) -> bool:
		return self._exists


def test_status_compiling_in_flight():
	a = _attempt(compiled=False, diff_exists=False, match_percent=None)
	label, cls, text = _attempt_status_labels(a, is_in_flight=True)
	assert (label, cls, text) == ("compiling…", "pending", "compiling")


def test_status_compile_failed_terminal():
	a = _attempt(compiled=False, diff_exists=False, match_percent=None)
	label, cls, text = _attempt_status_labels(a, is_in_flight=False)
	assert (label, cls, text) == ("compile failed", "failed", "compile")


def test_status_diffing_in_flight():
	a = _attempt(compiled=True, diff_exists=False, match_percent=None)
	label, cls, text = _attempt_status_labels(a, is_in_flight=True)
	assert (label, cls, text) == ("diffing…", "pending", "diffing")


def test_status_diff_failed_terminal():
	a = _attempt(compiled=True, diff_exists=False, match_percent=None)
	label, cls, text = _attempt_status_labels(a, is_in_flight=False)
	assert (label, cls, text) == ("diff failed", "failed", "diff")


def test_status_symbol_mismatch_when_diff_exists_but_no_match():
	a = _attempt(compiled=True, diff_exists=True, match_percent=None)
	label, cls, text = _attempt_status_labels(a, is_in_flight=False)
	assert (label, cls, text) == ("symbol mismatch", "failed", "no match")


def test_status_skipped_when_match_percent_set():
	a = _attempt(compiled=True, diff_exists=True, match_percent=42.5)
	label, _, _ = _attempt_status_labels(a, is_in_flight=False)
	assert label is None


def test_project_crumb_falls_back_when_no_path():
	assert _project_crumb(None) == ("workspace", None)


def test_project_crumb_falls_back_when_path_unloadable(tmp_path):
	bogus = tmp_path / "does-not-exist.json"
	assert _project_crumb(str(bogus)) == ("workspace", None)


def test_project_crumb_uses_project_name(tmp_path):
	manifest = tmp_path / "project.json"
	manifest.write_text(
		'{"name": "halo2-retail", "xbe_path": "/tmp/x.xbe", '
		'"workspace_root": "./functions", "functions": []}'
	)
	label, href = _project_crumb(str(manifest))
	assert label == "halo2-retail"
	assert href.startswith("/progress?path=")
	assert "halo2-retail" not in href or "project.json" in href  # quoted manifest path


def test_path_query_suffix_empty_when_none():
	assert _path_query_suffix(None) == ""


def test_path_query_suffix_quotes_path():
	s = _path_query_suffix("/tmp/has space/project.json")  # noqa: S108
	assert s.startswith("&path=")
	assert "%20" in s or "+" in s  # space encoded


def test_va_from_workspace_parses_fn_dirname(tmp_path):
	assert _va_from_workspace(tmp_path / "fn_00175F40") == 0x00175F40


def test_va_from_workspace_case_insensitive(tmp_path):
	assert _va_from_workspace(tmp_path / "fn_002d0cf5") == 0x002D0CF5


def test_va_from_workspace_none_for_non_fn_dir(tmp_path):
	assert _va_from_workspace(tmp_path / "scratch") is None


def test_run_interrupted_when_model_attempted_but_no_result_or_job():
	# Server restarted mid-run: attempts #1+ on disk, no result.json, no live job.
	assert _run_interrupted(None, None, [{"n": 1}, {"n": 2}]) is True


def test_run_not_interrupted_when_result_exists():
	# A clean termination wrote result.json — not an orphan.
	assert _run_interrupted(None, {"termination_reason": "matched"}, [{"n": 1}]) is False


def test_run_not_interrupted_when_job_is_live():
	# An in-memory job is still tracking the run.
	assert _run_interrupted(object(), None, [{"n": 1}]) is False


def test_run_not_interrupted_when_only_baseline_attempt():
	# Only the Ghidra warm-start (#0000) — the model never ran, nothing lost.
	assert _run_interrupted(None, None, [{"n": 0}]) is False


def test_run_not_interrupted_when_no_attempts():
	assert _run_interrupted(None, None, []) is False


class _FakeJob:
	def __init__(self, active):
		self._active = active

	def is_active(self):
		return self._active


def test_run_action_bar_run_when_fresh(tmp_path):
	bar = _run_action_bar(tmp_path / "fn_00175F40", "/p/project.json", None, has_attempts=False)
	assert "▶ run" in bar
	assert "/decomp/launch?path=" in bar
	assert "va=0x175f40" in bar


def test_run_action_bar_rerun_when_attempts_exist(tmp_path):
	bar = _run_action_bar(tmp_path / "fn_00175F40", "/p/project.json", None, has_attempts=True)
	assert "↻ re-run" in bar


def test_run_action_bar_hidden_while_job_active(tmp_path):
	root = tmp_path / "fn_00175F40"
	assert _run_action_bar(root, "/p/project.json", _FakeJob(True), has_attempts=True) == ""


def test_run_action_bar_hidden_without_project_path(tmp_path):
	assert _run_action_bar(tmp_path / "fn_00175F40", None, None, has_attempts=True) == ""


def test_run_action_bar_hidden_when_va_undecodable(tmp_path):
	assert _run_action_bar(tmp_path / "scratch", "/p/project.json", None, has_attempts=False) == ""


def test_attempt_model_label_uses_own_sidecar():
	got = _attempt_model_label({"n": 1, "model": "qwen/qwen3.5-9b"}, "fallback")
	assert got == "qwen/qwen3.5-9b"


def test_attempt_model_label_falls_back_to_run_model():
	# Legacy attempt with no sidecar → the run's recorded model.
	assert _attempt_model_label({"n": 2, "model": None}, "claude-haiku-4-5") == "claude-haiku-4-5"


def test_attempt_model_label_none_for_baseline():
	assert _attempt_model_label({"n": 0, "model": "ghidra"}, "claude-haiku-4-5") is None


def test_attempt_model_label_none_when_nothing_known():
	assert _attempt_model_label({"n": 1, "model": None}, None) is None


def _att(n, mp, model=None):
	return {"n": n, "match_percent": mp, "model": model}


def test_best_attempt_none_when_no_scored_attempts():
	assert _best_attempt([]) is None
	assert _best_attempt([_att(0, None), _att(1, None)]) is None


def test_best_attempt_picks_highest_match():
	best = _best_attempt([_att(1, 40.0, "alpha"), _att(2, 80.0, "beta"), _att(3, 55.0, "alpha")])
	assert best["n"] == 2
	assert best["model"] == "beta"


def test_best_attempt_ties_keep_earliest():
	best = _best_attempt([_att(1, 60.0, "alpha"), _att(2, 60.0, "beta")])
	assert best["n"] == 1
	assert best["model"] == "alpha"


def _project_json(tmp_path):
	path = tmp_path / "project.json"
	path.write_text('{"name": "demo", "xbe_path": "./x.xbe", "functions": []}')
	return path


def test_handle_symbol_rename_persists_label(tmp_path):
	project = _project_json(tmp_path)
	root = tmp_path / "functions" / "fn_00175F40"
	redirect = _handle_symbol_rename(
		{"path": str(project), "root": str(root), "va": "0x00175F40", "label": "CPlayer__Update"}
	)
	assert symbol_map_load(project).label_for(0x00175F40) == "CPlayer__Update"
	assert redirect.startswith("/decomp/run?root=")
	assert "path=" in redirect


def test_handle_symbol_rename_blank_reverts(tmp_path):
	project = _project_json(tmp_path)
	_handle_symbol_rename({"path": str(project), "root": "x", "va": "0x10", "label": "Foo"})
	_handle_symbol_rename({"path": str(project), "root": "x", "va": "0x10", "label": "  "})
	assert symbol_map_load(project).label_for(0x10) == "fn_00000010"


def test_handle_notes_save_writes_notes(tmp_path):
	root = tmp_path / "fn_00175F40"
	redirect = _handle_notes_save({"root": str(root), "path": "", "notes": "thiscall in ecx"})
	assert notes_load(root) == "thiscall in ecx"
	assert redirect.startswith("/decomp/run?root=")
