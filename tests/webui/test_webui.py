"""Tests for the few pure helpers in src/webui/."""

import os
import re
import threading
import time
import types
from pathlib import Path
from urllib.parse import quote

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

import src.webui as webui
from src.analysis.notes import notes_load  # noqa: E402
from src.analysis.symbols import symbol_map_load  # noqa: E402
from src.core.project import ProjectStats  # noqa: E402
from src.webui import (
	SweepState,
	_attempt_model_label,
	_attempt_status_labels,
	_best_attempt,
	_diff_json_is_stale,
	_ensure_diff_json,
	_handle_notes_save,
	_handle_symbol_rename,
	_pager_window,
	_path_query_suffix,
	_progress_bar,
	_project_crumb,
	_register_sweep,
	_run_action_bar,
	_run_interrupted,
	_sweep_section,
	_va_from_workspace,
)
from src.webui import state as webui_state
from src.webui.views_decomp import _symbol_notes_panel  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_webui_registries():
	"""Each test gets empty job/sweep/verify registries and parse cache, restored
	afterward, so tests can't leak state into one another."""
	registries = (
		webui_state._JOBS,
		webui_state._SWEEPS,
		webui_state._VERIFIES,
		webui_state._PARSE_CACHE,
	)
	saved = [dict(r) for r in registries]
	for r in registries:
		r.clear()
	yield
	for r, snapshot in zip(registries, saved, strict=True):
		r.clear()
		r.update(snapshot)


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


def _touch(path: Path, mtime: float) -> None:
	os.utime(path, (mtime, mtime))


def _diff_workspace(tmp_path: Path):
	"""A workspace with target.obj + history/0002.{obj,diff.json}. Returns the paths."""
	history = tmp_path / "history"
	history.mkdir()
	target = tmp_path / "target.obj"
	target.write_bytes(b"t")
	obj = history / "0002.obj"
	obj.write_bytes(b"o")
	diff = history / "0002.diff.json"
	diff.write_text("{}")
	return obj, diff, target


def test_diff_json_is_stale_when_an_input_is_newer(tmp_path):
	obj, diff, _target = _diff_workspace(tmp_path)
	_touch(diff, 1000)
	_touch(obj, 2000)  # obj rewritten after the diff was derived
	assert _diff_json_is_stale(diff, obj) is True


def test_diff_json_not_stale_when_newer_than_inputs(tmp_path):
	obj, diff, _target = _diff_workspace(tmp_path)
	_touch(obj, 1000)
	_touch(diff, 2000)
	assert _diff_json_is_stale(diff, obj) is False


def test_ensure_diff_json_regenerates_stale_cache(tmp_path, monkeypatch):
	"""A diff older than its obj (derived before symbol canonicalization) is
	regenerated rather than served — the bug behind 'matched 100%' runs whose
	attempts all showed 'symbol mismatch'."""
	obj, diff, target = _diff_workspace(tmp_path)
	_touch(target, 1000)
	_touch(diff, 1000)
	_touch(obj, 2000)  # obj newer than diff -> stale

	calls = []

	def fake_run(cmd, **kwargs):
		calls.append(cmd)
		diff.write_text('{"regenerated": true}')
		_touch(diff, 3000)
		return types.SimpleNamespace(returncode=0, stdout="", stderr="")

	monkeypatch.setattr(webui.diff, "_objdiff_cli_path", lambda: "objdiff-cli")
	monkeypatch.setattr(webui.diff.subprocess, "run", fake_run)

	assert _ensure_diff_json(tmp_path, 2, "_fn_00430D97") == diff
	assert calls, "a stale diff should trigger objdiff regeneration"


def test_ensure_diff_json_keeps_fresh_cache(tmp_path, monkeypatch):
	"""A diff newer than both inputs is served from cache without invoking objdiff."""
	obj, diff, target = _diff_workspace(tmp_path)
	_touch(target, 1000)
	_touch(obj, 1000)
	_touch(diff, 2000)  # diff newer than both inputs -> fresh

	def boom(*args, **kwargs):
		raise AssertionError("a fresh cache must not invoke objdiff")

	monkeypatch.setattr(webui.diff, "_objdiff_cli_path", lambda: "objdiff-cli")
	monkeypatch.setattr(webui.diff.subprocess, "run", boom)

	assert _ensure_diff_json(tmp_path, 2, "_fn_00430D97") == diff


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
	# Label is the project name; href links to the (quoted) manifest path, not the name.
	assert href == f"/progress?path={quote(str(manifest))}"
	assert "halo2-retail" not in href


def test_symbol_notes_panel_title_escaped_exactly_once(tmp_path):
	# panel() escapes its head, so the title must be passed raw. A pre-escaped
	# "Symbol &amp; notes" double-escapes to a literal "&amp;" on the page.
	html = _symbol_notes_panel(tmp_path, None)
	assert "Symbol &amp; notes" in html  # single escape of "Symbol & notes"
	assert "&amp;amp;" not in html


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


# --- Property tests for the pure rendering helpers --------------------------
# These take untrusted/derived numeric input (a match percent, a page number)
# and must never produce a malformed bar / out-of-range pager, whatever the
# input.


class TestProgressBar:
	@given(
		value=st.one_of(
			st.none(),
			st.floats(allow_nan=False, allow_infinity=False, min_value=-1e6, max_value=1e6),
		)
	)
	def test_fill_width_is_clamped_to_0_100_invariant(self, value):
		# The CSS width is always a real percentage, even for None/negative/>100.
		width = float(re.search(r"width:\s*([\d.]+)%", _progress_bar(value)).group(1))
		assert 0.0 <= width <= 100.0


class TestPagerWindow:
	@given(
		total_pages=st.integers(min_value=1, max_value=500),
		page=st.integers(min_value=1, max_value=500),
		radius=st.integers(min_value=0, max_value=6),
	)
	def test_window_is_sorted_bounded_and_centered_invariant(self, total_pages, page, radius):
		assume(page <= total_pages)
		window = _pager_window(page, total_pages, radius)
		# Strictly increasing (it is a sorted set) and every page is in range.
		assert window == sorted(set(window))
		assert all(1 <= p <= total_pages for p in window)
		# Always shows the ends and the current page.
		assert {1, total_pages, page} <= set(window)
		# Complete around the cursor: every in-range page within radius is present.
		expected_near = {
			p for p in range(page - radius, page + radius + 1) if 1 <= p <= total_pages
		}
		assert expected_near <= set(window)


def _stats(*, untouched, total=10):
	return ProjectStats(
		total_functions=total,
		matched_functions=0,
		partial_functions=0,
		untouched_functions=untouched,
		total_bytes=1000,
		matched_bytes=0,
		partial_bytes=0,
		function_statuses=(),
	)


class TestSweepSection:
	def test_idle_shows_launch_button_when_untouched(self):
		html, active = _sweep_section("/no/such/sweep-a.json", _stats(untouched=42))
		assert active is False
		assert 'action="/sweep/launch' in html
		assert "42 untouched" in html

	def test_idle_no_button_when_all_touched(self):
		html, active = _sweep_section("/no/such/sweep-b.json", _stats(untouched=0))
		assert active is False
		assert "/sweep/launch" not in html
		assert "nothing untouched" in html

	def test_active_shows_progress_and_stop(self):
		path = "/no/such/sweep-c.json"
		_register_sweep(
			SweepState(
				project_path=path,
				project_name="c",
				total=10,
				done=4,
				matched=2,
				partial=1,
				failed=1,
				current="fn_00012200",
			)
		)
		html, active = _sweep_section(path, _stats(untouched=6))
		assert active is True
		assert "SWEEPING" in html
		assert "4/10" in html
		assert "2 matched" in html
		assert 'action="/sweep/stop' in html
		assert "fn_00012200" in html

	def test_finished_summary_then_relaunch_button(self):
		path = "/no/such/sweep-d.json"
		_register_sweep(
			SweepState(
				project_path=path,
				project_name="d",
				total=10,
				state="done",
				done=10,
				matched=3,
			)
		)
		html, active = _sweep_section(path, _stats(untouched=7))
		assert active is False
		assert "last sweep finished" in html
		assert "/sweep/launch" in html  # can run again


class TestXbeCachedLoad:
	# The cache is read/written from many threads (ThreadingHTTPServer requests +
	# workers). Parsing the same XBE must happen once no matter how many callers
	# stampede the empty cache at the same instant.
	def test_concurrent_loads_parse_once_invariant(self, monkeypatch):
		calls: list[str] = []
		calls_lock = threading.Lock()

		def slow_fake_load(path: str):
			with calls_lock:
				calls.append(path)
			time.sleep(0.01)  # widen the check-then-store window the race lives in
			return object()  # a distinct ParsedXbe stand-in per real parse

		monkeypatch.setattr(webui_state, "xbe_load", slow_fake_load)

		n = 24
		barrier = threading.Barrier(n)
		results: list[object] = [None] * n

		def worker(i: int) -> None:
			barrier.wait()  # release all threads into the cache together
			results[i] = webui_state.xbe_cached_load("/x/default.xbe")

		threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
		for t in threads:
			t.start()
		for t in threads:
			t.join()

		assert len(calls) == 1  # parsed exactly once despite the stampede
		assert len({id(r) for r in results}) == 1  # every caller got the same instance
