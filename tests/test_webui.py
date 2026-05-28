"""Tests for the few pure helpers in scripts/webui.py."""

import sys
from pathlib import Path

# Make scripts/ importable without installing it
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from webui import _attempt_status_labels, _path_query_suffix, _project_crumb  # noqa: E402


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
