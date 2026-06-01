"""Tests for per-function free-text notes (a `notes.md` in the workspace dir)."""

from pathlib import Path

from src.analysis.notes import notes_load, notes_save


class TestNotes:
	def test_load_missing_is_empty(self, tmp_path: Path):
		assert notes_load(tmp_path) == ""

	def test_round_trip(self, tmp_path: Path):
		notes_save(tmp_path, "thiscall, `this` in ecx; loop is a memcpy")
		assert notes_load(tmp_path) == "thiscall, `this` in ecx; loop is a memcpy"

	def test_saves_to_notes_md(self, tmp_path: Path):
		notes_save(tmp_path, "hello")
		assert (tmp_path / "notes.md").read_text() == "hello"

	def test_overwrites(self, tmp_path: Path):
		notes_save(tmp_path, "first")
		notes_save(tmp_path, "second")
		assert notes_load(tmp_path) == "second"

	def test_creates_workspace_dir_if_absent(self, tmp_path: Path):
		ws = tmp_path / "fn_00175F40"
		notes_save(ws, "note before workspace materialized")
		assert notes_load(ws) == "note before workspace materialized"

	def test_blank_note_clears_file(self, tmp_path: Path):
		notes_save(tmp_path, "something")
		notes_save(tmp_path, "   ")
		assert notes_load(tmp_path) == ""
		assert not (tmp_path / "notes.md").exists()
