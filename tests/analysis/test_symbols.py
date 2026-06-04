"""Tests for the symbol map: a VA-keyed human-label overlay.

The map never touches machine symbols (`_fn_<va>` must stay VA-decodable for the
splice verifier); it only renders friendly labels for the webui and ctx comments.
Precedence: user override > SDK name (libmatch) > default `fn_<VA>`.
"""

import json
from pathlib import Path

import pytest

from src.analysis.symbols import (
	SymbolMap,
	symbol_map_load,
	symbol_rename,
)


def _project(tmp_path: Path) -> Path:
	path = tmp_path / "project.json"
	path.write_text(json.dumps({"name": "demo", "xbe_path": "./demo.xbe", "functions": []}))
	return path


def _write_sdk(tmp_path: Path) -> None:
	(tmp_path / "sdk.json").write_text(
		json.dumps(
			{
				"sdk": [
					{
						"va": "0x002D0CF5",
						"name": "_XoRebootToUpdater@12",
						"size": 40,
						"confidence": "exact",
					}
				]
			}
		)
	)


class TestLabelFor:
	def test_default_label_is_fn_va(self):
		m = SymbolMap(user={}, sdk={})
		assert m.label_for(0x00175F40) == "fn_00175F40"

	def test_sdk_name_wins_over_default(self):
		m = SymbolMap(user={}, sdk={0x002D0CF5: "_XoRebootToUpdater@12"})
		assert m.label_for(0x002D0CF5) == "_XoRebootToUpdater@12"

	def test_user_override_wins_over_sdk(self):
		m = SymbolMap(user={0x002D0CF5: "CPlayer__Update"}, sdk={0x002D0CF5: "_XoReboot@12"})
		assert m.label_for(0x002D0CF5) == "CPlayer__Update"


class TestProvenance:
	def test_reports_source(self):
		m = SymbolMap(user={0x10: "a"}, sdk={0x20: "b"})
		assert m.provenance(0x10) == "user"
		assert m.provenance(0x20) == "sdk"
		assert m.provenance(0x30) == "default"


class TestLoad:
	def test_empty_when_no_sidecars(self, tmp_path: Path):
		m = symbol_map_load(_project(tmp_path))
		assert m.user == {}
		assert m.sdk == {}

	def test_loads_sdk_names(self, tmp_path: Path):
		project = _project(tmp_path)
		_write_sdk(tmp_path)
		m = symbol_map_load(project)
		assert m.sdk == {0x002D0CF5: "_XoRebootToUpdater@12"}
		assert m.user == {}

	def test_loads_user_labels(self, tmp_path: Path):
		project = _project(tmp_path)
		(tmp_path / "symbols.json").write_text(
			json.dumps({"labels": {"0x00175F40": "CPlayer__Update"}})
		)
		m = symbol_map_load(project)
		assert m.user == {0x00175F40: "CPlayer__Update"}


class TestRename:
	def test_rename_persists_and_reloads(self, tmp_path: Path):
		project = _project(tmp_path)
		symbol_rename(project, 0x00175F40, "CPlayer__Update")
		assert symbol_map_load(project).label_for(0x00175F40) == "CPlayer__Update"

	def test_rename_is_keyed_by_va_not_name(self, tmp_path: Path):
		# The on-disk key is the canonical 0x-prefixed uppercase VA.
		project = _project(tmp_path)
		symbol_rename(project, 0x00175F40, "Foo")
		raw = json.loads((tmp_path / "symbols.json").read_text())
		assert raw["labels"] == {"0x00175F40": "Foo"}

	def test_empty_label_clears_override(self, tmp_path: Path):
		project = _project(tmp_path)
		symbol_rename(project, 0x00175F40, "Foo")
		symbol_rename(project, 0x00175F40, "   ")
		m = symbol_map_load(project)
		assert 0x00175F40 not in m.user
		assert m.label_for(0x00175F40) == "fn_00175F40"  # reverts to default

	def test_label_is_stripped(self, tmp_path: Path):
		project = _project(tmp_path)
		symbol_rename(project, 0x10, "  Spaced  ")
		assert symbol_map_load(project).user[0x10] == "Spaced"

	def test_newline_in_label_rejected(self, tmp_path: Path):
		project = _project(tmp_path)
		with pytest.raises(ValueError, match="single line"):
			symbol_rename(project, 0x10, "bad\nname")

	def test_rename_preserves_other_labels(self, tmp_path: Path):
		project = _project(tmp_path)
		symbol_rename(project, 0x10, "first")
		symbol_rename(project, 0x20, "second")
		m = symbol_map_load(project)
		assert m.user == {0x10: "first", 0x20: "second"}
