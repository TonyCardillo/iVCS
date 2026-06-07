"""Tests for the one-off stale-baseline recanonicalize repair.

A real COFF object is crafted with coff_object_build so the repair exercises
the actual symbol-name parse + rename; the diff is faked so no objdiff-cli is
needed.
"""

import json
from pathlib import Path

from src.decomp.objdiff import (
	SYMBOL_KIND_FUNCTION,
	DiffResult,
	DiffSide,
	DiffSymbol,
)
from src.drivers.recanonicalize import (
	baseline_recanonicalize_one,
	coff_defined_function_symbol,
	project_baselines_recanonicalize,
)
from src.formats.coff import coff_object_build


def _obj(symbol: str) -> bytes:
	# `ret 4` is irrelevant to symbol pairing; any .text body works.
	return coff_object_build(b"\xc2\x04\x00", symbol, [])


def _make_baseline(root: Path, *, target_sym: str, base_sym: str) -> None:
	"""A function workspace with a cached baseline whose obj symbol is `base_sym`
	while its target.obj symbol is `target_sym`."""
	(root / "history").mkdir(parents=True)
	root.joinpath("ctx.h").write_text("// ctx\n")
	root.joinpath("target.obj").write_bytes(_obj(target_sym))
	root.joinpath("history", "0000.c").write_text("int f(int){return 0;}\n")
	root.joinpath("history", "0000.obj").write_bytes(_obj(base_sym))


def _diff_fn_scoring(pct: float):
	"""A diff_fn that scores whatever symbol it is asked about — so a returned
	score proves the symbol was paired (i.e. canonicalized to match)."""

	def diff_fn(target, base, symbol):
		# Only score the symbol if the base object actually defines it, mirroring
		# objdiff: a name mismatch yields an unpaired None.
		base_sym = coff_defined_function_symbol(Path(base).read_bytes())
		score = pct if base_sym == symbol else None
		return DiffResult(
			left=DiffSide(
				symbols=(DiffSymbol(name=symbol, kind=SYMBOL_KIND_FUNCTION, match_percent=score),)
			)
		)

	return diff_fn


class TestCoffDefinedFunctionSymbol:
	def test_returns_unique_defined_symbol(self):
		assert coff_defined_function_symbol(_obj("_fn_00013D50@4")) == "_fn_00013D50@4"

	def test_returns_none_on_garbage(self):
		assert coff_defined_function_symbol(b"not a coff") is None


class TestBaselineRecanonicalizeOne:
	def test_repairs_stale_stdcall_decoration(self, tmp_path):
		root = tmp_path / "fn_00013D50"
		_make_baseline(root, target_sym="_fn_00013D50@4", base_sym="_fn_00013D50@8")

		outcome = baseline_recanonicalize_one(root, diff_fn=_diff_fn_scoring(29.25))

		assert outcome is not None
		assert outcome.old_symbol == "_fn_00013D50@8"
		assert outcome.new_symbol == "_fn_00013D50@4"
		# The phantom no-match (None) flips to its true paired score.
		assert outcome.match_percent == 29.25
		# The cached obj on disk now carries the canonical name.
		assert coff_defined_function_symbol((root / "history" / "0000.obj").read_bytes()) == (
			"_fn_00013D50@4"
		)
		# result.json reflects the repaired score.
		data = json.loads((root / "result.json").read_text())
		assert data["best_match_percent"] == 29.25

	def test_noop_when_symbols_already_agree(self, tmp_path):
		root = tmp_path / "fn_ok"
		_make_baseline(root, target_sym="_fn_ok@4", base_sym="_fn_ok@4")
		assert baseline_recanonicalize_one(root, diff_fn=_diff_fn_scoring(50.0)) is None
		# Untouched: no result.json written.
		assert not (root / "result.json").is_file()

	def test_noop_when_no_cached_obj(self, tmp_path):
		root = tmp_path / "fn_bare"
		(root / "history").mkdir(parents=True)
		root.joinpath("ctx.h").write_text("// ctx\n")
		root.joinpath("target.obj").write_bytes(_obj("_fn_bare@4"))
		assert baseline_recanonicalize_one(root, diff_fn=_diff_fn_scoring(50.0)) is None


class TestProjectBaselinesRecanonicalize:
	def test_walks_and_repairs_only_stale(self, tmp_path):
		ws_root = tmp_path / "functions"
		ws_root.mkdir()
		_make_baseline(ws_root / "fn_stale", target_sym="_fn_stale@4", base_sym="_fn_stale@8")
		_make_baseline(ws_root / "fn_ok", target_sym="_fn_ok@4", base_sym="_fn_ok@4")

		logged: list[str] = []
		summary = project_baselines_recanonicalize(
			ws_root, diff_fn=_diff_fn_scoring(40.0), log=lambda o: logged.append(o.name)
		)

		assert summary.scanned == 2
		assert summary.repaired == 1
		assert [o.name for o in summary.outcomes] == ["fn_stale"]
		assert logged == ["fn_stale"]
