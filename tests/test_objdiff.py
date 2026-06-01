"""Tests for the objdiff-cli wrapper.

Pure-parse tests use fixture JSON captured from real objdiff-cli runs
(see recon/objdiff-smoke/ for how they were generated). The fixtures
exercise both 100%-match (identical inputs) and structured-diff cases.
"""

import json
from pathlib import Path

import pytest

from src.decomp.objdiff import (
	DiffKind,
	DiffResult,
	objdiff_parse,
)

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def variant_diff() -> DiffResult:
	"""Diff where sum_to_n was changed (<= → <), other functions identical."""
	return objdiff_parse(json.loads((FIXTURES / "variant_diff.json").read_text()))


@pytest.fixture
def identical_diff() -> DiffResult:
	"""Diff of two builds of the same source: every function should be 100%."""
	return objdiff_parse(json.loads((FIXTURES / "identical_diff.json").read_text()))


class TestIdenticalDiff:
	def test_all_functions_match_100(self, identical_diff: DiffResult):
		for symbol in identical_diff.function_symbols():
			assert symbol.match_percent == 100.0, f"{symbol.name} should be 100% matched"


class TestVariantDiff:
	def test_unchanged_functions_match_100(self, variant_diff: DiffResult):
		by_name = {s.name: s for s in variant_diff.function_symbols()}
		assert by_name["_classify"].match_percent == 100.0
		assert by_name["_dot_product"].match_percent == 100.0

	def test_changed_function_does_not_match(self, variant_diff: DiffResult):
		by_name = {s.name: s for s in variant_diff.function_symbols()}
		sum_to_n = by_name["_sum_to_n"]
		assert sum_to_n.match_percent is not None
		assert sum_to_n.match_percent < 100.0

	def test_diff_rows_classify_correctly(self, variant_diff: DiffResult):
		"""Variant has INSERT, DELETE, and ARG_MISMATCH rows from the smoke test."""
		by_name = {s.name: s for s in variant_diff.function_symbols()}
		kinds = {row.diff_kind for row in by_name["_sum_to_n"].instructions}
		assert DiffKind.INSERT in kinds
		assert DiffKind.DELETE in kinds
		assert DiffKind.ARG_MISMATCH in kinds

	def test_arg_mismatch_has_arg_indices(self, variant_diff: DiffResult):
		"""ARG_MISMATCH rows should identify which argument(s) differ."""
		sum_to_n = next(s for s in variant_diff.function_symbols() if s.name == "_sum_to_n")
		arg_mismatches = [r for r in sum_to_n.instructions if r.diff_kind == DiffKind.ARG_MISMATCH]
		assert len(arg_mismatches) > 0
		for row in arg_mismatches:
			assert len(row.arg_diff_indices) > 0, (
				"ARG_MISMATCH row must point at offending arg index"
			)

	def test_delete_rows_carry_instruction(self, variant_diff: DiffResult):
		"""DELETE rows describe instructions present in target but absent in base."""
		sum_to_n = next(s for s in variant_diff.function_symbols() if s.name == "_sum_to_n")
		deletes = [r for r in sum_to_n.instructions if r.diff_kind == DiffKind.DELETE]
		assert len(deletes) > 0
		for row in deletes:
			assert row.instruction is not None
			assert row.instruction.formatted, "DELETE row instruction must have formatted text"

	def test_insert_rows_may_lack_instruction(self, variant_diff: DiffResult):
		"""INSERT rows on the left side describe content present only on the right."""
		sum_to_n = next(s for s in variant_diff.function_symbols() if s.name == "_sum_to_n")
		inserts = [r for r in sum_to_n.instructions if r.diff_kind == DiffKind.INSERT]
		assert len(inserts) > 0
		# The schema permits instruction=None on one side for INSERT/DELETE rows; tolerate either.


class TestParseEdgeCases:
	def test_empty_dict(self):
		result = objdiff_parse({})
		assert result.left is None
		assert result.right is None

	def test_unknown_diff_kind_defaults_to_none(self):
		raw = {
			"left": {
				"symbols": [
					{
						"name": "_foo",
						"matchPercent": 50.0,
						"instructions": [{"diff_kind": "DIFF_FROM_THE_FUTURE"}],
					}
				]
			}
		}
		result = objdiff_parse(raw)
		symbol = result.left.symbols[0]
		assert symbol.instructions[0].diff_kind == DiffKind.NONE

	def test_missing_match_percent_is_none(self):
		raw = {"left": {"symbols": [{"name": "_foo"}]}}
		result = objdiff_parse(raw)
		assert result.left.symbols[0].match_percent is None

	def test_mnemonic_extracted_from_parts(self):
		raw = {
			"left": {
				"symbols": [
					{
						"name": "_foo",
						"instructions": [
							{
								"diff_kind": "DIFF_NONE",
								"instruction": {
									"formatted": "mov eax, ebx",
									"parts": [
										{"opcode": {"mnemonic": "mov", "opcode": 414}},
									],
								},
							}
						],
					}
				]
			}
		}
		result = objdiff_parse(raw)
		row = result.left.symbols[0].instructions[0]
		assert row.instruction is not None
		assert row.instruction.mnemonic == "mov"
		assert row.instruction.formatted == "mov eax, ebx"
