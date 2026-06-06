"""Tests for src.verify.coverage — per-segment and whole-image byte coverage.

project_coverage answers "% of enumerated code matched" per segment;
image_coverage answers the wider "% of every image byte reconstructed from
source", with data sections showing up explicitly as gap.
"""

import json
from pathlib import Path

from src.core.project import FunctionEntry, Project
from src.core.workspace import FunctionWorkspace
from src.verify.coverage import image_coverage, project_coverage
from src.verify.segments import function_source_path
from tests.verify._helpers import _fstatus, _parsed, _section


class TestProjectCoverage:
	def _write_result(self, project, fn, pct, success):
		ws = FunctionWorkspace(root=project.workspace_for(fn), function_name=fn.name)
		ws.initialize()
		ws.result_json.write_text(json.dumps({"best_match_percent": pct, "success": success}))

	def test_per_segment_matched_partial_and_percent(self, tmp_path):
		parsed = _parsed(_section(".text", 0x1000, 0x1000))
		fns = [
			FunctionEntry("m", 0x1000, 0x60),  # matched
			FunctionEntry("p", 0x1100, 0x20),  # partial
			FunctionEntry("u", 0x1200, 0x20),  # untouched (no result.json)
		]
		proj = Project(
			name="t",
			xbe_path=Path("/x.xbe"),
			workspace_root=tmp_path / "ws",
			functions=tuple(fns),
			src_root=tmp_path / "src",
		)
		self._write_result(proj, fns[0], 100.0, True)
		self._write_result(proj, fns[1], 50.0, False)
		cov = project_coverage(proj, parsed)
		assert len(cov) == 1
		c = cov[0]
		assert c.matched_bytes == 0x60
		assert c.partial_bytes == 0x20
		assert c.function_bytes == 0x60 + 0x20 + 0x20
		assert round(c.matched_percent, 2) == round(0x60 / 0xA0 * 100, 2)

	def test_sdk_functions_split_out_of_the_target(self, tmp_path):
		parsed = _parsed(_section(".text", 0x1000, 0x1000))
		fns = [
			FunctionEntry("m", 0x1000, 0x60),  # matched game fn
			FunctionEntry("sdk", 0x1100, 0x40),  # identified SDK (also "matched" state)
		]
		proj = Project(
			name="t",
			xbe_path=Path("/x.xbe"),
			workspace_root=tmp_path / "ws",
			functions=tuple(fns),
			src_root=tmp_path / "src",
		)
		self._write_result(proj, fns[0], 100.0, True)
		self._write_result(proj, fns[1], 100.0, True)

		cov = project_coverage(proj, parsed, sdk_vas=frozenset({0x1100}))[0]
		assert cov.sdk_count == 1
		assert cov.sdk_bytes == 0x40
		assert cov.matched_bytes == 0x60  # SDK fn not counted as matched target
		assert cov.function_bytes == 0x60 + 0x40
		assert cov.game_bytes == 0x60
		# 100% of the *game* target is matched, even though SDK fills the segment.
		assert cov.matched_percent == 100.0

	def test_committed_counts_files_present_in_tree(self, tmp_path):
		parsed = _parsed(_section(".text", 0x1000, 0x1000))
		fn = FunctionEntry("m", 0x1000, 0x40)
		proj = Project(
			name="t",
			xbe_path=Path("/x.xbe"),
			workspace_root=tmp_path / "ws",
			functions=(fn,),
			src_root=tmp_path / "src",
		)
		self._write_result(proj, fn, 100.0, True)
		assert project_coverage(proj, parsed)[0].committed == 0
		# Now drop the committed source file into place.
		dest = function_source_path(proj, parsed, fn)
		dest.parent.mkdir(parents=True, exist_ok=True)
		dest.write_text("// committed\n")
		assert project_coverage(proj, parsed)[0].committed == 1

	def test_gaps_and_overlaps_surfaced(self, tmp_path):
		parsed = _parsed(_section(".text", 0x1000, 0x200))
		fns = [FunctionEntry("a", 0x1000, 0x60), FunctionEntry("b", 0x1040, 0x40)]  # overlap
		proj = Project(
			name="t",
			xbe_path=Path("/x.xbe"),
			workspace_root=tmp_path / "ws",
			functions=tuple(fns),
			src_root=tmp_path / "src",
		)
		c = project_coverage(proj, parsed)[0]
		assert len(c.overlaps) == 1
		assert c.gaps  # trailing gap to 0x1200 at least

	def test_empty_project_is_empty(self, tmp_path):
		parsed = _parsed(_section(".text", 0x1000, 0x1000))
		proj = Project(
			name="t",
			xbe_path=Path("/x.xbe"),
			workspace_root=tmp_path / "ws",
			functions=(),
			src_root=tmp_path / "src",
		)
		assert project_coverage(proj, parsed) == ()


class TestImageCoverage:
	def test_data_section_is_all_gap(self):
		# .text (code) at 0x1000 holds one matched fn; .data at 0x9000 holds none.
		parsed = _parsed(
			_section(".text", 0x1000, 0x100),
			_section(".data", 0x9000, 0x80, flags=0),
		)
		statuses = [_fstatus(0x1000, 0x40, "matched")]
		cov = image_coverage(statuses, parsed)
		by = {s.name: s for s in cov.sections}
		assert by[".text"].matched_bytes == 0x40
		assert by[".text"].gap_bytes == 0x100 - 0x40
		# Data section: no functions → entirely gap, zero from source.
		assert by[".data"].enumerated_bytes == 0
		assert by[".data"].gap_bytes == 0x80
		assert by[".data"].matched_bytes == 0

	def test_whole_image_denominator_includes_data(self):
		parsed = _parsed(
			_section(".text", 0x1000, 0x100),
			_section(".data", 0x9000, 0x100, flags=0),
		)
		statuses = [_fstatus(0x1000, 0x40, "matched")]
		cov = image_coverage(statuses, parsed)
		assert cov.total_bytes == 0x200
		assert cov.matched_bytes == 0x40
		# 0x40 of 0x200 — the data section is in the denominator, not ignored.
		assert cov.from_source_percent == 0x40 / 0x200 * 100.0

	def test_sdk_bytes_separated_from_matched(self):
		parsed = _parsed(_section(".text", 0x1000, 0x100))
		statuses = [
			_fstatus(0x1000, 0x20, "matched", name="game"),
			_fstatus(0x1040, 0x20, "matched", name="sdk"),
		]
		cov = image_coverage(statuses, parsed, sdk_vas=frozenset({0x1040}))
		(sec,) = cov.sections
		assert sec.matched_bytes == 0x20  # only the game fn
		assert sec.sdk_bytes == 0x20
		assert sec.enumerated_bytes == 0x40


class TestImageCoverageBudget:
	def test_todo_code_separates_unmatched_code_from_data(self):
		# Code section: 0x40 matched, 0x20 partial, 0x10 sdk, rest of enumerated todo.
		parsed = _parsed(
			_section(".text", 0x1000, 0x200),
			_section(".data", 0x9000, 0x100, flags=0),
		)
		statuses = [
			_fstatus(0x1000, 0x40, "matched", name="m"),
			_fstatus(0x1040, 0x20, "partial", name="p"),
			_fstatus(0x1060, 0x10, "matched", name="sdk"),  # marked sdk below
			_fstatus(0x1070, 0x30, "untouched", name="todo"),
		]
		cov = image_coverage(statuses, parsed, sdk_vas=frozenset({0x1060}))
		assert cov.matched_bytes == 0x40
		assert cov.partial_bytes == 0x20
		assert cov.sdk_bytes == 0x10
		assert cov.todo_code_bytes == 0x30  # the untouched enumerated function
		# Data section + .text padding are gap, NOT todo code.
		assert cov.gap_bytes == (0x200 - 0xA0) + 0x100
