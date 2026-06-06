"""Tests for src.verify.segments — the segment model.

Grouping a project's functions under the XBE section they live in, finding the
gaps/overlaps between them, and deriving where each function's committed source
belongs. Pure helpers, exercised against synthetic Project + ParsedXbe objects.
"""

from pathlib import Path

from src.core.project import FunctionEntry
from src.verify.segments import (
	function_source_path,
	project_segments,
	segment_gaps,
	segment_overlaps,
)
from tests.verify._helpers import _parsed, _project, _section


class TestProjectSegments:
	def test_groups_functions_by_containing_section_va_sorted(self):
		parsed = _parsed(
			_section(".text", 0x1000, 0x1000),
			_section(".data", 0x2000, 0x1000, flags=0),
		)
		# Out-of-order on purpose; expect va-sorted within the segment.
		fns = [
			FunctionEntry("fn_b", 0x1100, 0x20),
			FunctionEntry("fn_a", 0x1000, 0x100),
			FunctionEntry("fn_d", 0x2000, 0x40),  # in .data
		]
		segs = project_segments(_project(fns), parsed)
		assert [s.section for s in segs] == [".text", ".data"]
		text = segs[0]
		assert [f.name for f in text.functions] == ["fn_a", "fn_b"]
		assert text.is_executable is True
		assert segs[1].is_executable is False

	def test_section_with_no_functions_omitted(self):
		parsed = _parsed(_section(".text", 0x1000, 0x1000), _section(".rdata", 0x9000, 0x100))
		segs = project_segments(_project([FunctionEntry("fn_a", 0x1000, 0x10)]), parsed)
		assert [s.section for s in segs] == [".text"]

	def test_duplicate_section_names_stay_distinct_segments(self):
		# Real XBEs reuse names (Halo 2 has four 'BINKYUY2' sections). Grouping
		# must key on the section's address, not its name, or the functions of
		# all same-named sections collapse into one bucket and re-emit N times.
		parsed = _parsed(
			_section("BINKYUY2", 0x1000, 0x1000),
			_section("BINKYUY2", 0x3000, 0x1000),
		)
		fns = [FunctionEntry("fn_lo", 0x1000, 0x10), FunctionEntry("fn_hi", 0x3000, 0x10)]
		segs = project_segments(_project(fns), parsed)
		assert len(segs) == 2
		assert [f.name for s in segs for f in s.functions] == ["fn_lo", "fn_hi"]
		assert [len(s.functions) for s in segs] == [1, 1]

	def test_function_outside_any_section_is_skipped(self):
		parsed = _parsed(_section(".text", 0x1000, 0x1000))
		fns = [FunctionEntry("fn_a", 0x1000, 0x10), FunctionEntry("fn_orphan", 0xF0000, 0x10)]
		segs = project_segments(_project(fns), parsed)
		assert [f.name for f in segs[0].functions] == ["fn_a"]


class TestSegmentGaps:
	def test_hole_before_between_and_after(self):
		parsed = _parsed(_section(".text", 0x1000, 0x200))
		# function at +0x40 size 0x40 (ends 0x80); next at 0x100 size 0x40 (ends 0x140)
		fns = [FunctionEntry("a", 0x1040, 0x40), FunctionEntry("b", 0x1100, 0x40)]
		seg = project_segments(_project(fns), parsed)[0]
		gaps = segment_gaps(seg)
		assert [(g.virtual_address, g.size) for g in gaps] == [
			(0x1000, 0x40),  # before a
			(0x1080, 0x80),  # between a and b
			(0x1140, 0xC0),  # after b to end (0x1200)
		]

	def test_fully_tiled_segment_has_no_gaps(self):
		parsed = _parsed(_section(".text", 0x1000, 0x80))
		fns = [FunctionEntry("a", 0x1000, 0x40), FunctionEntry("b", 0x1040, 0x40)]
		seg = project_segments(_project(fns), parsed)[0]
		assert segment_gaps(seg) == ()


class TestSegmentOverlaps:
	def test_adjacent_functions_do_not_overlap(self):
		parsed = _parsed(_section(".text", 0x1000, 0x80))
		fns = [FunctionEntry("a", 0x1000, 0x40), FunctionEntry("b", 0x1040, 0x40)]
		seg = project_segments(_project(fns), parsed)[0]
		assert segment_overlaps(seg) == ()

	def test_overlapping_size_flagged(self):
		# a claims [0x1000,0x1060), b starts at 0x1040 — 0x20 overlap (enum bug).
		parsed = _parsed(_section(".text", 0x1000, 0x200))
		fns = [FunctionEntry("a", 0x1000, 0x60), FunctionEntry("b", 0x1040, 0x40)]
		seg = project_segments(_project(fns), parsed)[0]
		ov = segment_overlaps(seg)
		assert len(ov) == 1
		assert (ov[0].first.name, ov[0].second.name, ov[0].overlap_bytes) == ("a", "b", 0x20)

	def test_function_nested_inside_a_larger_earlier_one_flagged(self):
		# a=[0x1000,0x1100); c=[0x1080,0x10) sits fully inside a — must still flag.
		parsed = _parsed(_section(".text", 0x1000, 0x200))
		fns = [FunctionEntry("a", 0x1000, 0x100), FunctionEntry("c", 0x1080, 0x10)]
		seg = project_segments(_project(fns), parsed)[0]
		ov = segment_overlaps(seg)
		assert len(ov) == 1 and ov[0].first.name == "a" and ov[0].second.name == "c"


class TestFunctionSourcePath:
	def test_path_under_src_root_by_sanitized_section(self):
		parsed = _parsed(_section(".text", 0x1000, 0x1000))
		proj = _project([FunctionEntry("fn_a", 0x1000, 0x10)], src_root=Path("/proj/src_tree"))
		path = function_source_path(proj, parsed, proj.functions[0])
		# Leading dot stripped so it isn't a hidden directory.
		assert path == Path("/proj/src_tree/text/fn_a.c")

	def test_orphan_function_routed_to_orphan_dir(self):
		parsed = _parsed(_section(".text", 0x1000, 0x1000))
		proj = _project([FunctionEntry("fn_x", 0xF0000, 0x10)], src_root=Path("/proj/src_tree"))
		path = function_source_path(proj, parsed, proj.functions[0])
		assert path == Path("/proj/src_tree/_orphan/fn_x.c")
