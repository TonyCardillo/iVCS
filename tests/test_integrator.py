"""Tests for src.integrator — the source-tree integrator.

Phase 1 covers the segment model: grouping a project's functions under the
XBE section they live in, finding the gaps/overlaps between them, and deriving
where each function's committed source belongs. Pure helpers, exercised against
synthetic Project + ParsedXbe objects (no real XBE on disk).
"""

import json
import types
from pathlib import Path

from src.integrator import (
	function_source_path,
	integrate_commit,
	project_coverage,
	project_segments,
	segment_gaps,
	segment_overlaps,
)
from src.project import FunctionEntry, Project
from src.workspace import FunctionWorkspace
from src.xbe import SECTION_FLAG_EXECUTABLE, ParsedXbe, XbeHeader, XbeSection


def _ok_compile(c_source, out_obj, workspace_root):
	return types.SimpleNamespace(success=True)


def _fail_compile(c_source, out_obj, workspace_root):
	return types.SimpleNamespace(success=False)


def _section(name, va, vsize, flags=SECTION_FLAG_EXECUTABLE):
	return XbeSection(
		name=name,
		flags=flags,
		virtual_address=va,
		virtual_size=vsize,
		raw_address=0,
		raw_size=vsize,
	)


def _parsed(*sections):
	header = XbeHeader(0x10000, 0, 0, 0, len(sections), 0, 0, 0)
	return ParsedXbe(header=header, sections=tuple(sections), data=b"")


def _project(functions, src_root=Path("/proj/src_tree")):
	return Project(
		name="t",
		xbe_path=Path("/x.xbe"),
		workspace_root=Path("/ws"),
		functions=tuple(functions),
		src_root=src_root,
	)


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


class TestIntegrateCommit:
	def _parsed_text(self):
		return _parsed(_section(".text", 0x1000, 0x1000))

	def _project(self, tmp_path, fn):
		return Project(
			name="t",
			xbe_path=Path("/x.xbe"),
			workspace_root=tmp_path / "ws",
			functions=(fn,),
			src_root=tmp_path / "src_tree",
		)

	def _workspace(self, project, fn, *, best, ctx, pct, success):
		ws = FunctionWorkspace(root=project.workspace_for(fn), function_name=fn.name)
		ws.initialize()
		ws.best_c.write_text(best)
		ws.ctx_h.write_text(ctx)
		ws.result_json.write_text(json.dumps({"best_match_percent": pct, "success": success}))
		return ws

	def test_commits_with_shared_common_header(self, tmp_path):
		fn = FunctionEntry("fn_00001000", 0x1000, 0x10)
		proj = self._project(tmp_path, fn)
		self._workspace(
			proj, fn, best="int fn_00001000(void){return 0;}\n",
			ctx="typedef int X;\n", pct=100.0, success=True,
		)
		res = integrate_commit(proj, self._parsed_text(), fn, compile_fn=_ok_compile)
		assert res.skipped_reason is None
		assert res.compiled is True
		assert res.path == function_source_path(proj, self._parsed_text(), fn)
		body = res.path.read_text()
		# The shared typedef preamble lives once, in include/ivcs_common.h.
		assert body.startswith('#include "../include/ivcs_common.h"')
		assert "int fn_00001000(void){return 0;}" in body
		common = proj.src_root / "include" / "ivcs_common.h"
		assert "typedef int X;" in common.read_text()
		# An all-preamble ctx has no function-specific tail → no per-function header.
		assert not res.path.with_name("fn_00001000.ctx.h").exists()
		assert 'fn_00001000.ctx.h' not in body

	def test_function_specific_decls_kept_in_per_function_header(self, tmp_path):
		fn = FunctionEntry("fn_00001000", 0x1000, 0x10)
		proj = self._project(tmp_path, fn)
		ctx = "typedef int X;\n\n/* Target — pins mangling. */\nint fn_00001000(void);\n"
		self._workspace(
			proj, fn, best="int fn_00001000(void){return 0;}\n",
			ctx=ctx, pct=100.0, success=True,
		)
		res = integrate_commit(proj, self._parsed_text(), fn, compile_fn=_ok_compile)
		body = res.path.read_text()
		assert '#include "../include/ivcs_common.h"' in body
		assert '#include "fn_00001000.ctx.h"' in body
		# Shared part in the common header, specific part in the per-fn header.
		assert "typedef int X;" in (proj.src_root / "include" / "ivcs_common.h").read_text()
		tail = res.path.with_name("fn_00001000.ctx.h").read_text()
		assert "int fn_00001000(void);" in tail
		assert "typedef int X;" not in tail  # not duplicated

	def test_common_header_shared_across_functions(self, tmp_path):
		parsed = self._parsed_text()
		preamble = "typedef int X;\n"
		fns = [
			FunctionEntry("fn_00001000", 0x1000, 0x10),
			FunctionEntry("fn_00001100", 0x1100, 0x10),
		]
		proj = Project(
			name="t", xbe_path=Path("/x.xbe"), workspace_root=tmp_path / "ws",
			functions=tuple(fns), src_root=tmp_path / "src_tree",
		)
		for fn in fns:
			self._workspace(proj, fn, best=f"int {fn.name}(void){{return 0;}}\n",
				ctx=preamble, pct=100.0, success=True)
			integrate_commit(proj, parsed, fn, compile_fn=_ok_compile)
		# Exactly one shared header; neither function carries its own typedef copy.
		commons = list((proj.src_root / "include").glob("*.h"))
		assert [p.name for p in commons] == ["ivcs_common.h"]
		for fn in fns:
			assert not function_source_path(proj, parsed, fn).with_name(f"{fn.name}.ctx.h").exists()

	def test_unmatched_not_committed_without_force(self, tmp_path):
		fn = FunctionEntry("fn_00001000", 0x1000, 0x10)
		proj = self._project(tmp_path, fn)
		self._workspace(proj, fn, best="x", ctx="y", pct=40.0, success=False)
		res = integrate_commit(proj, self._parsed_text(), fn, compile_fn=_ok_compile)
		assert res.compiled is False
		assert "not matched" in res.skipped_reason
		assert not res.path.exists()

	def test_force_commits_partial(self, tmp_path):
		fn = FunctionEntry("fn_00001000", 0x1000, 0x10)
		proj = self._project(tmp_path, fn)
		self._workspace(
			proj, fn, best="int f(void){return 1;}\n", ctx="z\n", pct=40.0, success=False
		)
		res = integrate_commit(proj, self._parsed_text(), fn, compile_fn=_ok_compile, force=True)
		assert res.skipped_reason is None
		assert res.path.is_file()

	def test_missing_best_c_skipped(self, tmp_path):
		fn = FunctionEntry("fn_00001000", 0x1000, 0x10)
		proj = self._project(tmp_path, fn)
		ws = FunctionWorkspace(root=proj.workspace_for(fn), function_name=fn.name)
		ws.initialize()
		ws.ctx_h.write_text("c\n")
		ws.result_json.write_text(json.dumps({"best_match_percent": 100.0, "success": True}))
		res = integrate_commit(proj, self._parsed_text(), fn, compile_fn=_ok_compile)
		assert "best.c" in res.skipped_reason
		assert not res.path.exists()

	def test_recompile_failure_reported_but_files_written(self, tmp_path):
		fn = FunctionEntry("fn_00001000", 0x1000, 0x10)
		proj = self._project(tmp_path, fn)
		self._workspace(proj, fn, best="int f(void){}\n", ctx="c\n", pct=100.0, success=True)
		res = integrate_commit(proj, self._parsed_text(), fn, compile_fn=_fail_compile)
		assert res.compiled is False
		assert res.skipped_reason is None  # committed; recompile is a warning signal
		assert res.path.is_file()


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
			name="t", xbe_path=Path("/x.xbe"), workspace_root=tmp_path / "ws",
			functions=tuple(fns), src_root=tmp_path / "src",
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
			name="t", xbe_path=Path("/x.xbe"), workspace_root=tmp_path / "ws",
			functions=tuple(fns), src_root=tmp_path / "src",
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
			name="t", xbe_path=Path("/x.xbe"), workspace_root=tmp_path / "ws",
			functions=(fn,), src_root=tmp_path / "src",
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
			name="t", xbe_path=Path("/x.xbe"), workspace_root=tmp_path / "ws",
			functions=tuple(fns), src_root=tmp_path / "src",
		)
		c = project_coverage(proj, parsed)[0]
		assert len(c.overlaps) == 1
		assert c.gaps  # trailing gap to 0x1200 at least

	def test_empty_project_is_empty(self, tmp_path):
		parsed = _parsed(_section(".text", 0x1000, 0x1000))
		proj = Project(
			name="t", xbe_path=Path("/x.xbe"), workspace_root=tmp_path / "ws",
			functions=(), src_root=tmp_path / "src",
		)
		assert project_coverage(proj, parsed) == ()
