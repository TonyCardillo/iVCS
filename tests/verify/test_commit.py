"""Tests for src.verify.commit — promoting matched best.c into the source tree.

Each test stands up a real workspace (best.c + ctx.h + result.json) under tmp_path
and commits it with a stubbed compile_fn, then asserts on the written tree.
"""

import json
from pathlib import Path

from src.core.project import FunctionEntry, Project
from src.core.workspace import FunctionWorkspace
from src.verify.commit import integrate_commit
from src.verify.segments import function_source_path
from tests.verify._helpers import _fail_compile, _ok_compile, _parsed, _section


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
			proj,
			fn,
			best="int fn_00001000(void){return 0;}\n",
			ctx="typedef int X;\n",
			pct=100.0,
			success=True,
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
		assert "fn_00001000.ctx.h" not in body

	def test_function_specific_decls_kept_in_per_function_header(self, tmp_path):
		fn = FunctionEntry("fn_00001000", 0x1000, 0x10)
		proj = self._project(tmp_path, fn)
		ctx = "typedef int X;\n\n/* Target — pins mangling. */\nint fn_00001000(void);\n"
		self._workspace(
			proj,
			fn,
			best="int fn_00001000(void){return 0;}\n",
			ctx=ctx,
			pct=100.0,
			success=True,
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
			name="t",
			xbe_path=Path("/x.xbe"),
			workspace_root=tmp_path / "ws",
			functions=tuple(fns),
			src_root=tmp_path / "src_tree",
		)
		for fn in fns:
			self._workspace(
				proj,
				fn,
				best=f"int {fn.name}(void){{return 0;}}\n",
				ctx=preamble,
				pct=100.0,
				success=True,
			)
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

	def test_diverging_preamble_self_contains_without_clobbering_shared_header(self, tmp_path):
		# Two functions whose ctx typedef preambles differ. Committing the second
		# must NOT overwrite the shared include/ivcs_common.h out from under the
		# first: the divergent function carries its own full ctx instead, and the
		# first stays self-consistent (its shared typedef is still there).
		parsed = self._parsed_text()
		a = FunctionEntry("fn_00001000", 0x1000, 0x10)
		b = FunctionEntry("fn_00001100", 0x1100, 0x10)
		proj = Project(
			name="t",
			xbe_path=Path("/x.xbe"),
			workspace_root=tmp_path / "ws",
			functions=(a, b),
			src_root=tmp_path / "src_tree",
		)
		self._workspace(
			proj,
			a,
			best="int a(void){return 0;}\n",
			ctx="typedef int X;\n",
			pct=100.0,
			success=True,
		)
		self._workspace(
			proj,
			b,
			best="int b(void){return 0;}\n",
			ctx="typedef long Y;\n",
			pct=100.0,
			success=True,
		)

		integrate_commit(proj, parsed, a, compile_fn=_ok_compile)
		integrate_commit(proj, parsed, b, compile_fn=_ok_compile)

		# First writer owns the shared header; the divergent second did not clobber it.
		shared = (proj.src_root / "include" / "ivcs_common.h").read_text()
		assert "typedef int X;" in shared
		assert "typedef long Y;" not in shared

		# A still leans on the shared header and remains buildable.
		a_body = function_source_path(proj, parsed, a).read_text()
		assert '#include "../include/ivcs_common.h"' in a_body

		# B does not use the shared header; it carries its own typedef self-contained.
		b_path = function_source_path(proj, parsed, b)
		b_body = b_path.read_text()
		assert '#include "../include/ivcs_common.h"' not in b_body
		assert '#include "fn_00001100.ctx.h"' in b_body
		assert "typedef long Y;" in b_path.with_name("fn_00001100.ctx.h").read_text()

	def test_recompile_failure_reported_but_files_written(self, tmp_path):
		fn = FunctionEntry("fn_00001000", 0x1000, 0x10)
		proj = self._project(tmp_path, fn)
		self._workspace(proj, fn, best="int f(void){}\n", ctx="c\n", pct=100.0, success=True)
		res = integrate_commit(proj, self._parsed_text(), fn, compile_fn=_fail_compile)
		assert res.compiled is False
		assert res.skipped_reason is None  # committed; recompile is a warning signal
		assert res.path.is_file()
