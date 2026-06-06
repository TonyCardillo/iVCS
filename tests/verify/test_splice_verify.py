"""Tests for src.verify.splice_verify — the verify-result cache and the
per-matched-function progress hook.

The end-to-end relink/byte-compare path (real COFF objects, no Wine) lives in
test_image_verify.py; these cover the cache round-trip and the on_result callback.
"""

import json
import types
from pathlib import Path

from src.core.project import FunctionEntry, Project
from src.core.workspace import FunctionWorkspace
from src.verify.splice_verify import (
	FunctionVerify,
	ImageVerify,
	_compiled_function_object,
	image_splice_verify,
	image_verify_cache_load,
	image_verify_cache_path,
	image_verify_cache_write,
)
from tests.verify._helpers import _fail_compile, _parsed, _section


class TestMalformedRecompiledObject:
	def test_non_coff_recompile_output_is_reported_as_none_not_raised(self, tmp_path):
		# A recompile that emits a non-COFF blob must surface as an unverified
		# function (None), not a CoffReadError that escapes the per-function catch
		# and aborts the whole image-verify loop (cf. the relink KeyError, #1).
		fn = FunctionEntry("a", 0x1000, 4)
		proj = Project(
			name="t",
			xbe_path=Path("/x.xbe"),
			workspace_root=tmp_path / "ws",
			functions=(fn,),
			src_root=tmp_path / "src",
		)
		ws = FunctionWorkspace(root=proj.workspace_for(fn), function_name=fn.name)
		ws.initialize()
		ws.best_c.write_text("int a(void){return 0;}\n")
		ws.ctx_h.write_text("// ctx\n")

		def garbage_compile(c_source, out_obj, workspace_root):
			out_obj.write_bytes(b"not a coff object at all")
			return types.SimpleNamespace(success=True)

		build = tmp_path / "build"
		build.mkdir()
		assert _compiled_function_object(proj, fn, garbage_compile, build) is None


class TestImageVerifyCache:
	def test_write_then_load_round_trip(self, tmp_path):
		project_path = tmp_path / "project.json"
		project_path.write_text("{}")
		result = ImageVerify(
			functions=(
				FunctionVerify("a", 0x1000, 16, 16, None),
				FunctionVerify("b", 0x1010, 16, 8, "8/16 bytes match"),
			),
			matched_bytes=32,
			verified_bytes=24,
		)
		image_verify_cache_write(project_path, result, when=1234.0)
		assert image_verify_cache_path(project_path) == tmp_path / "image_verify.json"

		got = image_verify_cache_load(project_path)
		assert got["verified_bytes"] == 24
		assert got["matched_bytes"] == 32
		assert got["functions"] == 2
		assert got["functions_verified"] == 1
		assert got["generated_at"] == 1234.0

	def test_load_missing_returns_none(self, tmp_path):
		assert image_verify_cache_load(tmp_path / "project.json") is None


class TestImageVerifyProgress:
	def test_on_result_called_per_matched_function(self, tmp_path):
		# Two matched functions; stub compile so no Wine. relink will fail (no real
		# obj), but on_result must still fire once per matched function.
		fns = [FunctionEntry("a", 0x1000, 4), FunctionEntry("b", 0x1010, 4)]
		section = _section(".text", 0x1000, 0x100)
		parsed = _parsed(section)
		proj = Project(
			name="t",
			xbe_path=Path("/x.xbe"),
			workspace_root=tmp_path / "ws",
			functions=tuple(fns),
			src_root=tmp_path / "src",
		)
		for fn in fns:
			ws = FunctionWorkspace(root=proj.workspace_for(fn), function_name=fn.name)
			ws.root.mkdir(parents=True)
			ws.result_json.write_text(json.dumps({"best_match_percent": 100.0, "success": True}))

		seen = []
		image_splice_verify(proj, parsed, compile_fn=_fail_compile, on_result=seen.append)
		assert [fv.name for fv in seen] == ["a", "b"]
