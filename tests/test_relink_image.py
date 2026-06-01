"""Tests for the real-relink orchestration (Phase 4b).

The placement math is pure. The full orchestration is exercised with a fake
compiler (emits a real COFF via the writer) and a fake linker (emits a real PE
via the PE-test helper), so the collect-externals / pad / extract wiring runs
end-to-end without Wine.
"""

import json
import types
from pathlib import Path

from src.core.project import FunctionEntry, Project
from src.core.workspace import FunctionWorkspace
from src.formats.coff import coff_object_build
from src.formats.coff_read import coff_object_read
from src.formats.relocs import RelocKind, RelocSite, ResolvedReloc
from src.formats.xbe import SECTION_FLAG_EXECUTABLE, ParsedXbe, XbeHeader, XbeSection
from src.verify.link_tool import LinkOutput
from src.verify.relink_image import function_object_compile, function_real_relink, relink_placement
from tests.test_pe_read import _make_pe


class TestRelinkPlacement:
	def test_function_lands_at_va(self):
		base, pad = relink_placement(0x00175F40)
		assert base + 0x1000 + pad == 0x00175F40

	def test_pad_is_nonnegative(self):
		for va in (0x00011000, 0x00175F40, 0x002D0CF5, 0x003FFFFF):
			base, pad = relink_placement(va)
			assert pad >= 0
			assert base + 0x1000 + pad == va

	def test_low_bits_below_text_rva_drop_the_base(self):
		# low 16 bits (0x0800) < text_rva (0x1000): base must drop 64K.
		base, pad = relink_placement(0x00120800)
		assert pad >= 0
		assert base % 0x10000 == 0
		assert base + 0x1000 + pad == 0x00120800


def _parsed() -> ParsedXbe:
	section = XbeSection(
		name=".text",
		flags=SECTION_FLAG_EXECUTABLE,
		virtual_address=0x00011000,
		virtual_size=0x1000,
		raw_address=0,
		raw_size=0x1000,
	)
	return ParsedXbe(header=XbeHeader(0x10000, 0, 0, 0, 1, 0, 0, 0), sections=(section,), data=b"")


def _matched_workspace(root: Path, name: str) -> None:
	ws = FunctionWorkspace(root=root, function_name=name)
	ws.initialize()
	ws.best_c.write_text("void f(void){return;}\n")
	ws.ctx_h.write_text("/* ctx */\n")
	ws.result_json.write_text(json.dumps({"success": True, "best_match_percent": 100.0}))


def _project(tmp_path: Path, fn: FunctionEntry) -> Project:
	return Project(
		name="t",
		xbe_path=tmp_path / "x.xbe",
		workspace_root=tmp_path / "ws",
		functions=(fn,),
		src_root=tmp_path / "src_tree",
	)


def _compiler_emitting(obj_bytes: bytes):
	def compile_fn(c_source, out_obj, workspace_root):
		out_obj.write_bytes(obj_bytes)
		return types.SimpleNamespace(success=True)

	return compile_fn


def _linker_placing(fn_bytes: bytes):
	"""Fake linker: read the pad obj's .text length, emit a PE whose .text is the
	pad followed by fn_bytes at RVA 0x1000 — mirroring the real layout."""

	def link_fn(objs, out_path, *, base_address, entry=None, extra_flags=()):
		pad = coff_object_read(Path(objs[0]).read_bytes()).text_section().raw
		text = pad + fn_bytes
		out_path.write_bytes(_make_pe(base_address, [(".text", 0x1000, text)]))
		return LinkOutput(success=True, out_path=out_path)

	return link_fn


class TestFunctionObjectCompile:
	"""The shared recompile primitive used by both verifiers."""

	def test_writes_self_contained_source_and_returns_obj_example(self, tmp_path):
		ws_root = tmp_path / "ws"
		_matched_workspace(ws_root, "f")
		workspace = FunctionWorkspace(root=ws_root, function_name="f")
		build = tmp_path / "build"
		build.mkdir()
		captured = {}

		def compile_fn(c_source, out_obj, workspace_root):
			captured["src"] = c_source.read_text()
			out_obj.write_bytes(b"OBJ")
			return types.SimpleNamespace(success=True)

		obj = function_object_compile(workspace, build, "f", compile_fn)
		assert obj is not None
		assert obj.read_bytes() == b"OBJ"
		# best.c carries no include; the primitive prepends the copied ctx.h.
		assert '#include "f.ctx.h"' in captured["src"]
		assert "void f(void)" in captured["src"]

	def test_returns_none_when_inputs_missing_example(self, tmp_path):
		ws_root = tmp_path / "ws"
		workspace = FunctionWorkspace(root=ws_root, function_name="f")
		workspace.initialize()  # no best.c / ctx.h written
		build = tmp_path / "build"
		build.mkdir()
		assert function_object_compile(workspace, build, "f", _compiler_emitting(b"X")) is None

	def test_returns_none_when_compile_fails_example(self, tmp_path):
		ws_root = tmp_path / "ws"
		_matched_workspace(ws_root, "f")
		workspace = FunctionWorkspace(root=ws_root, function_name="f")
		build = tmp_path / "build"
		build.mkdir()

		def failing(c_source, out_obj, workspace_root):
			return types.SimpleNamespace(success=False)

		assert function_object_compile(workspace, build, "f", failing) is None


class TestFunctionRealRelink:
	def test_relocation_free_function_extracted_at_va(self, tmp_path):
		fn_bytes = b"\x55\x8b\xec\x5d\xc3"
		fn = FunctionEntry("fn_00011500", 0x00011500, len(fn_bytes))
		project = _project(tmp_path, fn)
		_matched_workspace(project.workspace_for(fn), fn.name)

		obj = coff_object_build(fn_bytes, "_FUN_00011500", relocations=[])
		result = function_real_relink(
			project,
			_parsed(),
			fn,
			compile_fn=_compiler_emitting(obj),
			link_fn=_linker_placing(fn_bytes),
		)
		assert result.ok
		assert result.function_bytes == fn_bytes

	def test_external_call_is_collected_into_stub_and_linked(self, tmp_path):
		# A function with one undefined external (_fn_00410000) — resolvable by the
		# default resolver. The fake linker doesn't patch it, but the orchestration
		# must build the stub without error and still place the function.
		fn_bytes = b"\xe8\x00\x00\x00\x00\xc3"
		fn = FunctionEntry("fn_00011500", 0x00011500, len(fn_bytes))
		project = _project(tmp_path, fn)
		_matched_workspace(project.workspace_for(fn), fn.name)

		reloc = ResolvedReloc(
			site=RelocSite(imm_offset=1, kind=RelocKind.REL32, target_va=0x00410000),
			symbol_name="_fn_00410000",
		)
		obj = coff_object_build(fn_bytes, "_FUN_00011500", relocations=[reloc])
		result = function_real_relink(
			project,
			_parsed(),
			fn,
			compile_fn=_compiler_emitting(obj),
			link_fn=_linker_placing(fn_bytes),
		)
		assert result.ok
		assert result.function_bytes == fn_bytes

	def test_unresolved_external_fails_cleanly(self, tmp_path):
		fn_bytes = b"\xe8\x00\x00\x00\x00\xc3"
		fn = FunctionEntry("fn_00011500", 0x00011500, len(fn_bytes))
		project = _project(tmp_path, fn)
		_matched_workspace(project.workspace_for(fn), fn.name)

		reloc = ResolvedReloc(
			site=RelocSite(imm_offset=1, kind=RelocKind.REL32, target_va=0),
			symbol_name="_mystery_thing",  # not fn_/data_/__imp__ → unresolvable
		)
		obj = coff_object_build(fn_bytes, "_FUN_00011500", relocations=[reloc])
		result = function_real_relink(
			project,
			_parsed(),
			fn,
			compile_fn=_compiler_emitting(obj),
			link_fn=_linker_placing(fn_bytes),
		)
		assert not result.ok
		assert "unresolved external" in result.reason

	def test_recompile_failure_reported(self, tmp_path):
		fn = FunctionEntry("fn_00011500", 0x00011500, 1)
		project = _project(tmp_path, fn)
		_matched_workspace(project.workspace_for(fn), fn.name)

		def failing(c_source, out_obj, workspace_root):
			return types.SimpleNamespace(success=False)

		result = function_real_relink(
			project, _parsed(), fn, compile_fn=failing, link_fn=_linker_placing(b"")
		)
		assert not result.ok
		assert result.reason == "recompile failed"
