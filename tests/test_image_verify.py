"""Tests for whole-image byte-splice verification (integrator Phase 4a).

A data-backed ParsedXbe carries the original image bytes; a fake compiler emits
a real COFF object (via the writer) so the reader + relocator run end-to-end
without Wine.
"""

import json
import struct
import types
from pathlib import Path

from src.coff import coff_object_build
from src.integrator import image_splice_verify
from src.project import FunctionEntry, Project
from src.relocs import RelocKind, RelocSite, ResolvedReloc
from src.workspace import FunctionWorkspace
from src.xbe import SECTION_FLAG_EXECUTABLE, ParsedXbe, XbeHeader, XbeSection

TEXT_VA = 0x00011000


def _parsed_with_text(text_bytes: bytes, text_va: int = TEXT_VA) -> ParsedXbe:
	"""One executable .text section whose raw bytes ARE text_bytes, at file
	offset 0 — so xbe_function_carve(va, n) returns text_bytes[:n]."""
	section = XbeSection(
		name=".text",
		flags=SECTION_FLAG_EXECUTABLE,
		virtual_address=text_va,
		virtual_size=len(text_bytes),
		raw_address=0,
		raw_size=len(text_bytes),
	)
	header = XbeHeader(0x10000, 0, 0, 0, 1, 0, 0, 0)
	return ParsedXbe(header=header, sections=(section,), data=text_bytes)


def _matched_workspace(root: Path, name: str) -> None:
	ws = FunctionWorkspace(root=root, function_name=name)
	ws.initialize()
	ws.best_c.write_text("void f(void){return;}\n")
	ws.ctx_h.write_text("/* ctx */\n")
	ws.result_json.write_text(json.dumps({"success": True, "best_match_percent": 100.0}))


def _project(tmp_path: Path, functions) -> Project:
	return Project(
		name="t",
		xbe_path=tmp_path / "x.xbe",
		workspace_root=tmp_path / "ws",
		functions=tuple(functions),
		src_root=tmp_path / "src_tree",
	)


def _fake_compiler(obj_bytes: bytes):
	def compile_fn(c_source, out_obj, workspace_root):
		out_obj.write_bytes(obj_bytes)
		return types.SimpleNamespace(success=True)

	return compile_fn


class TestNoRelocations:
	def test_exact_byte_match_is_fully_verified(self, tmp_path):
		body = b"\x55\x8b\xec\x5d\xc3"
		parsed = _parsed_with_text(body)
		fn = FunctionEntry("fn_00011000", TEXT_VA, len(body))
		project = _project(tmp_path, [fn])
		_matched_workspace(project.workspace_for(fn), fn.name)

		obj = coff_object_build(body, "f", relocations=[])
		result = image_splice_verify(project, parsed, compile_fn=_fake_compiler(obj))

		assert result.verified_bytes == len(body)
		assert result.matched_bytes == len(body)
		assert result.verified_percent == 100.0
		assert result.functions[0].is_verified

	def test_one_wrong_byte_is_reported(self, tmp_path):
		original = b"\x55\x8b\xec\x5d\xc3"
		compiled = b"\x55\x8b\xec\x5d\x90"  # last byte differs
		parsed = _parsed_with_text(original)
		fn = FunctionEntry("fn_00011000", TEXT_VA, len(original))
		project = _project(tmp_path, [fn])
		_matched_workspace(project.workspace_for(fn), fn.name)

		obj = coff_object_build(compiled, "f", relocations=[])
		result = image_splice_verify(project, parsed, compile_fn=_fake_compiler(obj))

		fv = result.functions[0]
		assert fv.verified_bytes == 4
		assert not fv.is_verified
		assert "4/5" in fv.reason


class TestRel32Relocated:
	def test_call_relocated_to_original_bytes(self, tmp_path):
		# Original: call to a callee at TEXT_VA+0x100. The relocated compiled
		# bytes must reproduce the original rel32 displacement exactly.
		callee_va = TEXT_VA + 0x100
		rel = (callee_va - (TEXT_VA + 5)) & 0xFFFFFFFF
		original = b"\xe8" + struct.pack("<I", rel) + b"\xc3"
		parsed = _parsed_with_text(original)

		fn = FunctionEntry("fn_00011000", TEXT_VA, len(original))
		project = _project(tmp_path, [fn])
		_matched_workspace(project.workspace_for(fn), fn.name)

		# Compiled obj: same opcodes, imm32 zeroed, with a REL32 reloc to
		# the _fn_<callee_va> symbol (name encodes the VA).
		reloc = ResolvedReloc(
			site=RelocSite(imm_offset=1, kind=RelocKind.REL32, target_va=callee_va),
			symbol_name=f"_fn_{callee_va:08X}",
		)
		obj = coff_object_build(b"\xe8\x00\x00\x00\x00\xc3", "f", relocations=[reloc])

		result = image_splice_verify(project, parsed, compile_fn=_fake_compiler(obj))
		assert result.functions[0].is_verified
		assert result.verified_percent == 100.0


class TestSizeMismatch:
	"""A relink that produces the wrong number of bytes is a hard failure, not a
	partial/near match — otherwise a too-short relink reads as 'almost matched'
	and a too-long one whose prefix matches reads as fully verified."""

	def test_short_relink_is_size_mismatch_not_partial_example(self, tmp_path):
		original = b"\x55\x8b\xec\x5d\x90\xc3"  # 6 bytes
		compiled = b"\x55\x8b\xec\xc3"  # 4 bytes — relink lost two bytes
		parsed = _parsed_with_text(original)
		fn = FunctionEntry("fn_00011000", TEXT_VA, len(original))
		project = _project(tmp_path, [fn])
		_matched_workspace(project.workspace_for(fn), fn.name)

		obj = coff_object_build(compiled, "f", relocations=[])
		result = image_splice_verify(project, parsed, compile_fn=_fake_compiler(obj))

		fv = result.functions[0]
		assert not fv.is_verified
		assert fv.verified_bytes == 0
		assert "size mismatch" in fv.reason

	def test_long_relink_with_matching_prefix_is_not_verified_example(self, tmp_path):
		original = b"\x55\x8b\xec\x5d\x90\xc3"  # 6 bytes
		compiled = original + b"\x90\x90"  # 8 bytes — prefix matches exactly
		parsed = _parsed_with_text(original)
		fn = FunctionEntry("fn_00011000", TEXT_VA, len(original))
		project = _project(tmp_path, [fn])
		_matched_workspace(project.workspace_for(fn), fn.name)

		obj = coff_object_build(compiled, "f", relocations=[])
		result = image_splice_verify(project, parsed, compile_fn=_fake_compiler(obj))

		fv = result.functions[0]
		assert not fv.is_verified  # must NOT be a false positive
		assert fv.verified_bytes == 0
		assert "size mismatch" in fv.reason


class TestUntouchedSkipped:
	def test_only_matched_functions_are_verified(self, tmp_path):
		body = b"\xc3"
		parsed = _parsed_with_text(body)
		fn = FunctionEntry("fn_00011000", TEXT_VA, 1)
		project = _project(tmp_path, [fn])
		# No workspace/result.json → untouched → not verified, not counted.
		result = image_splice_verify(project, parsed, compile_fn=_fake_compiler(b""))
		assert result.functions == ()
		assert result.matched_bytes == 0
		assert result.verified_percent == 0.0
