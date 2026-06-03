"""Tests for Microsoft COFF/i386 object synthesis.

The carver feeds (carved bytes, function name, relocations) into
coff_object_build and gets back a .obj ready for objdiff-cli to diff
against an MSVC-compiled candidate.
"""

import shutil
import struct
import subprocess
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from src.formats.coff import (
	COFF_HEADER_SIZE,
	COFF_SYMBOL_SIZE,
	IMAGE_FILE_MACHINE_I386,
	IMAGE_REL_I386_DIR32,
	IMAGE_REL_I386_REL32,
	IMAGE_SCN_CNT_CODE,
	IMAGE_SCN_MEM_EXECUTE,
	IMAGE_SCN_MEM_READ,
	IMAGE_SYM_CLASS_EXTERNAL,
	IMAGE_SYM_CLASS_STATIC,
	IMAGE_SYM_TYPE_FUNCTION,
	coff_defined_function_rename,
	coff_object_build,
)
from src.formats.coff_read import CoffObject, CoffReloc, coff_object_read
from src.formats.relocs import RelocKind, RelocSite, ResolvedReloc


def _defined_function_name(blob: bytes) -> str | None:
	"""The name of the lone defined external function symbol, via the reader."""
	obj = coff_object_read(blob)
	names = [
		s.name
		for s in obj.symbols
		if s.storage_class == IMAGE_SYM_CLASS_EXTERNAL
		and s.section_number > 0
		and s.type == IMAGE_SYM_TYPE_FUNCTION
	]
	return names[0] if len(names) == 1 else None


class TestDefinedFunctionRename:
	def test_renames_short_name_to_canonical(self):
		# Source named it readably ("_XMemAlloc"); object should export "_fn_..".
		blob = coff_object_build(b"\xc3", "_XMemAlloc", relocations=[])
		out = coff_defined_function_rename(blob, "_fn_00012280@8")
		assert _defined_function_name(out) == "_fn_00012280@8"

	def test_renames_long_name_to_canonical(self):
		blob = coff_object_build(b"\xc3", "_CPlayer_Update_long_name", relocations=[])
		out = coff_defined_function_rename(blob, "_fn_00747474")
		assert _defined_function_name(out) == "_fn_00747474"

	def test_noop_when_already_canonical(self):
		blob = coff_object_build(b"\xc3", "_fn_00012280", relocations=[])
		assert coff_defined_function_rename(blob, "_fn_00012280") == blob

	def test_callee_externs_untouched_and_relocs_intact(self):
		body = b"\xe8\x00\x00\x00\x00\xc3"  # call rel32 ; ret
		reloc = ResolvedReloc(
			site=RelocSite(imm_offset=1, kind=RelocKind.REL32, target_va=0x00430000),
			symbol_name="_fn_00430000",
		)
		blob = coff_object_build(body, "_XMemAlloc", relocations=[reloc])
		out = coff_defined_function_rename(blob, "_fn_00012280@8")
		obj = coff_object_read(out)

		assert _defined_function_name(out) == "_fn_00012280@8"
		# The callee extern still present and unrenamed.
		assert any(s.name == "_fn_00430000" for s in obj.symbols)
		# The reloc still points at a symbol named "_fn_00430000".
		text = obj.text_section()
		assert text is not None
		(r,) = text.relocations
		assert obj.symbol_at(r.symbol_index).name == "_fn_00430000"

	def test_object_still_parses_after_rename(self):
		blob = coff_object_build(b"\x90\x90\xc3", "_XMemAlloc", relocations=[])
		out = coff_defined_function_rename(blob, "_fn_00012280@8")
		# Round-trips cleanly: text bytes preserved, one .text section.
		obj = coff_object_read(out)
		assert obj.text_section().raw == b"\x90\x90\xc3"


# Names kept disjoint so a rename only ever touches the defined function symbol.
_FUNC_NAMES = st.sampled_from(["_f", "_short", "_XMemAlloc", "_a_long_source_name_over_eight"])
_EXTERN_NAMES = st.sampled_from(["_alpha", "_beta", "__imp__NtClose@4", "_fn_00430000"])
_NEW_NAMES = st.sampled_from(["_fn_00012280@8", "_fn_00747474", "_fn_00000001"])


@st.composite
def _renameable_object(draw):
	"""(text_bytes, function_name, relocs, new_name) for a buildable .obj."""
	relocs: list[ResolvedReloc] = []
	body = b""
	for i in range(draw(st.integers(0, 4))):
		offset = len(body) + 1  # imm32 field sits one byte into the placeholder
		kind = draw(st.sampled_from([RelocKind.REL32, RelocKind.DIR32]))
		body += b"\xe8\x00\x00\x00\x00"  # opcode + 4-byte field the writer zeroes
		relocs.append(ResolvedReloc(RelocSite(offset, kind, 0x1000 + i), draw(_EXTERN_NAMES)))
	body += b"\xc3"
	return body, draw(_FUNC_NAMES), relocs, draw(_NEW_NAMES)


def _undefined_externs(obj) -> set[str]:
	return {s.name for s in obj.symbols if s.section_number == 0}


def _reloc_view(obj) -> list[tuple[int, int, str]]:
	text = obj.text_section()
	if text is None:
		return []
	return [(r.offset, r.type, obj.symbol_at(r.symbol_index).name) for r in text.relocations]


class TestDefinedFunctionRenameProperties:
	@given(case=_renameable_object())
	def test_rename_sets_name_and_preserves_everything_else(self, case):
		body, fname, relocs, new_name = case
		blob = coff_object_build(body, fname, relocations=relocs)
		before = coff_object_read(blob)
		out = coff_defined_function_rename(blob, new_name)
		after = coff_object_read(out)

		# The lone defined function now carries the canonical name...
		assert _defined_function_name(out) == new_name
		# ...while everything else the object carries is untouched:
		assert after.text_section().raw == before.text_section().raw
		assert _undefined_externs(after) == _undefined_externs(before)
		assert _reloc_view(after) == _reloc_view(before)

	@given(case=_renameable_object())
	def test_rename_is_idempotent(self, case):
		body, fname, relocs, new_name = case
		blob = coff_object_build(body, fname, relocations=relocs)
		once = coff_defined_function_rename(blob, new_name)
		# Second rename to the same canonical name hits the already-named no-op.
		assert coff_defined_function_rename(once, new_name) == once


# The reader (coff_object_read) is the inverse of the builder and is itself
# round-trip-tested in test_coff_read.py, so assertions about symbols, relocs,
# and raw bytes go through it rather than reparsing the layout here. Only what
# the reader deliberately doesn't model needs a raw probe: a section's
# characteristic flags and the on-disk short-vs-string-table name encoding.


def _symbol_slot(obj: CoffObject, name: str) -> int:
	"""The symbol-table slot of a named symbol, for on-disk encoding probes."""
	return next(slot for slot, sym in obj.symbol_by_slot.items() if sym.name == name)


def _name_field(blob: bytes, slot: int) -> bytes:
	"""The raw 8-byte name field of the symbol at `slot` (inline short name vs
	`\\0\\0\\0\\0` + string-table offset for a long name)."""
	symbol_table_ptr = struct.unpack_from("<I", blob, 8)[0]
	off = symbol_table_ptr + slot * COFF_SYMBOL_SIZE
	return blob[off : off + 8]


def _text_characteristics(blob: bytes) -> int:
	"""Section 0's characteristics flags — CoffSection models name/raw/relocs only."""
	return struct.unpack_from("<I", blob, COFF_HEADER_SIZE + 36)[0]


class TestCoffHeaderAndSections:
	def test_emits_valid_coff_header_for_minimal_function(self):
		blob = coff_object_build(b"\xc3", "_ret_only", relocations=[])
		obj = coff_object_read(blob)
		assert obj.machine == IMAGE_FILE_MACHINE_I386
		assert len(obj.sections) == 1
		# The static section symbol and the function symbol are both present.
		assert {".text", "_ret_only"} <= {s.name for s in obj.symbols}

	def test_emits_single_text_section_with_raw_bytes(self):
		body = b"\xb8\x01\x00\x00\x00\xc3"  # mov eax, 1; ret
		blob = coff_object_build(body, "_one", relocations=[])
		sec = coff_object_read(blob).text_section()
		assert sec is not None
		assert sec.name == ".text"
		assert sec.raw == body

	def test_text_section_has_code_and_execute_characteristics(self):
		blob = coff_object_build(b"\xc3", "_fn", relocations=[])
		chars = _text_characteristics(blob)
		assert chars & IMAGE_SCN_CNT_CODE
		assert chars & IMAGE_SCN_MEM_EXECUTE
		assert chars & IMAGE_SCN_MEM_READ

	def test_section_with_no_relocs_has_empty_relocations(self):
		blob = coff_object_build(b"\xc3", "_fn", relocations=[])
		sec = coff_object_read(blob).text_section()
		assert sec is not None
		assert sec.relocations == ()


class TestCoffSymbolTable:
	def test_function_symbol_present_with_external_class_and_function_type(self):
		blob = coff_object_build(b"\xc3", "_my_func", relocations=[])
		sym = next(s for s in coff_object_read(blob).symbols if s.name == "_my_func")
		assert sym.storage_class == IMAGE_SYM_CLASS_EXTERNAL
		assert sym.type == IMAGE_SYM_TYPE_FUNCTION
		assert sym.section_number == 1
		assert sym.value == 0

	def test_text_section_symbol_present_as_static_with_aux(self):
		blob = coff_object_build(b"\xc3", "_fn", relocations=[])
		obj = coff_object_read(blob)
		text_slot = _symbol_slot(obj, ".text")
		text_sym = obj.symbol_by_slot[text_slot]
		assert text_sym.storage_class == IMAGE_SYM_CLASS_STATIC
		assert text_sym.section_number == 1
		# The reader skips aux records, so an absent next slot proves the one aux.
		assert (text_slot + 1) not in obj.symbol_by_slot

	def test_one_external_symbol_per_unique_reloc_target(self):
		body = b"\xe8\x00\x00\x00\x00" * 3 + b"\xc3"
		relocs = [
			ResolvedReloc(
				site=RelocSite(imm_offset=1, kind=RelocKind.REL32, target_va=0x1000),
				symbol_name="_alpha",
			),
			ResolvedReloc(
				site=RelocSite(imm_offset=6, kind=RelocKind.REL32, target_va=0x2000),
				symbol_name="_beta",
			),
			ResolvedReloc(
				site=RelocSite(imm_offset=11, kind=RelocKind.REL32, target_va=0x3000),
				symbol_name="_gamma",
			),
		]
		blob = coff_object_build(body, "_caller", relocations=relocs)
		obj = coff_object_read(blob)
		for name in ("_alpha", "_beta", "_gamma"):
			sym = next(s for s in obj.symbols if s.name == name)
			assert sym.section_number == 0  # external/undefined
			assert sym.storage_class == IMAGE_SYM_CLASS_EXTERNAL

	def test_dedupes_externals_with_repeated_symbol_name(self):
		body = b"\xe8\x00\x00\x00\x00\xe8\x00\x00\x00\x00\xc3"
		relocs = [
			ResolvedReloc(
				site=RelocSite(imm_offset=1, kind=RelocKind.REL32, target_va=0x1000),
				symbol_name="_same",
			),
			ResolvedReloc(
				site=RelocSite(imm_offset=6, kind=RelocKind.REL32, target_va=0x1000),
				symbol_name="_same",
			),
		]
		blob = coff_object_build(body, "_caller", relocations=relocs)
		count = sum(1 for s in coff_object_read(blob).symbols if s.name == "_same")
		assert count == 1

	def test_long_symbol_name_uses_string_table(self):
		long_name = "_very_long_function_name_exceeding_eight_chars"
		assert len(long_name) > 8
		blob = coff_object_build(b"\xc3", long_name, relocations=[])
		# The reader recovers the name (so the string-table round-trips); the raw
		# probe confirms it was actually encoded out-of-line (four leading zeros).
		slot = _symbol_slot(coff_object_read(blob), long_name)
		assert _name_field(blob, slot)[:4] == b"\x00\x00\x00\x00"

	def test_short_symbol_name_inlined_in_eight_byte_field(self):
		blob = coff_object_build(b"\xc3", "_short", relocations=[])
		slot = _symbol_slot(coff_object_read(blob), "_short")
		assert _name_field(blob, slot)[:4] != b"\x00\x00\x00\x00"


class TestCoffRelocations:
	def test_one_reloc_record_per_resolved_reloc(self):
		body = b"\xe8\x00\x00\x00\x00\xe8\x00\x00\x00\x00\xc3"
		relocs = [
			ResolvedReloc(
				site=RelocSite(imm_offset=1, kind=RelocKind.REL32, target_va=0x1000),
				symbol_name="_a",
			),
			ResolvedReloc(
				site=RelocSite(imm_offset=6, kind=RelocKind.REL32, target_va=0x2000),
				symbol_name="_b",
			),
		]
		blob = coff_object_build(body, "_caller", relocations=relocs)
		sec = coff_object_read(blob).text_section()
		assert sec is not None
		assert len(sec.relocations) == 2

	def test_rel32_reloc_type_and_offset(self):
		body = b"\xe8\x00\x00\x00\x00\xc3"
		relocs = [
			ResolvedReloc(
				site=RelocSite(imm_offset=1, kind=RelocKind.REL32, target_va=0x1000),
				symbol_name="_target",
			)
		]
		blob = coff_object_build(body, "_caller", relocations=relocs)
		obj = coff_object_read(blob)
		sec = obj.text_section()
		assert sec is not None
		assert sec.relocations == (
			CoffReloc(
				offset=1, symbol_index=_symbol_slot(obj, "_target"), type=IMAGE_REL_I386_REL32
			),
		)

	def test_imm32_at_each_reloc_site_is_zeroed(self):
		# Pre-fill imm32 with non-zero garbage to prove zeroing happens
		body = b"\xe8\xde\xad\xbe\xef\xc3"
		relocs = [
			ResolvedReloc(
				site=RelocSite(imm_offset=1, kind=RelocKind.REL32, target_va=0x1000),
				symbol_name="_t",
			)
		]
		blob = coff_object_build(body, "_caller", relocations=relocs)
		sec = coff_object_read(blob).text_section()
		assert sec is not None
		assert sec.raw[1:5] == b"\x00\x00\x00\x00"
		assert sec.raw[0] == 0xE8
		assert sec.raw[5] == 0xC3

	def test_dir32_reloc_emits_image_rel_i386_dir32_type(self):
		# FF 15 imm32 = call dword ptr [imm32]
		body = b"\xff\x15\xde\xad\xbe\xef\xc3"
		relocs = [
			ResolvedReloc(
				site=RelocSite(imm_offset=2, kind=RelocKind.DIR32, target_va=0xEFBEADDE),
				symbol_name="__imp__NtClose@4",
			)
		]
		blob = coff_object_build(body, "_caller", relocations=relocs)
		sec = coff_object_read(blob).text_section()
		assert sec is not None
		assert len(sec.relocations) == 1
		assert sec.relocations[0].type == IMAGE_REL_I386_DIR32
		assert sec.relocations[0].offset == 2
		assert sec.raw[2:6] == b"\x00\x00\x00\x00"  # imm32 zeroed
		assert sec.raw[0:2] == b"\xff\x15"  # opcode preserved
		assert sec.raw[6] == 0xC3

	def test_reloc_symbol_index_points_to_matching_external(self):
		body = b"\xe8\x00\x00\x00\x00\xe8\x00\x00\x00\x00\xc3"
		relocs = [
			ResolvedReloc(
				site=RelocSite(imm_offset=1, kind=RelocKind.REL32, target_va=0x1000),
				symbol_name="_first",
			),
			ResolvedReloc(
				site=RelocSite(imm_offset=6, kind=RelocKind.REL32, target_va=0x2000),
				symbol_name="_second",
			),
		]
		blob = coff_object_build(body, "_caller", relocations=relocs)
		obj = coff_object_read(blob)
		sec = obj.text_section()
		assert sec is not None
		assert sec.relocations[0].symbol_index == _symbol_slot(obj, "_first")
		assert sec.relocations[1].symbol_index == _symbol_slot(obj, "_second")


class TestCoffEndToEndObjdiff:
	"""Round-trip the synthesized .obj through real objdiff-cli to prove parseability."""

	OBJDIFF_CLI = Path(__file__).resolve().parent.parent.parent / "recon/objdiff-smoke/objdiff-cli"

	def setup_method(self):
		if not self.OBJDIFF_CLI.is_file():
			pytest.skip(f"objdiff-cli not present at {self.OBJDIFF_CLI}")
		if shutil.which("file") is None:
			pytest.skip("file(1) not available")

	def test_objdiff_finds_function_symbol_in_synthesized_obj(self, tmp_path: Path):
		body = b"\xb8\x07\x00\x00\x00\xc3"  # mov eax, 7; ret
		blob = coff_object_build(body, "_seven", relocations=[])
		target = tmp_path / "target.obj"
		target.write_bytes(blob)

		# Diff against itself — both sides should parse identically
		cmd = [
			str(self.OBJDIFF_CLI),
			"diff",
			"-1",
			str(target),
			"-2",
			str(target),
			"--format",
			"json",
			"-o",
			"-",
		]
		result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=True)
		import json

		d = json.loads(result.stdout)
		left_symbols = [
			s["name"] for s in d["left"]["symbols"] if s.get("kind") == "SYMBOL_FUNCTION"
		]
		assert "_seven" in left_symbols

	def test_objdiff_handles_synthesized_obj_with_reloc(self, tmp_path: Path):
		body = b"\xe8\x00\x00\x00\x00\xc3"
		relocs = [
			ResolvedReloc(
				site=RelocSite(imm_offset=1, kind=RelocKind.REL32, target_va=0x1000),
				symbol_name="_callee",
			)
		]
		blob = coff_object_build(body, "_caller", relocations=relocs)
		target = tmp_path / "target.obj"
		target.write_bytes(blob)
		cmd = [
			str(self.OBJDIFF_CLI),
			"diff",
			"-1",
			str(target),
			"-2",
			str(target),
			"--format",
			"json",
			"-o",
			"-",
		]
		result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=True)
		import json

		d = json.loads(result.stdout)
		names = [s["name"] for s in d["left"]["symbols"]]
		assert "_caller" in names
