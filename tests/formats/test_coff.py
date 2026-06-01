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
	COFF_RELOC_SIZE,
	COFF_SECTION_SIZE,
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
from src.formats.coff_read import coff_object_read
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


def _coff_header_parse(blob: bytes) -> dict:
	machine, nsec, _ts, sym_ptr, nsym, optsz, chars = struct.unpack_from("<HHIIIHH", blob, 0)
	return dict(
		machine=machine,
		section_count=nsec,
		symbol_table_ptr=sym_ptr,
		symbol_count=nsym,
		optional_header_size=optsz,
		characteristics=chars,
	)


def _section_entry_parse(blob: bytes, index: int) -> dict:
	off = COFF_HEADER_SIZE + index * COFF_SECTION_SIZE
	name = blob[off : off + 8]
	_vs, _va, raw_sz, raw_ptr, rel_ptr, _ln_ptr, nrel, _nln, sc = struct.unpack_from(
		"<IIIIIIHHI", blob, off + 8
	)
	return dict(
		name=name.rstrip(b"\x00").decode("ascii", "replace"),
		raw_size=raw_sz,
		raw_ptr=raw_ptr,
		reloc_ptr=rel_ptr,
		reloc_count=nrel,
		characteristics=sc,
	)


def _symbol_name_at(blob: bytes, sym_index: int) -> str:
	hdr = _coff_header_parse(blob)
	off = hdr["symbol_table_ptr"] + sym_index * COFF_SYMBOL_SIZE
	name_field = blob[off : off + 8]
	if name_field[:4] == b"\x00\x00\x00\x00":
		str_off = struct.unpack_from("<I", name_field, 4)[0]
		strtab_off = hdr["symbol_table_ptr"] + hdr["symbol_count"] * COFF_SYMBOL_SIZE
		end = blob.find(b"\x00", strtab_off + str_off)
		return blob[strtab_off + str_off : end].decode("ascii", "replace")
	return name_field.rstrip(b"\x00").decode("ascii", "replace")


def _symbol_record_at(blob: bytes, sym_index: int) -> dict:
	hdr = _coff_header_parse(blob)
	off = hdr["symbol_table_ptr"] + sym_index * COFF_SYMBOL_SIZE
	val, sec, ty, cls, naux = struct.unpack_from("<IhHBB", blob, off + 8)
	return dict(
		name=_symbol_name_at(blob, sym_index),
		value=val,
		section=sec,
		type=ty,
		storage_class=cls,
		aux_count=naux,
	)


def _function_symbol_index(blob: bytes, name: str) -> int:
	hdr = _coff_header_parse(blob)
	for i in range(hdr["symbol_count"]):
		if _symbol_name_at(blob, i) == name:
			return i
	raise AssertionError(f"symbol {name!r} not present")


def _reloc_records(blob: bytes, section_index: int) -> list[dict]:
	sec = _section_entry_parse(blob, section_index)
	records = []
	for i in range(sec["reloc_count"]):
		off = sec["reloc_ptr"] + i * COFF_RELOC_SIZE
		va, sym_idx, ty = struct.unpack_from("<IIH", blob, off)
		records.append(dict(virtual_address=va, symbol_index=sym_idx, type=ty))
	return records


def _raw_section_bytes(blob: bytes, section_index: int) -> bytes:
	sec = _section_entry_parse(blob, section_index)
	return blob[sec["raw_ptr"] : sec["raw_ptr"] + sec["raw_size"]]


class TestCoffHeaderAndSections:
	def test_emits_valid_coff_header_for_minimal_function(self):
		blob = coff_object_build(b"\xc3", "_ret_only", relocations=[])
		hdr = _coff_header_parse(blob)
		assert hdr["machine"] == IMAGE_FILE_MACHINE_I386
		assert hdr["section_count"] == 1
		assert hdr["optional_header_size"] == 0
		assert hdr["symbol_count"] >= 3  # .text static + aux + function

	def test_emits_single_text_section_with_raw_bytes(self):
		body = b"\xb8\x01\x00\x00\x00\xc3"  # mov eax, 1; ret
		blob = coff_object_build(body, "_one", relocations=[])
		sec = _section_entry_parse(blob, 0)
		assert sec["name"] == ".text"
		assert sec["raw_size"] == len(body)
		assert _raw_section_bytes(blob, 0) == body

	def test_text_section_has_code_and_execute_characteristics(self):
		blob = coff_object_build(b"\xc3", "_fn", relocations=[])
		sec = _section_entry_parse(blob, 0)
		assert sec["characteristics"] & IMAGE_SCN_CNT_CODE
		assert sec["characteristics"] & IMAGE_SCN_MEM_EXECUTE
		assert sec["characteristics"] & IMAGE_SCN_MEM_READ

	def test_section_with_no_relocs_has_zero_reloc_count_and_ptr(self):
		blob = coff_object_build(b"\xc3", "_fn", relocations=[])
		sec = _section_entry_parse(blob, 0)
		assert sec["reloc_count"] == 0
		assert sec["reloc_ptr"] == 0


class TestCoffSymbolTable:
	def test_function_symbol_present_with_external_class_and_function_type(self):
		blob = coff_object_build(b"\xc3", "_my_func", relocations=[])
		idx = _function_symbol_index(blob, "_my_func")
		sym = _symbol_record_at(blob, idx)
		assert sym["storage_class"] == IMAGE_SYM_CLASS_EXTERNAL
		assert sym["type"] == IMAGE_SYM_TYPE_FUNCTION
		assert sym["section"] == 1
		assert sym["value"] == 0

	def test_text_section_symbol_present_as_static_with_aux(self):
		blob = coff_object_build(b"\xc3", "_fn", relocations=[])
		idx = _function_symbol_index(blob, ".text")
		sym = _symbol_record_at(blob, idx)
		assert sym["storage_class"] == IMAGE_SYM_CLASS_STATIC
		assert sym["aux_count"] == 1
		assert sym["section"] == 1

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
		for name in ("_alpha", "_beta", "_gamma"):
			sym = _symbol_record_at(blob, _function_symbol_index(blob, name))
			assert sym["section"] == 0  # external/undefined
			assert sym["storage_class"] == IMAGE_SYM_CLASS_EXTERNAL

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
		# Count occurrences of "_same" in symbol table
		hdr = _coff_header_parse(blob)
		count = sum(1 for i in range(hdr["symbol_count"]) if _symbol_name_at(blob, i) == "_same")
		assert count == 1

	def test_long_symbol_name_uses_string_table(self):
		long_name = "_very_long_function_name_exceeding_eight_chars"
		assert len(long_name) > 8
		blob = coff_object_build(b"\xc3", long_name, relocations=[])
		idx = _function_symbol_index(blob, long_name)
		# Confirm the on-disk name field starts with four zero bytes
		hdr = _coff_header_parse(blob)
		off = hdr["symbol_table_ptr"] + idx * COFF_SYMBOL_SIZE
		assert blob[off : off + 4] == b"\x00\x00\x00\x00"

	def test_short_symbol_name_inlined_in_eight_byte_field(self):
		blob = coff_object_build(b"\xc3", "_short", relocations=[])
		idx = _function_symbol_index(blob, "_short")
		hdr = _coff_header_parse(blob)
		off = hdr["symbol_table_ptr"] + idx * COFF_SYMBOL_SIZE
		assert blob[off : off + 4] != b"\x00\x00\x00\x00"


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
		records = _reloc_records(blob, 0)
		assert len(records) == 2

	def test_rel32_reloc_type_and_virtual_address(self):
		body = b"\xe8\x00\x00\x00\x00\xc3"
		relocs = [
			ResolvedReloc(
				site=RelocSite(imm_offset=1, kind=RelocKind.REL32, target_va=0x1000),
				symbol_name="_target",
			)
		]
		blob = coff_object_build(body, "_caller", relocations=relocs)
		records = _reloc_records(blob, 0)
		assert records == [
			dict(
				virtual_address=1,
				symbol_index=_function_symbol_index(blob, "_target"),
				type=IMAGE_REL_I386_REL32,
			)
		]

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
		raw = _raw_section_bytes(blob, 0)
		assert raw[1:5] == b"\x00\x00\x00\x00"
		assert raw[0] == 0xE8
		assert raw[5] == 0xC3

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
		records = _reloc_records(blob, 0)
		assert len(records) == 1
		assert records[0]["type"] == IMAGE_REL_I386_DIR32
		assert records[0]["virtual_address"] == 2
		raw = _raw_section_bytes(blob, 0)
		assert raw[2:6] == b"\x00\x00\x00\x00"  # imm32 zeroed
		assert raw[0:2] == b"\xff\x15"  # opcode preserved
		assert raw[6] == 0xC3

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
		records = _reloc_records(blob, 0)
		first_idx = _function_symbol_index(blob, "_first")
		second_idx = _function_symbol_index(blob, "_second")
		assert records[0]["symbol_index"] == first_idx
		assert records[1]["symbol_index"] == second_idx


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
