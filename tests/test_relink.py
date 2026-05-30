"""Tests for the single-function relocator."""

import struct

import pytest

from src.coff import IMAGE_REL_I386_DIR32, IMAGE_REL_I386_REL32, IMAGE_SYM_CLASS_STATIC
from src.coff_read import CoffObject, CoffReloc, CoffSection, CoffSymbol
from src.relink import RelinkError, relink_place


def _obj(text: bytes, relocs, symbols_by_slot) -> CoffObject:
	section = CoffSection(name=".text", raw=text, relocations=tuple(relocs))
	return CoffObject(
		machine=0x014C,
		sections=(section,),
		symbols=tuple(symbols_by_slot.values()),
		symbol_by_slot=symbols_by_slot,
	)


def _extern(name: str) -> CoffSymbol:
	return CoffSymbol(name=name, value=0, section_number=0, type=0, storage_class=2)


def _signed32(b: bytes) -> int:
	return struct.unpack("<i", b)[0]


def _unsigned32(b: bytes) -> int:
	return struct.unpack("<I", b)[0]


class TestMalformedReloc:
	def test_reloc_field_past_text_raises_relink_error_example(self):
		# A reloc whose 4-byte field runs past the end of .text must raise the
		# module's own RelinkError, not an opaque struct.error. The splice
		# verifier catches RelinkError per-function; a bare struct.error would
		# escape and abort the whole image-verify loop.
		text = b"\xe8\x00\x00\x00\x00\xc3"  # 6 bytes
		relocs = [CoffReloc(offset=4, symbol_index=2, type=IMAGE_REL_I386_REL32)]  # 4+4 > 6
		symbols = {0: _extern(".text"), 1: _extern("fn_1"), 2: _extern("_fn_00410000")}
		obj = _obj(text, relocs, symbols)
		with pytest.raises(RelinkError):
			relink_place(obj, 0x00400000, lambda n: 0x00410000)


class TestNoRelocations:
	def test_text_unchanged(self):
		text = b"\x55\x8b\xec\x5d\xc3"
		obj = _obj(text, [], {0: _extern(".text")})
		assert relink_place(obj, 0x00400000, lambda n: None) == text


class TestRel32:
	def test_external_call_displacement(self):
		# E8 <imm32> at offset 1; call into _fn_00410000.
		text = b"\xe8\x00\x00\x00\x00\xc3"
		relocs = [CoffReloc(offset=1, symbol_index=2, type=IMAGE_REL_I386_REL32)]
		symbols = {0: _extern(".text"), 1: _extern("fn_1"), 2: _extern("_fn_00410000")}
		obj = _obj(text, relocs, symbols)

		out = relink_place(obj, 0x00400000, lambda n: 0x00410000 if n == "_fn_00410000" else None)

		expected = 0x00410000 - (0x00400000 + 1 + 4)
		assert _signed32(out[1:5]) == expected

	def test_addend_in_field_is_honored(self):
		# A nonzero addend (as cl.exe emits for .text-relative sites) is added in.
		text = b"\xe8" + struct.pack("<i", 0x10) + b"\xc3"
		relocs = [CoffReloc(offset=1, symbol_index=2, type=IMAGE_REL_I386_REL32)]
		symbols = {0: _extern(".text"), 1: _extern("fn_1"), 2: _extern("_fn_00410000")}
		obj = _obj(text, relocs, symbols)

		out = relink_place(obj, 0x00400000, lambda n: 0x00410000)

		expected = (0x00410000 + 0x10) - (0x00400000 + 1 + 4)
		assert _signed32(out[1:5]) == expected


class TestDir32:
	def test_absolute_address_written(self):
		# FF 15 <imm32> at offset 2; indirect call through a kernel thunk slot.
		text = b"\xff\x15\x00\x00\x00\x00\xc3"
		relocs = [CoffReloc(offset=2, symbol_index=1, type=IMAGE_REL_I386_DIR32)]
		symbols = {0: _extern(".text"), 1: _extern("__imp__KeFn")}
		obj = _obj(text, relocs, symbols)

		out = relink_place(obj, 0x00400000, lambda n: 0x00088100)

		assert _unsigned32(out[2:6]) == 0x00088100


class TestSectionRelativeSymbol:
	def test_text_relative_branch_is_placement_independent(self):
		# REL32 against the .text section symbol with the target's section offset
		# as the addend — a local jump. Result must not depend on placement_va.
		text = b"\xe8" + struct.pack("<i", 0x20) + b"\xc3"
		relocs = [CoffReloc(offset=1, symbol_index=0, type=IMAGE_REL_I386_REL32)]
		text_sym = CoffSymbol(
			name=".text", value=0, section_number=1, type=0, storage_class=IMAGE_SYM_CLASS_STATIC
		)
		obj = _obj(text, relocs, {0: text_sym})

		out_a = relink_place(obj, 0x00400000, lambda n: None)
		out_b = relink_place(obj, 0x00999000, lambda n: None)

		expected = 0x20 - (1 + 4)
		assert _signed32(out_a[1:5]) == expected
		assert out_a == out_b


class TestUnresolved:
	def test_unresolvable_external_raises(self):
		text = b"\xe8\x00\x00\x00\x00\xc3"
		relocs = [CoffReloc(offset=1, symbol_index=1, type=IMAGE_REL_I386_REL32)]
		obj = _obj(text, relocs, {0: _extern(".text"), 1: _extern("_data_DEADBEEF")})

		with pytest.raises(RelinkError):
			relink_place(obj, 0x00400000, lambda n: None)
