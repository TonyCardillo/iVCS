"""Tests for the XBE (Xbox Executable) loader.

The XBE format is documented in Cxbx-Reloaded's src/common/xbe/Xbe.h.
Header is 0x178 bytes minimum; section headers are 56 bytes each; section
name strings are null-terminated ASCII stored in the header region.
Virtual addresses inside the header region convert to file offsets via
(vaddr - base_addr).

These tests synthesize minimal valid XBEs at byte level rather than
shipping a real game .xbe; format conformance is the contract under test.
"""

import dataclasses
import struct
from io import BytesIO

import pytest

from src.xbe import (
	SECTION_FLAG_EXECUTABLE,
	SECTION_FLAG_WRITABLE,
	XBE_EP_KEY_CHIHIRO,
	XBE_EP_KEY_DEBUG,
	XBE_EP_KEY_RETAIL,
	XBE_KT_KEY_CHIHIRO,
	XBE_KT_KEY_DEBUG,
	XbeFormatError,
	XbeFunction,
	is_xbe_magic_valid,
	xbe_build_flavor_detect,
	xbe_entry_point_get,
	xbe_function_carve,
	xbe_functions_enumerate,
	xbe_kernel_thunk_address_get,
	xbe_parse,
	xbe_section_containing_va,
	xbe_section_find,
	xbe_section_read,
)


def build_minimal_xbe(
	base_addr: int = 0x00010000,
	sections: list[tuple[str, int, bytes] | tuple[str, int, bytes, int]] | None = None,
	size_of_image: int = 0,
	entry_point_xor: int = 0,
	kernel_thunk_address_xor: int = 0,
) -> bytes:
	"""Construct a syntactically-valid XBE byte stream for tests.

	sections: list of (name, flags, raw_data) or (name, flags, raw_data,
	virtual_address). Raw addresses pack contiguously after the name table;
	virtual_address defaults to 0 when omitted.
	"""
	sections = sections or []
	normalized: list[tuple[str, int, bytes, int]] = []
	for entry in sections:
		if len(entry) == 4:
			normalized.append(entry)  # type: ignore[arg-type]
		else:
			name, flags, data = entry
			normalized.append((name, flags, data, 0))
	sections = normalized
	header_size = 0x178
	section_header_size = 56
	section_table_offset = header_size
	section_table_size = section_header_size * len(sections)

	name_table_offset = section_table_offset + section_table_size
	name_bytes = b""
	name_offsets: list[int] = []
	for name, _, _, _ in sections:
		name_offsets.append(len(name_bytes))
		name_bytes += name.encode("ascii") + b"\x00"

	raw_data_offset = name_table_offset + len(name_bytes)

	header = bytearray(header_size)
	header[0:4] = b"XBEH"
	struct.pack_into("<I", header, 0x104, base_addr)
	struct.pack_into("<I", header, 0x108, raw_data_offset)
	struct.pack_into("<I", header, 0x10C, size_of_image)
	struct.pack_into("<I", header, 0x110, header_size)
	struct.pack_into("<I", header, 0x11C, len(sections))
	struct.pack_into("<I", header, 0x120, base_addr + section_table_offset)
	struct.pack_into("<I", header, 0x128, entry_point_xor)
	struct.pack_into("<I", header, 0x158, kernel_thunk_address_xor)

	out = BytesIO()
	out.write(bytes(header))

	raw_cursor = raw_data_offset
	for (_name, flags, data, virtual_address), name_off in zip(sections, name_offsets, strict=True):
		out.write(struct.pack("<I", flags))
		out.write(struct.pack("<I", virtual_address))
		out.write(struct.pack("<I", len(data)))  # virtual size
		out.write(struct.pack("<I", raw_cursor))  # raw addr
		out.write(struct.pack("<I", len(data)))  # raw size
		out.write(struct.pack("<I", base_addr + name_table_offset + name_off))
		out.write(struct.pack("<I", 0))  # section ref count
		out.write(struct.pack("<I", 0))  # head shared ref count addr
		out.write(struct.pack("<I", 0))  # tail shared ref count addr
		out.write(b"\x00" * 20)  # section digest
		raw_cursor += len(data)

	out.write(name_bytes)
	for _, _, data, _ in sections:
		out.write(data)

	return out.getvalue()


class TestMagicCheck:
	def test_valid_magic_passes(self):
		assert is_xbe_magic_valid(build_minimal_xbe()) is True

	def test_wrong_magic_fails(self):
		assert is_xbe_magic_valid(b"MZ\x90\x00" + b"\x00" * 100) is False

	def test_empty_data_fails(self):
		assert is_xbe_magic_valid(b"") is False

	def test_too_short_fails(self):
		assert is_xbe_magic_valid(b"XBE") is False


class TestHeaderParse:
	def test_header_fields_match_input(self):
		parsed = xbe_parse(build_minimal_xbe(base_addr=0x00020000))
		assert parsed.header.base_address == 0x00020000
		assert parsed.header.section_count == 0
		assert parsed.header.size_of_image_header == 0x178

	def test_bad_magic_raises(self):
		with pytest.raises(XbeFormatError, match="magic"):
			xbe_parse(b"NOPE" + b"\x00" * 1000)

	def test_truncated_header_raises(self):
		with pytest.raises(XbeFormatError, match="header"):
			xbe_parse(b"XBEH" + b"\x00" * 50)


class TestSectionEnumeration:
	def test_zero_sections(self):
		parsed = xbe_parse(build_minimal_xbe(sections=[]))
		assert parsed.sections == ()

	def test_single_section_attributes(self):
		section_data = b"\x90" * 16
		flags = SECTION_FLAG_EXECUTABLE
		parsed = xbe_parse(build_minimal_xbe(sections=[(".text", flags, section_data)]))

		assert len(parsed.sections) == 1
		s = parsed.sections[0]
		assert s.name == ".text"
		assert s.flags == flags
		assert s.is_executable is True
		assert s.is_writable is False
		assert s.virtual_size == 16
		assert s.raw_size == 16

	def test_multiple_sections_preserve_order(self):
		parsed = xbe_parse(
			build_minimal_xbe(
				sections=[
					(".text", SECTION_FLAG_EXECUTABLE, b"\x90\x90"),
					(".data", SECTION_FLAG_WRITABLE, b"\x01\x02\x03"),
					(".rdata", 0, b"\xaa"),
				]
			)
		)
		assert [s.name for s in parsed.sections] == [".text", ".data", ".rdata"]

	def test_section_flags_decoded(self):
		parsed = xbe_parse(
			build_minimal_xbe(
				sections=[
					(".text", SECTION_FLAG_EXECUTABLE, b"\x00"),
					(".data", SECTION_FLAG_WRITABLE, b"\x00"),
				]
			)
		)
		text, data_section = parsed.sections
		assert text.is_executable and not text.is_writable
		assert data_section.is_writable and not data_section.is_executable


class TestSectionLookup:
	def test_find_existing_section(self):
		parsed = xbe_parse(
			build_minimal_xbe(
				sections=[
					(".text", SECTION_FLAG_EXECUTABLE, b"\x90"),
					(".data", SECTION_FLAG_WRITABLE, b"\x01"),
				]
			)
		)
		text = xbe_section_find(parsed, ".text")
		assert text is not None and text.name == ".text"

	def test_find_missing_section_returns_none(self):
		parsed = xbe_parse(build_minimal_xbe(sections=[(".text", 0, b"\x90")]))
		assert xbe_section_find(parsed, ".nope") is None


class TestSectionRead:
	def test_section_bytes_round_trip(self):
		payload = b"hello there general kenobi"
		parsed = xbe_parse(
			build_minimal_xbe(sections=[(".text", SECTION_FLAG_EXECUTABLE, payload)])
		)
		section = xbe_section_find(parsed, ".text")
		assert xbe_section_read(parsed, section) == payload

	def test_section_bytes_for_each_of_multiple(self):
		sections = [
			(".text", SECTION_FLAG_EXECUTABLE, b"\xc3"),
			(".data", SECTION_FLAG_WRITABLE, b"\x42\x43"),
			(".rdata", 0, b"\xde\xad\xbe\xef"),
		]
		parsed = xbe_parse(build_minimal_xbe(sections=sections))
		for name, _, expected in sections:
			section = xbe_section_find(parsed, name)
			assert xbe_section_read(parsed, section) == expected, name

	def test_section_bytes_truncated_data_raises(self):
		payload = b"\xaa" * 32
		data = build_minimal_xbe(sections=[(".text", 0, payload)])
		parsed = xbe_parse(data)
		section = parsed.sections[0]
		truncated = dataclasses.replace(parsed, data=data[: section.raw_address + 4])
		with pytest.raises(XbeFormatError, match="truncated"):
			xbe_section_read(truncated, section)


class TestSectionContainingVa:
	def test_finds_section_at_start_address(self):
		parsed = xbe_parse(
			build_minimal_xbe(
				sections=[
					(".text", SECTION_FLAG_EXECUTABLE, b"\x90" * 16, 0x00011000),
				]
			)
		)
		section = xbe_section_containing_va(parsed, 0x00011000)
		assert section is not None and section.name == ".text"

	def test_finds_section_at_interior_address(self):
		parsed = xbe_parse(
			build_minimal_xbe(
				sections=[
					(".text", SECTION_FLAG_EXECUTABLE, b"\x90" * 16, 0x00011000),
				]
			)
		)
		section = xbe_section_containing_va(parsed, 0x00011008)
		assert section is not None and section.name == ".text"

	def test_address_at_section_end_is_outside(self):
		parsed = xbe_parse(
			build_minimal_xbe(
				sections=[
					(".text", SECTION_FLAG_EXECUTABLE, b"\x90" * 16, 0x00011000),
				]
			)
		)
		assert xbe_section_containing_va(parsed, 0x00011010) is None

	def test_distinguishes_between_sections(self):
		parsed = xbe_parse(
			build_minimal_xbe(
				sections=[
					(".text", SECTION_FLAG_EXECUTABLE, b"\x90" * 16, 0x00011000),
					(".data", SECTION_FLAG_WRITABLE, b"\x42" * 16, 0x00012000),
				]
			)
		)
		assert xbe_section_containing_va(parsed, 0x00011004).name == ".text"
		assert xbe_section_containing_va(parsed, 0x00012004).name == ".data"

	def test_address_outside_all_sections_returns_none(self):
		parsed = xbe_parse(
			build_minimal_xbe(
				sections=[
					(".text", SECTION_FLAG_EXECUTABLE, b"\x90" * 16, 0x00011000),
				]
			)
		)
		assert xbe_section_containing_va(parsed, 0x00099000) is None


class TestFunctionCarve:
	"""Carving extracts raw bytes from the file at a given VA + size.

	The contract: VA must be inside an executable section, and [VA, VA+size)
	must fit within the section's raw_size (BSS-style virtual padding past
	raw bytes is undefined for carving).
	"""

	def test_carves_function_bytes_at_section_start(self):
		text_bytes = (
			b"\x55\x8b\xec\x33\xc0\x5d\xc3"  # push ebp; mov ebp,esp; xor eax,eax; pop ebp; ret
		)
		parsed = xbe_parse(
			build_minimal_xbe(sections=[(".text", SECTION_FLAG_EXECUTABLE, text_bytes, 0x00011000)])
		)
		assert xbe_function_carve(parsed, 0x00011000, len(text_bytes)) == text_bytes

	def test_carves_function_bytes_at_interior_offset(self):
		prefix = b"\x90\x90\x90"
		function = b"\x55\x8b\xec\x5d\xc3"
		suffix = b"\xcc\xcc"
		parsed = xbe_parse(
			build_minimal_xbe(
				sections=[
					(".text", SECTION_FLAG_EXECUTABLE, prefix + function + suffix, 0x00011000)
				]
			)
		)
		assert xbe_function_carve(parsed, 0x00011000 + len(prefix), len(function)) == function

	def test_carve_up_to_section_end_is_allowed(self):
		text_bytes = b"\xc3" * 8
		parsed = xbe_parse(
			build_minimal_xbe(sections=[(".text", SECTION_FLAG_EXECUTABLE, text_bytes, 0x00011000)])
		)
		assert xbe_function_carve(parsed, 0x00011000, 8) == text_bytes

	def test_carve_past_raw_size_raises(self):
		text_bytes = b"\xc3" * 8
		parsed = xbe_parse(
			build_minimal_xbe(sections=[(".text", SECTION_FLAG_EXECUTABLE, text_bytes, 0x00011000)])
		)
		with pytest.raises(XbeFormatError, match="past"):
			xbe_function_carve(parsed, 0x00011000, 9)

	def test_carve_va_not_in_any_section_raises(self):
		parsed = xbe_parse(
			build_minimal_xbe(
				sections=[(".text", SECTION_FLAG_EXECUTABLE, b"\xc3" * 4, 0x00011000)]
			)
		)
		with pytest.raises(XbeFormatError, match="no section"):
			xbe_function_carve(parsed, 0x99999999, 4)

	def test_carve_in_non_executable_section_raises(self):
		parsed = xbe_parse(
			build_minimal_xbe(
				sections=[
					(".data", SECTION_FLAG_WRITABLE, b"\x42" * 16, 0x00012000),
				]
			)
		)
		with pytest.raises(XbeFormatError, match="executable"):
			xbe_function_carve(parsed, 0x00012000, 4)

	def test_carve_zero_size_raises(self):
		parsed = xbe_parse(
			build_minimal_xbe(
				sections=[(".text", SECTION_FLAG_EXECUTABLE, b"\xc3" * 4, 0x00011000)]
			)
		)
		with pytest.raises(ValueError, match="size"):
			xbe_function_carve(parsed, 0x00011000, 0)

	def test_carve_negative_size_raises(self):
		parsed = xbe_parse(
			build_minimal_xbe(
				sections=[(".text", SECTION_FLAG_EXECUTABLE, b"\xc3" * 4, 0x00011000)]
			)
		)
		with pytest.raises(ValueError, match="size"):
			xbe_function_carve(parsed, 0x00011000, -1)


class TestBuildFlavorDetect:
	"""Entry-point and kernel-thunk fields are XOR-encoded with DIFFERENT
	per-build keys; the EP and KT keys are paired by build flavor. We
	detect the flavor by trying each EP key against [base, base+size).
	"""

	BASE = 0x00010000
	IMAGE_SIZE = 0x00100000
	ENTRY_VA = 0x00012000

	def _xbe_with_entry(self, ep_key: int) -> bytes:
		return build_minimal_xbe(
			base_addr=self.BASE,
			size_of_image=self.IMAGE_SIZE,
			entry_point_xor=self.ENTRY_VA ^ ep_key,
		)

	def test_detects_retail_flavor(self):
		parsed = xbe_parse(self._xbe_with_entry(XBE_EP_KEY_RETAIL))
		assert xbe_build_flavor_detect(parsed).name == "retail"

	def test_detects_debug_flavor(self):
		parsed = xbe_parse(self._xbe_with_entry(XBE_EP_KEY_DEBUG))
		assert xbe_build_flavor_detect(parsed).name == "debug"

	def test_detects_chihiro_flavor(self):
		parsed = xbe_parse(self._xbe_with_entry(XBE_EP_KEY_CHIHIRO))
		assert xbe_build_flavor_detect(parsed).name == "chihiro"

	def test_no_matching_flavor_raises(self):
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=self.BASE,
				size_of_image=0x10,  # tiny image, no decoded value will fit
				entry_point_xor=0xDEADBEEF,
			)
		)
		with pytest.raises(XbeFormatError, match="build flavor"):
			xbe_build_flavor_detect(parsed)


class TestEntryPointDecode:
	def test_returns_decoded_va(self):
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=0x00010000,
				size_of_image=0x00100000,
				entry_point_xor=0x00012000 ^ XBE_EP_KEY_RETAIL,
			)
		)
		assert xbe_entry_point_get(parsed) == 0x00012000


class TestKernelThunkAddressDecode:
	def test_uses_paired_kt_key_for_debug_flavor(self):
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=0x00010000,
				size_of_image=0x00100000,
				entry_point_xor=0x00012000 ^ XBE_EP_KEY_DEBUG,
				kernel_thunk_address_xor=0x00013000 ^ XBE_KT_KEY_DEBUG,
			)
		)
		assert xbe_kernel_thunk_address_get(parsed) == 0x00013000

	def test_uses_paired_kt_key_for_chihiro_flavor(self):
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=0x00010000,
				size_of_image=0x00100000,
				entry_point_xor=0x00012000 ^ XBE_EP_KEY_CHIHIRO,
				kernel_thunk_address_xor=0x00013000 ^ XBE_KT_KEY_CHIHIRO,
			)
		)
		assert xbe_kernel_thunk_address_get(parsed) == 0x00013000

	def test_propagates_no_flavor_match(self):
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=0x00010000,
				size_of_image=0x10,
				entry_point_xor=0xDEADBEEF,
				kernel_thunk_address_xor=0xCAFEBABE,
			)
		)
		with pytest.raises(XbeFormatError, match="build flavor"):
			xbe_kernel_thunk_address_get(parsed)


class TestHalo2RetailRegression:
	"""Regression test pinned to real bytes from Halo 2 retail default.xbe.

	The raw header words at 0x128 and 0x158 are reproduced verbatim; the
	decoded VAs are documented (entry 0x002D0AEE per mbox/doc/xbe-format.md,
	thunk 0x00411520 which lands at the start of the .rdata section).
	"""

	def test_decodes_known_retail_entry_and_thunk(self):
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=0x00010000,
				size_of_image=0x005754C0,
				entry_point_xor=0xA8D15D45,
				kernel_thunk_address_xor=0x5B2C5596,
			)
		)
		assert xbe_build_flavor_detect(parsed).name == "retail"
		assert xbe_entry_point_get(parsed) == 0x002D0AEE
		assert xbe_kernel_thunk_address_get(parsed) == 0x00411520


# Building blocks for synthetic .text sections used by enumeration tests.
# Each leaf is a real x86-32 instruction stream that ends in `ret` (C3) or
# `ret imm16` (C2). Comments document the assembled bytes.

# push ebp; mov ebp, esp; pop ebp; ret   (6 bytes, stdcall-ish frame)
FN_FRAME_NOOP = b"\x55\x8b\xec\x5d\xc3"  # actually 5 bytes
# mov eax, 0; ret   (6 bytes, leaf returning 0)
FN_LEAF_RET0 = b"\xb8\x00\x00\x00\x00\xc3"
# push esi; mov esi, ecx; xor eax, eax; pop esi; ret 4   (8 bytes, stdcall@4)
FN_STDCALL = b"\x56\x8b\xf1\x33\xc0\x5e\xc2\x04\x00"  # 9 bytes
# Single ret, "skeleton" function (1 byte)
FN_RET_ONLY = b"\xc3"
# Two-ret function: test eax, eax; jz +2; ret; xor eax, eax; ret  (early return then real return)
FN_TWO_RETS = b"\x85\xc0\x74\x02\xc3\x33\xc0\xc3"  # 8 bytes; first ret at offset 4 not boundary


class TestEnumerateFunctions:
	def test_returns_empty_when_no_executable_sections(self):
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=0x00010000,
				size_of_image=0x00100000,
				sections=[(".data", SECTION_FLAG_WRITABLE, b"\x90" * 32, 0x00011000)],
			)
		)
		assert xbe_functions_enumerate(parsed) == ()

	def test_single_function_in_text_section(self):
		text = FN_LEAF_RET0  # 6 bytes
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=0x00010000,
				size_of_image=0x00100000,
				sections=[(".text", SECTION_FLAG_EXECUTABLE, text, 0x00011000)],
			)
		)
		fns = xbe_functions_enumerate(parsed)
		assert fns == (XbeFunction(name="fn_00011000", va=0x00011000, size=6),)

	def test_two_functions_separated_by_int3_padding(self):
		text = FN_LEAF_RET0 + b"\xcc\xcc\xcc" + FN_FRAME_NOOP
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=0x00010000,
				size_of_image=0x00100000,
				sections=[(".text", SECTION_FLAG_EXECUTABLE, text, 0x00011000)],
			)
		)
		fns = xbe_functions_enumerate(parsed)
		assert len(fns) == 2
		assert fns[0] == XbeFunction(name="fn_00011000", va=0x00011000, size=6)
		assert fns[1] == XbeFunction(name="fn_00011009", va=0x00011009, size=5)

	def test_nop_padding_between_functions(self):
		text = FN_LEAF_RET0 + b"\x90\x90" + FN_RET_ONLY
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=0x00010000,
				size_of_image=0x00100000,
				sections=[(".text", SECTION_FLAG_EXECUTABLE, text, 0x00011000)],
			)
		)
		fns = xbe_functions_enumerate(parsed)
		assert len(fns) == 2

	def test_stdcall_ret_imm16_recognized_as_boundary(self):
		text = FN_STDCALL + b"\xcc" + FN_LEAF_RET0
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=0x00010000,
				size_of_image=0x00100000,
				sections=[(".text", SECTION_FLAG_EXECUTABLE, text, 0x00011000)],
			)
		)
		fns = xbe_functions_enumerate(parsed)
		assert len(fns) == 2
		assert fns[0].size == 9  # FN_STDCALL is 9 bytes including ret 4

	def test_early_ret_inside_function_does_not_split(self):
		# FN_TWO_RETS has a `ret` mid-stream that's immediately followed by
		# another instruction (no padding). It must NOT split the function.
		text = FN_TWO_RETS + b"\xcc"  # trailing pad so the final ret is recognized
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=0x00010000,
				size_of_image=0x00100000,
				sections=[(".text", SECTION_FLAG_EXECUTABLE, text, 0x00011000)],
			)
		)
		fns = xbe_functions_enumerate(parsed)
		assert len(fns) == 1
		assert fns[0].size == 8  # whole FN_TWO_RETS

	def test_function_at_section_end_terminates_without_padding(self):
		# A `ret` immediately followed by section-end is still a boundary.
		text = FN_RET_ONLY  # one byte
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=0x00010000,
				size_of_image=0x00100000,
				sections=[(".text", SECTION_FLAG_EXECUTABLE, text, 0x00011000)],
			)
		)
		fns = xbe_functions_enumerate(parsed)
		assert fns == (XbeFunction(name="fn_00011000", va=0x00011000, size=1),)

	def test_skips_leading_padding(self):
		text = b"\xcc\xcc\xcc\xcc" + FN_LEAF_RET0
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=0x00010000,
				size_of_image=0x00100000,
				sections=[(".text", SECTION_FLAG_EXECUTABLE, text, 0x00011000)],
			)
		)
		fns = xbe_functions_enumerate(parsed)
		assert len(fns) == 1
		assert fns[0].va == 0x00011004

	def test_names_use_8_hex_digits_uppercase(self):
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=0x00010000,
				size_of_image=0x00100000,
				sections=[(".text", SECTION_FLAG_EXECUTABLE, FN_LEAF_RET0, 0x002D1D94)],
			)
		)
		fns = xbe_functions_enumerate(parsed)
		assert fns[0].name == "fn_002D1D94"

	def test_multi_section_enumeration(self):
		text1 = FN_LEAF_RET0
		text2 = FN_FRAME_NOOP
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=0x00010000,
				size_of_image=0x00100000,
				sections=[
					(".text", SECTION_FLAG_EXECUTABLE, text1, 0x00011000),
					(".text2", SECTION_FLAG_EXECUTABLE, text2, 0x00020000),
				],
			)
		)
		fns = xbe_functions_enumerate(parsed)
		names = {f.name for f in fns}
		assert names == {"fn_00011000", "fn_00020000"}

	def test_back_to_back_functions_split_on_prologue(self):
		# Two functions with NO padding between them. The first ends in `ret`
		# and the second immediately starts with `push ebp` (a prologue).
		# Without prologue detection these would be merged; with it, split.
		text = FN_LEAF_RET0 + FN_FRAME_NOOP + b"\xcc"
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=0x00010000,
				size_of_image=0x00100000,
				sections=[(".text", SECTION_FLAG_EXECUTABLE, text, 0x00011000)],
			)
		)
		fns = xbe_functions_enumerate(parsed)
		assert len(fns) == 2
		assert fns[0] == XbeFunction(name="fn_00011000", va=0x00011000, size=6)
		assert fns[1] == XbeFunction(name="fn_00011006", va=0x00011006, size=5)

	def test_back_to_back_split_when_target_of_internal_call(self):
		# Function A at 0x11000 makes a self-referential call to 0x11006
		# (where function B begins) and then rets. B starts with `mov eax,
		# 0` (NOT a recognized prologue). Without call-target tracking,
		# A's ret would not be a boundary and B would be merged in. With
		# it, 0x11006 being a known call target makes A's ret a boundary.
		#
		# call rel32 (E8 + 4-byte offset). For call at 0x11000:
		#   target = next_instr_addr + rel32 = 0x11005 + rel32
		#   want target = 0x11006, so rel32 = 1
		a = b"\xe8\x01\x00\x00\x00\xc3"  # call 0x11006; ret
		b = b"\xb8\x00\x00\x00\x00\xc3"  # mov eax, 0; ret
		text = a + b + b"\xcc"
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=0x00010000,
				size_of_image=0x00100000,
				sections=[(".text", SECTION_FLAG_EXECUTABLE, text, 0x00011000)],
			)
		)
		fns = xbe_functions_enumerate(parsed)
		assert len(fns) == 2
		assert fns[0] == XbeFunction(name="fn_00011000", va=0x00011000, size=6)
		assert fns[1] == XbeFunction(name="fn_00011006", va=0x00011006, size=6)

	def test_back_to_back_not_split_when_no_prologue(self):
		# Two consecutive `ret` instructions with no padding and no prologue
		# after. The first ret is not a boundary (treated as early return).
		text = b"\xc3\x90\x90" + FN_LEAF_RET0  # one early ret, then padding, then leaf
		# Actually: the early ret IS followed by padding (0x90), so it IS a
		# boundary. Construct a cleaner case: ret, then another non-prologue
		# instruction that itself ends in ret with padding.
		text = b"\xc3" + b"\x33\xc0\xc3" + b"\xcc"  # ret; xor eax,eax; ret; pad
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=0x00010000,
				size_of_image=0x00100000,
				sections=[(".text", SECTION_FLAG_EXECUTABLE, text, 0x00011000)],
			)
		)
		fns = xbe_functions_enumerate(parsed)
		# The first ret is not followed by padding or a prologue (`xor eax,
		# eax` is not in the prologue set), so it doesn't close the function.
		assert len(fns) == 1
		assert fns[0].size == 4
