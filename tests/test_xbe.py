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
from hypothesis import given
from hypothesis import strategies as st

from src.xbe import (
	SECTION_FLAG_EXECUTABLE,
	SECTION_FLAG_PRELOAD,
	SECTION_FLAG_WRITABLE,
	XBE_BUILD_FLAVORS,
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
	def test_header_fields_match_input_example(self):
		parsed = xbe_parse(build_minimal_xbe(base_addr=0x00020000))
		assert parsed.header.base_address == 0x00020000
		assert parsed.header.section_count == 0
		assert parsed.header.size_of_image_header == 0x178

	def test_bad_magic_raises_example(self):
		with pytest.raises(XbeFormatError, match="magic"):
			xbe_parse(b"NOPE" + b"\x00" * 1000)

	def test_truncated_header_raises_example(self):
		with pytest.raises(XbeFormatError, match="header"):
			xbe_parse(b"XBEH" + b"\x00" * 50)


class TestSectionEnumeration:
	# Zero/one/many section parsing (name, flags, sizes, order) is covered by
	# TestXbeParseRoundTrip. What stays pins the is_executable/is_writable flag
	# derivation the round-trip only asserts as a raw flags int.
	def test_section_flags_decoded_example(self):
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
	def test_find_existing_section_example(self):
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

	def test_find_missing_section_returns_none_example(self):
		parsed = xbe_parse(build_minimal_xbe(sections=[(".text", 0, b"\x90")]))
		assert xbe_section_find(parsed, ".nope") is None


class TestSectionRead:
	# Reading a section's bytes back is covered by TestXbeParseRoundTrip (which
	# asserts xbe_section_read == data for every generated section). What stays
	# pins the truncated-file error path the round-trip never builds.
	def test_section_bytes_truncated_data_raises_example(self):
		payload = b"\xaa" * 32
		data = build_minimal_xbe(sections=[(".text", 0, payload)])
		parsed = xbe_parse(data)
		section = parsed.sections[0]
		truncated = dataclasses.replace(parsed, data=data[: section.raw_address + 4])
		with pytest.raises(XbeFormatError, match="truncated"):
			xbe_section_read(truncated, section)


class TestSectionContainingVa:
	# Start/interior hits and the at-end miss are covered by
	# TestCarveProperties.test_containing_va_is_consistent_with_carve. What stays
	# pins multi-section disambiguation (the property uses a single section).
	def test_distinguishes_between_sections_example(self):
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


class TestFunctionCarve:
	"""Carving extracts raw bytes from the file at a given VA + size.

	The contract: VA must be inside an executable section, and [VA, VA+size)
	must fit within the section's raw_size (BSS-style virtual padding past
	raw bytes is undefined for carving).
	"""

	# Carving the exact bytes at a start/interior offset and up to the section
	# end is covered by TestCarveProperties.test_carve_returns_the_exact_subrange.
	# What stays pins the error paths the property never enters: past-raw-size,
	# VA-in-no-section, non-executable section, and non-positive size.
	def test_carve_past_raw_size_raises_example(self):
		text_bytes = b"\xc3" * 8
		parsed = xbe_parse(
			build_minimal_xbe(sections=[(".text", SECTION_FLAG_EXECUTABLE, text_bytes, 0x00011000)])
		)
		with pytest.raises(XbeFormatError, match="past"):
			xbe_function_carve(parsed, 0x00011000, 9)

	def test_carve_va_not_in_any_section_raises_example(self):
		parsed = xbe_parse(
			build_minimal_xbe(
				sections=[(".text", SECTION_FLAG_EXECUTABLE, b"\xc3" * 4, 0x00011000)]
			)
		)
		with pytest.raises(XbeFormatError, match="no section"):
			xbe_function_carve(parsed, 0x99999999, 4)

	def test_carve_in_non_executable_section_raises_example(self):
		parsed = xbe_parse(
			build_minimal_xbe(
				sections=[
					(".data", SECTION_FLAG_WRITABLE, b"\x42" * 16, 0x00012000),
				]
			)
		)
		with pytest.raises(XbeFormatError, match="executable"):
			xbe_function_carve(parsed, 0x00012000, 4)

	def test_carve_zero_size_raises_example(self):
		parsed = xbe_parse(
			build_minimal_xbe(
				sections=[(".text", SECTION_FLAG_EXECUTABLE, b"\xc3" * 4, 0x00011000)]
			)
		)
		with pytest.raises(ValueError, match="size"):
			xbe_function_carve(parsed, 0x00011000, 0)

	def test_carve_negative_size_raises_example(self):
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

	# Per-flavor detection (retail/debug/chihiro) and entry-point/thunk decoding
	# are covered by TestXorAddressInvertibility, which asserts detect picks the
	# encoding flavor and both getters hand back the encoded VAs. What stays pins
	# the no-flavor-matches error path (here and for the thunk getter below).
	def test_no_matching_flavor_raises_example(self):
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=0x00010000,
				size_of_image=0x10,  # tiny image, no decoded value will fit
				entry_point_xor=0xDEADBEEF,
			)
		)
		with pytest.raises(XbeFormatError, match="build flavor"):
			xbe_build_flavor_detect(parsed)


class TestKernelThunkAddressDecode:
	def test_propagates_no_flavor_match_example(self):
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

	def test_decodes_known_retail_entry_and_thunk_example(self):
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

	def test_tail_jmp_predecessor_splits_at_call_target(self):
		# Function A ends in a tail call (`jmp eax`) — never a `ret` — so the old
		# enumerator merged the following function B into it. B is a direct call
		# target, so it cannot lie inside A: reaching B's VA must split.
		#   A: call 0x11007 ; jmp eax        (7 bytes, ends in jmp not ret)
		#   B: mov eax, 0 ; ret              (6 bytes)
		a = b"\xe8\x02\x00\x00\x00\xff\xe0"  # call 0x11007 (rel32=2); jmp eax
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
		assert fns == (
			XbeFunction(name="fn_00011000", va=0x00011000, size=7),
			XbeFunction(name="fn_00011007", va=0x00011007, size=6),
		)

	def test_noreturn_call_then_int3_then_prologue_splits(self):
		# Function A ends in a `call` (e.g. to a noreturn) with no trailing `ret`,
		# then int3 padding, then function B opens with a `push ebp` prologue.
		# The int3 run leading into a prologue must close A.
		a = b"\xe8\xfb\xff\xff\xff"  # call 0x11000 (back-edge, A's own start)
		pad = b"\xcc\xcc"
		b = b"\x55\x8b\xec\x5d\xc3"  # push ebp; mov ebp,esp; pop ebp; ret
		text = a + pad + b + b"\xcc"
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=0x00010000,
				size_of_image=0x00100000,
				sections=[(".text", SECTION_FLAG_EXECUTABLE, text, 0x00011000)],
			)
		)
		fns = xbe_functions_enumerate(parsed)
		assert fns == (
			XbeFunction(name="fn_00011000", va=0x00011000, size=5),
			XbeFunction(name="fn_00011007", va=0x00011007, size=5),
		)

	def test_int3_run_splits_before_non_prologue_entry(self):
		# A run of 2+ int3 is reliable inter-function padding even when the next
		# function's entry isn't a recognized prologue (here a `push imm32`
		# registration thunk). Without this, runs of such thunks merge into one.
		#   A: xor eax,eax ; jmp eax       (4 bytes, ends in jmp not ret)
		#   <int3 int3 int3>
		#   B: push 0x12345678 ; ret       (6 bytes, non-prologue entry)
		a = b"\x33\xc0\xff\xe0"  # xor eax,eax; jmp eax
		pad = b"\xcc\xcc\xcc"
		b = b"\x68\x78\x56\x34\x12\xc3"  # push 0x12345678; ret
		text = a + pad + b + b"\xcc"
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=0x00010000,
				size_of_image=0x00100000,
				sections=[(".text", SECTION_FLAG_EXECUTABLE, text, 0x00011000)],
			)
		)
		fns = xbe_functions_enumerate(parsed)
		assert fns == (
			XbeFunction(name="fn_00011000", va=0x00011000, size=4),
			XbeFunction(name="fn_00011007", va=0x00011007, size=6),
		)

	def test_nop_alignment_inside_function_not_split(self):
		# A `nop` run is intra-function alignment, not a separator. A function
		# with mid-body nop padding followed by non-prologue code must NOT split.
		#   xor eax,eax ; nop ; nop ; inc eax ; ret
		text = b"\x33\xc0" + b"\x90\x90" + b"\x40" + b"\xc3" + b"\xcc"
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=0x00010000,
				size_of_image=0x00100000,
				sections=[(".text", SECTION_FLAG_EXECUTABLE, text, 0x00011000)],
			)
		)
		fns = xbe_functions_enumerate(parsed)
		assert fns == (XbeFunction(name="fn_00011000", va=0x00011000, size=6),)

	def test_int3_debugbreak_inside_function_not_split(self):
		# A lone int3 (`__debugbreak`) followed by ordinary code (not a prologue
		# or call target) is intra-function — it must NOT split the function.
		#   xor eax,eax ; int3 ; inc eax ; ret
		text = b"\x33\xc0" + b"\xcc" + b"\x40" + b"\xc3" + b"\xcc"
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=0x00010000,
				size_of_image=0x00100000,
				sections=[(".text", SECTION_FLAG_EXECUTABLE, text, 0x00011000)],
			)
		)
		fns = xbe_functions_enumerate(parsed)
		assert fns == (XbeFunction(name="fn_00011000", va=0x00011000, size=5),)

	def test_back_to_back_not_split_when_no_prologue(self):
		# ret; xor eax,eax; ret; pad. The first ret is followed by a non-prologue
		# instruction (`xor eax,eax`), not padding or a prologue, so it does not
		# close the function — the whole run stays one function.
		text = b"\xc3" + b"\x33\xc0\xc3" + b"\xcc"
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


# --- Property tests --------------------------------------------------------
# The hand-built XBEs above each pin one shape; these assert the laws those
# witnesses instance: parse inverts the byte-level writer, the XOR address
# scrambling is invertible per build flavor, and carve returns the exact
# sub-range of a section's bytes.

_FLAGS = st.sampled_from(
	[
		0,
		SECTION_FLAG_EXECUTABLE,
		SECTION_FLAG_WRITABLE,
		SECTION_FLAG_EXECUTABLE | SECTION_FLAG_WRITABLE,
		SECTION_FLAG_PRELOAD | SECTION_FLAG_EXECUTABLE,
	]
)
_SECTION_NAME = st.sampled_from([".text", ".data", ".rdata", "XONLINE", "DSOUND", "$$XTIMAGE"])


_xbe_section = st.tuples(
	_SECTION_NAME,
	_FLAGS,
	st.binary(max_size=32),
	st.integers(min_value=0x1000, max_value=0x00FF_0000),
)
_xbe_section_list = st.lists(_xbe_section, max_size=4)


class TestXbeParseRoundTrip:
	@given(
		base=st.integers(min_value=0x10000, max_value=0x40_0000),
		size=st.integers(min_value=0, max_value=0x100_0000),
		sections=_xbe_section_list,
	)
	def test_parse_recovers_header_and_section_fields(self, base, size, sections):
		parsed = xbe_parse(build_minimal_xbe(base_addr=base, size_of_image=size, sections=sections))
		assert parsed.header.base_address == base
		assert parsed.header.size_of_image == size
		assert len(parsed.sections) == len(sections)
		for (name, flags, data, va), sec in zip(sections, parsed.sections, strict=True):
			assert sec.name == name
			assert sec.flags == flags
			assert sec.virtual_address == va
			assert sec.virtual_size == len(data)
			assert sec.raw_size == len(data)
			assert xbe_section_read(parsed, sec) == data  # raw bytes survive the trip


class TestXorAddressInvertibility:
	# entry_point_xor / kernel_thunk_address_xor are the VA XOR a per-flavor key;
	# detect picks the flavor whose decoded entry point lands in the image, and
	# the getters must hand back exactly the VAs that were encoded.
	@given(
		flavor=st.sampled_from(list(XBE_BUILD_FLAVORS)),
		ep_offset=st.integers(min_value=0, max_value=0xF_FFFF),
		thunk_va=st.integers(min_value=0, max_value=2**32 - 1),
	)
	def test_entry_point_and_thunk_decode_to_the_encoded_vas(self, flavor, ep_offset, thunk_va):
		base, size = 0x00010000, 0x00100000
		entry_va = base + ep_offset  # guaranteed inside [base, base + size)
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=base,
				size_of_image=size,
				entry_point_xor=entry_va ^ flavor.ep_key,
				kernel_thunk_address_xor=thunk_va ^ flavor.kt_key,
				sections=[(".text", SECTION_FLAG_EXECUTABLE, b"\x90", 0x00011000)],
			)
		)
		assert xbe_build_flavor_detect(parsed).name == flavor.name
		assert xbe_entry_point_get(parsed) == entry_va
		assert xbe_kernel_thunk_address_get(parsed) == thunk_va


@st.composite
def _carve_case(draw):
	data = draw(st.binary(min_size=1, max_size=64))
	offset = draw(st.integers(min_value=0, max_value=len(data) - 1))
	size = draw(st.integers(min_value=1, max_value=len(data) - offset))
	return data, offset, size


class TestCarveProperties:
	SECTION_VA = 0x00020000

	@given(case=_carve_case())
	def test_carve_returns_the_exact_subrange(self, case):
		data, offset, size = case
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=0x00010000,
				size_of_image=0x00100000,
				sections=[(".text", SECTION_FLAG_EXECUTABLE, data, self.SECTION_VA)],
			)
		)
		carved = xbe_function_carve(parsed, self.SECTION_VA + offset, size)
		assert carved == data[offset : offset + size]

	@given(case=_carve_case())
	def test_containing_va_is_consistent_with_carve(self, case):
		data, offset, _size = case
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=0x00010000,
				size_of_image=0x00100000,
				sections=[(".text", SECTION_FLAG_EXECUTABLE, data, self.SECTION_VA)],
			)
		)
		# Any VA inside the section resolves to it; one past the end does not.
		assert xbe_section_containing_va(parsed, self.SECTION_VA + offset).name == ".text"
		assert xbe_section_containing_va(parsed, self.SECTION_VA + len(data)) is None
