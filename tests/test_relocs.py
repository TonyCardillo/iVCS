"""Tests for static relocation discovery in carved function bytes.

The discover pass finds REL32 imm operands whose target lives outside the
function. The resolve pass maps each target VA to a symbol name (kernel
import / sub_ / data_) so slice 4 can emit COFF external symbols.
"""

import struct

from hypothesis import given
from hypothesis import strategies as st

from src.formats.relocs import (
	RelocKind,
	RelocSite,
	ResolvedReloc,
	convention_from_bytes,
	reloc_symbol_name,
	relocs_discover,
	relocs_kernel_import_va_map,
	relocs_resolve,
)
from src.formats.xbe import (
	SECTION_FLAG_EXECUTABLE,
	SECTION_FLAG_WRITABLE,
	XBE_EP_KEY_RETAIL,
	XBE_KT_KEY_RETAIL,
	xbe_parse,
)
from tests.test_xbe import build_minimal_xbe


def call_rel32(at_va: int, target_va: int) -> bytes:
	rel = (target_va - at_va - 5) & 0xFFFFFFFF
	return b"\xe8" + rel.to_bytes(4, "little")


def jmp_rel32(at_va: int, target_va: int) -> bytes:
	rel = (target_va - at_va - 5) & 0xFFFFFFFF
	return b"\xe9" + rel.to_bytes(4, "little")


def je_rel32(at_va: int, target_va: int) -> bytes:
	rel = (target_va - at_va - 6) & 0xFFFFFFFF
	return b"\x0f\x84" + rel.to_bytes(4, "little")


class TestRelocsDiscoverRel32:
	# The positive REL32 cases (call/jmp/je outside, multi-external order, mixed
	# internal/external) are covered by TestRelocsDiscoverProperties. What stays
	# pins decode paths the property never emits: short rel8 branches, a bare
	# `mov`, and empty input — all of which must yield no relocs.
	def test_je_rel8_short_yields_no_reloc_example(self):
		# 0x74 0x02 = je +2 (rel8). Always 2 bytes — no rel32 target.
		body = b"\x74\x02" + b"\x90" * 4 + b"\xc3"
		assert relocs_discover(body, 0x00011000) == []

	def test_jmp_rel8_short_yields_no_reloc_example(self):
		# 0xEB 0x02 = jmp +2 (rel8).
		body = b"\xeb\x02" + b"\x90" * 4 + b"\xc3"
		assert relocs_discover(body, 0x00011000) == []

	def test_no_branches_yields_no_relocs_example(self):
		# mov eax, ebx; ret
		assert relocs_discover(b"\x89\xd8\xc3", 0x00011000) == []

	def test_empty_bytes_yields_no_relocs_example(self):
		assert relocs_discover(b"", 0x00011000) == []


def _rel32_site(target_va: int) -> RelocSite:
	return RelocSite(imm_offset=0, kind=RelocKind.REL32, target_va=target_va)


class TestConventionFromBytes:
	# `ret imm16 → stdcall N` (with leading padding) is covered by
	# TestConventionProperties. What stays pins the cdecl branches the property
	# never exercises: a bare `ret`, no ret at all, a realistic prologue before
	# `ret 4`, and first-ret-wins.
	def test_cdecl_when_first_ret_has_no_immediate_example(self):
		body = b"\xb8\x00\x00\x00\x00\xc3"  # mov eax, 0; ret
		assert convention_from_bytes(body) == ("cdecl", 0)

	def test_stdcall_with_one_arg_example(self):
		body = b"\x56\x8b\xf1\x5e\xc2\x04\x00"  # push esi; mov esi,ecx; pop esi; ret 4
		assert convention_from_bytes(body) == ("stdcall", 4)

	def test_no_ret_falls_back_to_cdecl_example(self):
		body = b"\x00" * 8
		assert convention_from_bytes(body) == ("cdecl", 0)

	def test_first_ret_wins_example(self):
		# ret (c3) then later ret 8 — first wins.
		body = b"\xc3\xc2\x08\x00"
		assert convention_from_bytes(body) == ("cdecl", 0)


class TestRelocSymbolNameRel32:
	BASE = 0x00010000
	IMAGE_SIZE = 0x00100000

	def test_target_in_executable_section_is_fn_prefix(self):
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=self.BASE,
				size_of_image=self.IMAGE_SIZE,
				sections=[(".text", SECTION_FLAG_EXECUTABLE, b"\x90" * 16, 0x00011000)],
			)
		)
		assert reloc_symbol_name(_rel32_site(0x00011008), parsed) == "_fn_00011008"

	def test_stdcall_callee_gets_at_n_decoration(self):
		# Callee whose first ret is `ret 8` (C2 08 00) is __stdcall; the symbol
		# must carry @8 so target.obj matches the ctx.h-declared call site.
		text = b"\x90" * 8 + b"\xc2\x08\x00" + b"\x90" * 5
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=self.BASE,
				size_of_image=self.IMAGE_SIZE,
				sections=[(".text", SECTION_FLAG_EXECUTABLE, text, 0x00011000)],
			)
		)
		assert reloc_symbol_name(_rel32_site(0x00011008), parsed) == "_fn_00011008@8"

	def test_cdecl_callee_with_plain_ret_has_no_decoration(self):
		# A plain `ret` (C3) is cdecl — no @N suffix.
		text = b"\xc3" + b"\x90" * 15
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=self.BASE,
				size_of_image=self.IMAGE_SIZE,
				sections=[(".text", SECTION_FLAG_EXECUTABLE, text, 0x00011000)],
			)
		)
		assert reloc_symbol_name(_rel32_site(0x00011000), parsed) == "_fn_00011000"

	def test_target_in_non_executable_section_is_data_prefix(self):
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=self.BASE,
				size_of_image=self.IMAGE_SIZE,
				sections=[(".data", SECTION_FLAG_WRITABLE, b"\x00" * 16, 0x00012000)],
			)
		)
		assert reloc_symbol_name(_rel32_site(0x00012008), parsed) == "_data_00012008"

	def test_target_outside_any_section_is_data_prefix(self):
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=self.BASE,
				size_of_image=self.IMAGE_SIZE,
				sections=[(".text", SECTION_FLAG_EXECUTABLE, b"\x90", 0x00011000)],
			)
		)
		assert reloc_symbol_name(_rel32_site(0x000FFFFF), parsed) == "_data_000FFFFF"

	def test_rel32_to_kernel_thunk_slot_does_not_resolve_to_imp_name(self):
		# REL32 hitting a thunk slot is semantic nonsense (call rel32 from .text
		# to a non-executable .rdata location) — should fall through to data_*.
		thunk_va = 0x00012000
		ordinal = 187
		thunk_bytes = struct.pack("<I", ordinal | 0x80000000) + struct.pack("<I", 0)
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=self.BASE,
				size_of_image=self.IMAGE_SIZE,
				entry_point_xor=0x00011000 ^ XBE_EP_KEY_RETAIL,
				kernel_thunk_address_xor=thunk_va ^ XBE_KT_KEY_RETAIL,
				sections=[
					(".text", SECTION_FLAG_EXECUTABLE, b"\x90", 0x00011000),
					(".XBLD", SECTION_FLAG_WRITABLE, thunk_bytes, thunk_va),
				],
			)
		)
		assert reloc_symbol_name(_rel32_site(thunk_va), parsed) == f"_data_{thunk_va:08X}"


def ff15_call_indirect(target_va: int) -> bytes:
	return b"\xff\x15" + target_va.to_bytes(4, "little")


def ff25_jmp_indirect(target_va: int) -> bytes:
	return b"\xff\x25" + target_va.to_bytes(4, "little")


class TestRelocsDiscoverDir32:
	# The positive DIR32 cases (ff15/ff25 indirect, mixed with rel32) are covered
	# by TestRelocsDiscoverProperties. What stays pins the non-absolute indirect
	# forms the property never emits: register-indirect and base+disp.
	def test_ff_d0_register_indirect_call_yields_no_reloc_example(self):
		# call eax — register-indirect, no memory operand
		body = b"\xff\xd0\xc3"
		assert relocs_discover(body, 0x00011000) == []

	def test_call_through_register_with_disp_yields_no_reloc_example(self):
		# call [eax + 0x10] — base + disp, not absolute disp32
		body = b"\xff\x50\x10\xc3"
		assert relocs_discover(body, 0x00011000) == []


class TestRelocSymbolNameDir32:
	BASE = 0x00010000
	IMAGE_SIZE = 0x00100000

	def test_dir32_to_thunk_slot_when_rdata_is_marked_executable(self):
		# Halo 2 retail has flags=0x6 on .rdata (PRELOAD|EXECUTABLE). The
		# resolver must not gate kernel-import lookups on section.is_executable.
		thunk_va = 0x00012000
		ordinal = 187
		thunk_bytes = struct.pack("<I", ordinal | 0x80000000) + struct.pack("<I", 0)
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=self.BASE,
				size_of_image=self.IMAGE_SIZE,
				entry_point_xor=0x00011000 ^ XBE_EP_KEY_RETAIL,
				kernel_thunk_address_xor=thunk_va ^ XBE_KT_KEY_RETAIL,
				sections=[
					(".text", SECTION_FLAG_EXECUTABLE, b"\x90", 0x00011000),
					(".rdata", SECTION_FLAG_EXECUTABLE, thunk_bytes, thunk_va),
				],
			)
		)
		site = RelocSite(imm_offset=2, kind=RelocKind.DIR32, target_va=thunk_va)
		assert reloc_symbol_name(site, parsed) == "__imp__NtClose@4"

	def test_dir32_to_slot_without_ordinal_flag_falls_back_to_data(self):
		# An entry without IMAGE_ORDINAL_FLAG32 high bit isn't a kernel
		# thunk slot — it's some other rdata. Must not be misidentified.
		thunk_va = 0x00012000
		slot_va = thunk_va + 8  # past the table proper
		rdata_bytes = (
			struct.pack("<I", 187 | 0x80000000)  # real thunk slot
			+ struct.pack("<I", 0)  # terminator
			+ struct.pack("<I", 187)  # spurious — high bit NOT set
		)
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=self.BASE,
				size_of_image=self.IMAGE_SIZE,
				entry_point_xor=0x00011000 ^ XBE_EP_KEY_RETAIL,
				kernel_thunk_address_xor=thunk_va ^ XBE_KT_KEY_RETAIL,
				sections=[
					(".text", SECTION_FLAG_EXECUTABLE, b"\x90", 0x00011000),
					(".rdata", SECTION_FLAG_WRITABLE, rdata_bytes, thunk_va),
				],
			)
		)
		site = RelocSite(imm_offset=2, kind=RelocKind.DIR32, target_va=slot_va)
		assert reloc_symbol_name(site, parsed) == f"_data_{slot_va:08X}"

	def test_dir32_to_kernel_thunk_slot_yields_imp_prefixed_decorated_name(self):
		thunk_va = 0x00012000
		ordinal = 187  # NtClose, mangled = "NtClose@4"
		thunk_bytes = struct.pack("<I", ordinal | 0x80000000) + struct.pack("<I", 0)
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=self.BASE,
				size_of_image=self.IMAGE_SIZE,
				entry_point_xor=0x00011000 ^ XBE_EP_KEY_RETAIL,
				kernel_thunk_address_xor=thunk_va ^ XBE_KT_KEY_RETAIL,
				sections=[
					(".text", SECTION_FLAG_EXECUTABLE, b"\x90", 0x00011000),
					(".XBLD", SECTION_FLAG_WRITABLE, thunk_bytes, thunk_va),
				],
			)
		)
		site = RelocSite(imm_offset=2, kind=RelocKind.DIR32, target_va=thunk_va)
		assert reloc_symbol_name(site, parsed) == "__imp__NtClose@4"

	def test_dir32_outside_kernel_thunk_falls_back_to_data_prefix(self):
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=self.BASE,
				size_of_image=self.IMAGE_SIZE,
				sections=[(".data", SECTION_FLAG_WRITABLE, b"\x00" * 16, 0x00012000)],
			)
		)
		site = RelocSite(imm_offset=0, kind=RelocKind.DIR32, target_va=0x00012008)
		assert reloc_symbol_name(site, parsed) == "_data_00012008"


class TestRelocsResolveCombines:
	def test_returns_one_resolved_reloc_per_discovered_site(self):
		fn_va = 0x00011000
		body = call_rel32(fn_va, 0x00012000) + b"\xc3"
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=0x00010000,
				size_of_image=0x00100000,
				sections=[
					(".text", SECTION_FLAG_EXECUTABLE, body + b"\x90" * 16, 0x00011000),
					(".other", SECTION_FLAG_EXECUTABLE, b"\xc3", 0x00012000),
				],
			)
		)
		resolved = relocs_resolve(body, fn_va, parsed)
		assert resolved == [
			ResolvedReloc(
				site=RelocSite(imm_offset=1, kind=RelocKind.REL32, target_va=0x00012000),
				symbol_name="_fn_00012000",
			)
		]


class TestKernelImportVaMap:
	BASE = 0x00010000
	IMAGE_SIZE = 0x00100000

	def test_maps_decorated_name_to_slot_va(self):
		thunk_va = 0x00012000
		# Two ordinals then a null terminator: 187=NtClose@4,
		# 184=NtAllocateVirtualMemory@20.
		thunk_bytes = (
			struct.pack("<I", 187 | 0x80000000)
			+ struct.pack("<I", 184 | 0x80000000)
			+ struct.pack("<I", 0)
		)
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=self.BASE,
				size_of_image=self.IMAGE_SIZE,
				entry_point_xor=0x00011000 ^ XBE_EP_KEY_RETAIL,
				kernel_thunk_address_xor=thunk_va ^ XBE_KT_KEY_RETAIL,
				sections=[
					(".text", SECTION_FLAG_EXECUTABLE, b"\x90", 0x00011000),
					(".rdata", SECTION_FLAG_EXECUTABLE, thunk_bytes, thunk_va),
				],
			)
		)
		va_map = relocs_kernel_import_va_map(parsed)
		assert va_map["NtClose@4"] == thunk_va
		assert va_map["NtAllocateVirtualMemory@20"] == thunk_va + 4

	def test_stops_at_null_terminator(self):
		thunk_va = 0x00012000
		thunk_bytes = (
			struct.pack("<I", 187 | 0x80000000)
			+ struct.pack("<I", 0)  # terminator
			+ struct.pack("<I", 184 | 0x80000000)  # past the table — must be ignored
		)
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=self.BASE,
				size_of_image=self.IMAGE_SIZE,
				entry_point_xor=0x00011000 ^ XBE_EP_KEY_RETAIL,
				kernel_thunk_address_xor=thunk_va ^ XBE_KT_KEY_RETAIL,
				sections=[
					(".text", SECTION_FLAG_EXECUTABLE, b"\x90", 0x00011000),
					(".rdata", SECTION_FLAG_EXECUTABLE, thunk_bytes, thunk_va),
				],
			)
		)
		va_map = relocs_kernel_import_va_map(parsed)
		assert va_map == {"NtClose@4": thunk_va}


# --- Property tests --------------------------------------------------------
# The single-instruction examples above each pin one branch shape; this builds
# arbitrary mixed programs and asserts the discovery law they witness: every
# DIR32 indirect branch and every *external* REL32 branch becomes a site, in
# instruction order, with the right offset/kind/target — and internal REL32
# branches never do.

_FN_VA = 0x00400000
_EXT_BASE = 0x00410000  # 64 KiB past _FN_VA — always outside any body we build


@st.composite
def _branch_program(draw):
	specs = draw(
		st.lists(
			st.tuples(
				st.sampled_from(["rel_call", "rel_jmp", "rel_je", "dir_call", "dir_jmp"]),
				st.booleans(),  # REL32 only: target external? (DIR32 has no internal filter)
			),
			max_size=8,
		)
	)
	body = b""
	expected: list[RelocSite] = []
	ext = 0
	for kind, external in specs:
		at = _FN_VA + len(body)
		is_rel = kind.startswith("rel")
		internal = is_rel and not external
		if internal:
			target = _FN_VA  # inside [fn_va, fn_end) → dropped by discover
		else:
			target = _EXT_BASE + ext * 0x100
			ext += 1
		if kind == "rel_call":
			enc, off, rk = call_rel32(at, target), len(body) + 1, RelocKind.REL32
		elif kind == "rel_jmp":
			enc, off, rk = jmp_rel32(at, target), len(body) + 1, RelocKind.REL32
		elif kind == "rel_je":
			enc, off, rk = je_rel32(at, target), len(body) + 2, RelocKind.REL32
		elif kind == "dir_call":
			enc, off, rk = ff15_call_indirect(target), len(body) + 2, RelocKind.DIR32
		else:
			enc, off, rk = ff25_jmp_indirect(target), len(body) + 2, RelocKind.DIR32
		if not internal:
			expected.append(RelocSite(imm_offset=off, kind=rk, target_va=target))
		body += enc
	return body + b"\xc3", expected


class TestRelocsDiscoverProperties:
	@given(program=_branch_program())
	def test_discover_recovers_exactly_external_branches_in_order(self, program):
		body, expected = program
		assert relocs_discover(body, _FN_VA) == expected


class TestConventionProperties:
	@given(n=st.integers(0, 0xFFFF), nops=st.integers(0, 6))
	def test_ret_imm16_is_stdcall_with_byte_count(self, n, nops):
		# Leading nops (anything before the first ret) don't change the verdict;
		# `ret imm16` reports stdcall with exactly that popped byte count.
		body = b"\x90" * nops + b"\xc2" + n.to_bytes(2, "little")
		assert convention_from_bytes(body) == ("stdcall", n)
