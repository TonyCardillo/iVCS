"""Tests for static relocation discovery in carved function bytes.

The discover pass finds REL32 imm operands whose target lives outside the
function. The resolve pass maps each target VA to a symbol name (kernel
import / sub_ / data_) so slice 4 can emit COFF external symbols.
"""

import struct

from src.relocs import (
	RelocKind,
	RelocSite,
	ResolvedReloc,
	convention_from_bytes,
	reloc_symbol_name,
	relocs_discover,
	relocs_resolve,
)
from src.xbe import (
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
	def test_call_outside_function_yields_one_reloc(self):
		fn_va = 0x00011000
		body = call_rel32(fn_va, 0x00020000) + b"\xc3"
		assert relocs_discover(body, fn_va) == [
			RelocSite(imm_offset=1, kind=RelocKind.REL32, target_va=0x00020000)
		]

	def test_call_inside_function_yields_no_reloc(self):
		fn_va = 0x00011000
		body = call_rel32(fn_va, fn_va + 10) + b"\x90" * 10 + b"\xc3"
		assert relocs_discover(body, fn_va) == []

	def test_jmp_rel32_outside_yields_one_reloc(self):
		fn_va = 0x00011000
		body = jmp_rel32(fn_va, 0x00030000)
		assert relocs_discover(body, fn_va) == [
			RelocSite(imm_offset=1, kind=RelocKind.REL32, target_va=0x00030000)
		]

	def test_je_rel32_outside_yields_one_reloc(self):
		fn_va = 0x00011000
		body = je_rel32(fn_va, 0x00040000)
		assert relocs_discover(body, fn_va) == [
			RelocSite(imm_offset=2, kind=RelocKind.REL32, target_va=0x00040000)
		]

	def test_je_rel8_short_yields_no_reloc(self):
		# 0x74 0x02 = je +2 (rel8). Always 2 bytes — no rel32 target.
		body = b"\x74\x02" + b"\x90" * 4 + b"\xc3"
		assert relocs_discover(body, 0x00011000) == []

	def test_jmp_rel8_short_yields_no_reloc(self):
		# 0xEB 0x02 = jmp +2 (rel8).
		body = b"\xeb\x02" + b"\x90" * 4 + b"\xc3"
		assert relocs_discover(body, 0x00011000) == []

	def test_no_branches_yields_no_relocs(self):
		# mov eax, ebx; ret
		assert relocs_discover(b"\x89\xd8\xc3", 0x00011000) == []

	def test_empty_bytes_yields_no_relocs(self):
		assert relocs_discover(b"", 0x00011000) == []

	def test_multiple_externals_preserve_order(self):
		fn_va = 0x00011000
		body = call_rel32(fn_va, 0x00020000) + call_rel32(fn_va + 5, 0x00030000) + b"\xc3"
		sites = relocs_discover(body, fn_va)
		assert [s.target_va for s in sites] == [0x00020000, 0x00030000]
		assert [s.imm_offset for s in sites] == [1, 6]

	def test_mixed_internal_and_external_keeps_only_externals(self):
		fn_va = 0x00011000
		body = (
			call_rel32(fn_va, 0x00020000)  # external — kept
			+ call_rel32(fn_va + 5, fn_va + 10)  # internal — dropped
			+ b"\xc3"
		)
		sites = relocs_discover(body, fn_va)
		assert len(sites) == 1
		assert sites[0].target_va == 0x00020000


def _rel32_site(target_va: int) -> RelocSite:
	return RelocSite(imm_offset=0, kind=RelocKind.REL32, target_va=target_va)


class TestConventionFromBytes:
	def test_cdecl_when_first_ret_has_no_immediate(self):
		body = b"\xb8\x00\x00\x00\x00\xc3"  # mov eax, 0; ret
		assert convention_from_bytes(body) == ("cdecl", 0)

	def test_stdcall_with_byte_count(self):
		body = b"\xc2\x08\x00"  # ret 8
		assert convention_from_bytes(body) == ("stdcall", 8)

	def test_stdcall_with_one_arg(self):
		body = b"\x56\x8b\xf1\x5e\xc2\x04\x00"  # ret 4
		assert convention_from_bytes(body) == ("stdcall", 4)

	def test_no_ret_falls_back_to_cdecl(self):
		body = b"\x00" * 8
		assert convention_from_bytes(body) == ("cdecl", 0)

	def test_first_ret_wins(self):
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
	def test_ff15_call_indirect_yields_one_dir32(self):
		fn_va = 0x00011000
		body = ff15_call_indirect(0x00411520) + b"\xc3"
		assert relocs_discover(body, fn_va) == [
			RelocSite(imm_offset=2, kind=RelocKind.DIR32, target_va=0x00411520)
		]

	def test_ff25_jmp_indirect_yields_one_dir32(self):
		fn_va = 0x00011000
		body = ff25_jmp_indirect(0x00411520)
		assert relocs_discover(body, fn_va) == [
			RelocSite(imm_offset=2, kind=RelocKind.DIR32, target_va=0x00411520)
		]

	def test_ff_d0_register_indirect_call_yields_no_reloc(self):
		# call eax — register-indirect, no memory operand
		body = b"\xff\xd0\xc3"
		assert relocs_discover(body, 0x00011000) == []

	def test_call_through_register_with_disp_yields_no_reloc(self):
		# call [eax + 0x10] — base + disp, not absolute disp32
		body = b"\xff\x50\x10\xc3"
		assert relocs_discover(body, 0x00011000) == []

	def test_mixed_rel32_and_dir32_both_discovered(self):
		fn_va = 0x00011000
		body = call_rel32(fn_va, 0x00020000) + ff15_call_indirect(0x00411520) + b"\xc3"
		sites = relocs_discover(body, fn_va)
		assert sites == [
			RelocSite(imm_offset=1, kind=RelocKind.REL32, target_va=0x00020000),
			RelocSite(imm_offset=7, kind=RelocKind.DIR32, target_va=0x00411520),
		]


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
