"""Discover relocation sites in a carved function's raw bytes.

A reloc site = the byte offset of an imm32 operand whose target lives
outside the function. The COFF emitter consumes these to produce external
symbol references.

Supported kinds:
  - REL32: call/jmp/jcc rel32 (E8/E9/0F 8x + imm32)
  - DIR32: call/jmp dword ptr [disp32] (FF 15 / FF 25 + imm32)

DIR32 sites that target a kernel thunk-table slot resolve to the
`__imp__<mangled>` symbol — matching what MSVC emits for
`__declspec(dllimport) __stdcall` calls. Other DIR32 sites fall back to
`data_*` / `sub_*` like REL32 does.

Out of MVP scope: absolute-address operands on mov/push/lea
(IMAGE_REL_I386_DIR32 against non-call instructions).
"""

import re
import struct
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

import capstone
import capstone.x86

from src.xbe import (
	ParsedXbe,
	XbeFormatError,
	xbe_function_carve,
	xbe_kernel_thunk_address_get,
	xbe_section_containing_va,
)
from src.xboxkrnl import xboxkrnl_mangled_get, xboxkrnl_name_get


class RelocKind(Enum):
	REL32 = "REL32"
	DIR32 = "DIR32"


@dataclass(frozen=True)
class RelocSite:
	imm_offset: int  # offset within the carved bytes, not the VA
	kind: RelocKind
	target_va: int


@dataclass(frozen=True)
class ResolvedReloc:
	site: RelocSite
	symbol_name: str


def relocs_discover(function_bytes: bytes, function_va: int) -> list[RelocSite]:
	if not function_bytes:
		return []

	md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
	md.detail = True

	function_end = function_va + len(function_bytes)
	sites: list[RelocSite] = []

	for instr in md.disasm(function_bytes, function_va):
		if capstone.CS_GRP_CALL not in instr.groups and capstone.CS_GRP_JUMP not in instr.groups:
			continue
		if not instr.operands:
			continue

		site = _site_from_branch(instr, function_va, function_end)
		if site is not None:
			sites.append(site)

	return sites


_CALLEE_SCAN_BYTES = 256


def convention_from_bytes(body: bytes) -> tuple[str, int]:
	"""Classify calling convention from the first ret instruction.

	`ret imm16` → ('stdcall', byte_count); a bare `ret` or no ret found within
	the scanned bytes → ('cdecl', 0). The byte_count is the callee's stack
	cleanup, which is also the MSVC @N decoration.
	"""
	md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
	md.detail = False
	for _addr, _size, mnem, op in md.disasm_lite(body, 0):
		if mnem == "ret":
			if op:
				try:
					return ("stdcall", int(op, 0))
				except ValueError:
					return ("cdecl", 0)
			return ("cdecl", 0)
	return ("cdecl", 0)


def callee_convention_at(parsed: ParsedXbe, target_va: int) -> tuple[str, int]:
	"""Infer a same-binary callee's convention by reading its real bytes."""
	section = xbe_section_containing_va(parsed, target_va)
	if section is None or not section.is_executable:
		return ("cdecl", 0)
	available = section.raw_size - (target_va - section.virtual_address)
	if available <= 0:
		return ("cdecl", 0)
	try:
		body = xbe_function_carve(parsed, target_va, min(_CALLEE_SCAN_BYTES, available))
	except XbeFormatError:
		return ("cdecl", 0)
	return convention_from_bytes(body)


def reloc_symbol_name(site: RelocSite, parsed: ParsedXbe) -> str:
	# stdcall mangles as `_name@N`; recover N from the callee's bytes so the
	# call-site symbol matches ctx.h's declared convention.
	if site.kind == RelocKind.DIR32:
		kernel_name = _kernel_import_name_at(site.target_va, parsed)
		if kernel_name is not None:
			return f"__imp__{kernel_name}"

	section = xbe_section_containing_va(parsed, site.target_va)
	if section is not None and section.is_executable:
		conv, byte_count = callee_convention_at(parsed, site.target_va)
		suffix = f"@{byte_count}" if conv == "stdcall" else ""
		return f"_fn_{site.target_va:08X}{suffix}"
	return f"_data_{site.target_va:08X}"


def relocs_resolve(
	function_bytes: bytes, function_va: int, parsed: ParsedXbe
) -> list[ResolvedReloc]:
	return [
		ResolvedReloc(site=site, symbol_name=reloc_symbol_name(site, parsed))
		for site in relocs_discover(function_bytes, function_va)
	]


def _site_from_branch(instr, function_va: int, function_end: int) -> RelocSite | None:
	op = instr.operands[0]

	# REL32: E8/E9 (size 5) or 0F 8x (size 6) with an immediate operand.
	if op.type == capstone.x86.X86_OP_IMM and instr.size in (5, 6):
		target = op.imm
		if function_va <= target < function_end:
			return None
		imm_offset = (instr.address + instr.size - 4) - function_va
		return RelocSite(imm_offset=imm_offset, kind=RelocKind.REL32, target_va=target)

	# DIR32: FF 15 / FF 25 — call/jmp dword ptr [disp32]; disp is an absolute VA.
	if (
		op.type == capstone.x86.X86_OP_MEM
		and instr.size == 6
		and op.mem.base == 0
		and op.mem.index == 0
	):
		target = op.mem.disp & 0xFFFFFFFF
		imm_offset = (instr.address + instr.size - 4) - function_va
		return RelocSite(imm_offset=imm_offset, kind=RelocKind.DIR32, target_va=target)

	return None


_IMAGE_ORDINAL_FLAG32 = 0x80000000


def relocs_kernel_ordinal_at(target_va: int, parsed: ParsedXbe) -> int | None:
	"""Return the kernel export ordinal at this VA, or None if the VA
	isn't a thunk-table slot. Public so callers (e.g., the launcher's
	ctx.h composer) can resolve to a plain name without re-mangling."""
	try:
		thunk_va = xbe_kernel_thunk_address_get(parsed)
	except XbeFormatError:
		return None

	# Can't filter by is_executable: Halo 2 retail marks .rdata EXECUTABLE.
	# The IMAGE_ORDINAL_FLAG32 check below is the real guard against stray data.
	section = xbe_section_containing_va(parsed, target_va)
	if section is None:
		return None
	if target_va < thunk_va or (target_va - thunk_va) % 4 != 0:
		return None

	file_offset = section.raw_address + (target_va - section.virtual_address)
	if file_offset + 4 > len(parsed.data):
		return None

	raw = struct.unpack_from("<I", parsed.data, file_offset)[0]
	if not (raw & _IMAGE_ORDINAL_FLAG32):
		return None
	return raw & 0x7FFFFFFF


def _kernel_import_name_at(target_va: int, parsed: ParsedXbe) -> str | None:
	ordinal = relocs_kernel_ordinal_at(target_va, parsed)
	if ordinal is None:
		return None
	return xboxkrnl_mangled_get(ordinal) or xboxkrnl_name_get(ordinal)


_THUNK_SLOT_LIMIT = 4096  # null-terminated table; a bound against runaway scans


def relocs_kernel_import_va_map(parsed: ParsedXbe) -> dict[str, int]:
	"""Map each kernel-import decorated name to its thunk-table slot VA.

	The inverse of `_kernel_import_name_at`: the whole-image relocator resolves an
	`__imp__<name>` symbol back to the slot address it occupied. Keyed by the same
	decorated name `reloc_symbol_name` emits after the `__imp__` prefix. Walks the
	null-terminated thunk table from its base; non-ordinal slots are skipped.
	"""
	try:
		thunk_va = xbe_kernel_thunk_address_get(parsed)
	except XbeFormatError:
		return {}
	section = xbe_section_containing_va(parsed, thunk_va)
	if section is None:
		return {}

	out: dict[str, int] = {}
	for i in range(_THUNK_SLOT_LIMIT):
		slot_va = thunk_va + i * 4
		file_offset = section.raw_address + (slot_va - section.virtual_address)
		if file_offset + 4 > len(parsed.data):
			break
		raw = struct.unpack_from("<I", parsed.data, file_offset)[0]
		if raw == 0:
			break
		if not (raw & _IMAGE_ORDINAL_FLAG32):
			continue
		ordinal = raw & 0x7FFFFFFF
		name = xboxkrnl_mangled_get(ordinal) or xboxkrnl_name_get(ordinal)
		if name:
			out[name] = slot_va
	return out


_FN_OR_DATA_SYMBOL = re.compile(r"^_?(?:fn|data)_([0-9A-Fa-f]{8})(?:@\d+)?$")
_IMP_PREFIX = "__imp__"


def relocs_image_va_resolver(parsed: ParsedXbe) -> Callable[[str], int | None]:
	"""Resolve a compiled object's external symbol names back to image VAs.

	The inverse of `reloc_symbol_name`: `_fn_<va>` / `_data_<va>` carry the
	absolute VA in the name; `__imp__<export>` resolves to the kernel thunk-table
	slot the import occupied. Both the byte-splice verifier (Phase 4a) and the
	real relink (Phase 4b) place externals at the addresses this returns.
	"""
	imports = relocs_kernel_import_va_map(parsed)

	def resolve(name: str) -> int | None:
		if name.startswith(_IMP_PREFIX):
			return imports.get(name[len(_IMP_PREFIX) :])
		match = _FN_OR_DATA_SYMBOL.match(name)
		if match is not None:
			return int(match.group(1), 16)
		return None

	return resolve
