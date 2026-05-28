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

import struct
from dataclasses import dataclass
from enum import Enum

import capstone
import capstone.x86

from src.xbe import (
    ParsedXbe,
    XbeFormatError,
    xbe_kernel_thunk_address_get,
    xbe_section_containing_va,
)
from src.xboxkrnl import xboxkrnl_mangled_get, xboxkrnl_name_get


class RelocKind(Enum):
    REL32 = "REL32"
    DIR32 = "DIR32"


@dataclass(frozen=True)
class RelocSite:
    imm_offset: int  # byte offset of the imm32 within the carved bytes
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
        if (
            capstone.CS_GRP_CALL not in instr.groups
            and capstone.CS_GRP_JUMP not in instr.groups
        ):
            continue
        if not instr.operands:
            continue

        site = _site_from_branch(instr, function_va, function_end)
        if site is not None:
            sites.append(site)

    return sites


def reloc_symbol_name(site: RelocSite, parsed: ParsedXbe) -> str:
    # MSVC mangles cdecl as `_name`; stdcall as `_name@N`. We default to
    # cdecl since we can't infer arg byte count from a placeholder.
    if site.kind == RelocKind.DIR32:
        kernel_name = _kernel_import_name_at(site.target_va, parsed)
        if kernel_name is not None:
            return f"__imp__{kernel_name}"

    section = xbe_section_containing_va(parsed, site.target_va)
    if section is not None and section.is_executable:
        return f"_fn_{site.target_va:08X}"
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

    # DIR32: FF 15 / FF 25 — call/jmp dword ptr [disp32]. Size 6, no base or
    # index register; the disp is an absolute VA.
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

    # Halo 2 retail has .rdata flags = PRELOAD|EXECUTABLE, so we can't filter
    # by section.is_executable here. The IMAGE_ORDINAL_FLAG32 check below
    # provides the actual safety against treating arbitrary data as a slot.
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
