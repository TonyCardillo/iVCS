"""Synthesize a Microsoft COFF/i386 object file from a carved XBE function.

Produces target.obj for the objdiff comparison side. One .text section
holds the carved bytes (with REL32 imm32 fields zeroed); the symbol
table carries the function symbol plus one external per unique
relocation target; one IMAGE_REL_I386_REL32 record per ResolvedReloc.

Emits both IMAGE_REL_I386_REL32 (E8/E9/0F 8x direct call/jmp) and
IMAGE_REL_I386_DIR32 (FF 15/FF 25 indirect call/jmp through the kernel
thunk table).
"""

import struct
from dataclasses import dataclass

from src.relocs import RelocKind, ResolvedReloc

COFF_HEADER_SIZE = 20
COFF_SECTION_SIZE = 40
COFF_RELOC_SIZE = 10
COFF_SYMBOL_SIZE = 18

IMAGE_FILE_MACHINE_I386 = 0x014C

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_ALIGN_16BYTES = 0x00500000
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
TEXT_SECTION_CHARACTERISTICS = (
	IMAGE_SCN_CNT_CODE | IMAGE_SCN_ALIGN_16BYTES | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
)

IMAGE_REL_I386_DIR32 = 0x0006
IMAGE_REL_I386_REL32 = 0x0014

IMAGE_SYM_CLASS_EXTERNAL = 2
IMAGE_SYM_CLASS_STATIC = 3
IMAGE_SYM_TYPE_NULL = 0x0000
IMAGE_SYM_TYPE_FUNCTION = 0x0020

IMAGE_SYM_ABSOLUTE = -1  # section number for a symbol with an absolute value

_SHORT_NAME_LEN = 8


@dataclass(frozen=True)
class _SymbolRecord:
	name: str
	value: int
	section_number: int
	type: int
	storage_class: int
	aux_data: bytes = b""


def coff_object_build(
	text_bytes: bytes,
	function_name: str,
	relocations: list[ResolvedReloc],
) -> bytes:
	"""Return a complete COFF/i386 .obj as bytes."""
	text_relocated = _text_zero_imm32_sites(text_bytes, relocations)
	unique_externals = _unique_external_names(relocations, exclude=function_name)
	symbols = _symbol_table_build(function_name, unique_externals)
	symbol_index_by_name = {sym.name: i for i, sym in _enumerate_with_aux(symbols)}

	reloc_records = _reloc_records_build(relocations, symbol_index_by_name)

	# Layout: header | section table | .text raw | .text relocs | symbols | string table
	text_raw_ptr = COFF_HEADER_SIZE + COFF_SECTION_SIZE
	text_reloc_ptr = text_raw_ptr + len(text_relocated) if reloc_records else 0
	symbol_table_ptr = text_raw_ptr + len(text_relocated) + len(reloc_records) * COFF_RELOC_SIZE

	section_table = _section_entry_pack(
		name=".text",
		raw_size=len(text_relocated),
		raw_ptr=text_raw_ptr,
		reloc_ptr=text_reloc_ptr,
		reloc_count=len(reloc_records),
		characteristics=TEXT_SECTION_CHARACTERISTICS,
	)
	symbol_blob, string_table = _symbol_table_pack(symbols)
	header = _coff_header_pack(
		section_count=1,
		symbol_table_ptr=symbol_table_ptr,
		symbol_count=_symbol_slot_count(symbols),
	)

	return b"".join(
		[
			header,
			section_table,
			text_relocated,
			b"".join(reloc_records),
			symbol_blob,
			string_table,
		]
	)


def coff_absolute_symbols_build(symbols: dict[str, int]) -> bytes:
	"""A sectionless COFF/i386 object defining each name as an absolute symbol.

	The real-relink path (Phase 4b) feeds this to Link.Exe so the linker resolves
	a function's REL32/DIR32 externals — other functions' VAs, kernel thunk slots —
	to fixed image addresses, exactly as they sit in the original image. An
	`IMAGE_SYM_ABSOLUTE` (section number -1) symbol's value IS its virtual address.
	"""
	records = [
		_SymbolRecord(
			name=name,
			value=va,
			section_number=IMAGE_SYM_ABSOLUTE,
			type=IMAGE_SYM_TYPE_NULL,
			storage_class=IMAGE_SYM_CLASS_EXTERNAL,
		)
		for name, va in symbols.items()
	]
	symbol_blob, string_table = _symbol_table_pack(records)
	header = _coff_header_pack(
		section_count=0,
		symbol_table_ptr=COFF_HEADER_SIZE,
		symbol_count=_symbol_slot_count(records),
	)
	return header + symbol_blob + string_table


def _text_zero_imm32_sites(text_bytes: bytes, relocations: list[ResolvedReloc]) -> bytes:
	if not relocations:
		return text_bytes
	buf = bytearray(text_bytes)
	for r in relocations:
		if r.site.kind not in _RELOC_KIND_TO_COFF_TYPE:
			continue
		off = r.site.imm_offset
		buf[off : off + 4] = b"\x00\x00\x00\x00"
	return bytes(buf)


def _unique_external_names(relocations: list[ResolvedReloc], *, exclude: str) -> list[str]:
	seen: set[str] = {exclude}
	ordered: list[str] = []
	for r in relocations:
		if r.symbol_name in seen:
			continue
		seen.add(r.symbol_name)
		ordered.append(r.symbol_name)
	return ordered


def _symbol_table_build(function_name: str, external_names: list[str]) -> list[_SymbolRecord]:
	return [
		_SymbolRecord(
			name=".text",
			value=0,
			section_number=1,
			type=IMAGE_SYM_TYPE_NULL,
			storage_class=IMAGE_SYM_CLASS_STATIC,
			aux_data=_section_aux_record(length=0, nrelocs=0),
		),
		_SymbolRecord(
			name=function_name,
			value=0,
			section_number=1,
			type=IMAGE_SYM_TYPE_FUNCTION,
			storage_class=IMAGE_SYM_CLASS_EXTERNAL,
		),
		*[
			_SymbolRecord(
				name=name,
				value=0,
				section_number=0,
				type=IMAGE_SYM_TYPE_NULL,
				storage_class=IMAGE_SYM_CLASS_EXTERNAL,
			)
			for name in external_names
		],
	]


def _section_aux_record(length: int, nrelocs: int) -> bytes:
	return struct.pack(
		"<IHHIHB3x",
		length,  # Length
		nrelocs,  # NumberOfRelocations
		0,  # NumberOfLinenumbers
		0,  # CheckSum
		0,  # Number
		0,  # Selector
	)


def _enumerate_with_aux(symbols: list[_SymbolRecord]):
	"""Yield (slot_index, symbol) accounting for aux records consuming slots."""
	slot = 0
	for sym in symbols:
		yield slot, sym
		slot += 1 + (len(sym.aux_data) // COFF_SYMBOL_SIZE)


def _symbol_slot_count(symbols: list[_SymbolRecord]) -> int:
	return sum(1 + (len(sym.aux_data) // COFF_SYMBOL_SIZE) for sym in symbols)


_RELOC_KIND_TO_COFF_TYPE = {
	RelocKind.REL32: IMAGE_REL_I386_REL32,
	RelocKind.DIR32: IMAGE_REL_I386_DIR32,
}


def _reloc_records_build(
	relocations: list[ResolvedReloc], symbol_index_by_name: dict[str, int]
) -> list[bytes]:
	records: list[bytes] = []
	for r in relocations:
		coff_type = _RELOC_KIND_TO_COFF_TYPE.get(r.site.kind)
		if coff_type is None:
			continue
		sym_idx = symbol_index_by_name[r.symbol_name]
		records.append(struct.pack("<IIH", r.site.imm_offset, sym_idx, coff_type))
	return records


def _coff_header_pack(section_count: int, symbol_table_ptr: int, symbol_count: int) -> bytes:
	return struct.pack(
		"<HHIIIHH",
		IMAGE_FILE_MACHINE_I386,
		section_count,
		0,  # TimeDateStamp
		symbol_table_ptr,
		symbol_count,
		0,  # SizeOfOptionalHeader
		0,  # Characteristics
	)


def _section_entry_pack(
	name: str,
	raw_size: int,
	raw_ptr: int,
	reloc_ptr: int,
	reloc_count: int,
	characteristics: int,
) -> bytes:
	name_bytes = name.encode("ascii")
	if len(name_bytes) > 8:
		raise ValueError(
			f"section name {name!r} exceeds 8 bytes (long-name encoding not supported)"
		)
	name_field = name_bytes.ljust(8, b"\x00")
	return name_field + struct.pack(
		"<IIIIIIHHI",
		0,  # VirtualSize
		0,  # VirtualAddress
		raw_size,
		raw_ptr,
		reloc_ptr,
		0,  # PointerToLinenumbers
		reloc_count,
		0,  # NumberOfLinenumbers
		characteristics,
	)


def _symbol_table_pack(symbols: list[_SymbolRecord]) -> tuple[bytes, bytes]:
	"""Pack the symbol table; return (symbol_blob, string_table_blob).

	The string table begins with its own size field (u32). Offset 0 means
	'no entry', so the first usable offset is 4.
	"""
	strings: list[bytes] = []
	string_offsets: dict[str, int] = {}
	next_offset = 4  # reserve bytes 0..3 for the size field itself

	def stringtab_offset_for(name: str) -> int:
		nonlocal next_offset
		if name in string_offsets:
			return string_offsets[name]
		offset = next_offset
		encoded = name.encode("ascii") + b"\x00"
		strings.append(encoded)
		string_offsets[name] = offset
		next_offset += len(encoded)
		return offset

	out = bytearray()
	for sym in symbols:
		name_bytes = sym.name.encode("ascii")
		if len(name_bytes) <= _SHORT_NAME_LEN:
			name_field = name_bytes.ljust(8, b"\x00")
		else:
			name_field = struct.pack("<II", 0, stringtab_offset_for(sym.name))

		aux_slots = len(sym.aux_data) // COFF_SYMBOL_SIZE
		out += name_field + struct.pack(
			"<IhHBB",
			sym.value,
			sym.section_number,
			sym.type,
			sym.storage_class,
			aux_slots,
		)
		if sym.aux_data:
			if len(sym.aux_data) != aux_slots * COFF_SYMBOL_SIZE:
				raise ValueError(
					f"aux data for {sym.name!r} is {len(sym.aux_data)} bytes "
					f"(must be a multiple of {COFF_SYMBOL_SIZE})"
				)
			out += sym.aux_data

	string_table_body = b"".join(strings)
	string_table = struct.pack("<I", 4 + len(string_table_body)) + string_table_body
	return bytes(out), string_table
