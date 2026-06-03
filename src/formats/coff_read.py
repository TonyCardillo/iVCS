"""Read a Microsoft COFF/i386 object into sections, relocs, and symbols.

The inverse of `coff.py`, feeding the splice verifier. Models only the subset
iVCS and `cl.exe` emit for one function: i386, short/long names,
`IMAGE_REL_I386_{REL32,DIR32}`, section symbols with one aux record.
"""

import struct
from dataclasses import dataclass

from src.formats.coff import (
	COFF_HEADER_SIZE,
	COFF_RELOC_SIZE,
	COFF_SECTION_SIZE,
	COFF_SYMBOL_SIZE,
	coff_name_field_decode,
)


@dataclass(frozen=True)
class CoffSymbol:
	name: str
	value: int
	section_number: int
	type: int
	storage_class: int


@dataclass(frozen=True)
class CoffReloc:
	offset: int  # byte offset of the field within the section's raw bytes
	symbol_index: int  # slot index into the symbol table
	type: int  # IMAGE_REL_I386_*


@dataclass(frozen=True)
class CoffSection:
	name: str
	raw: bytes
	relocations: tuple[CoffReloc, ...]


@dataclass(frozen=True)
class CoffObject:
	machine: int
	sections: tuple[CoffSection, ...]
	symbols: tuple[CoffSymbol, ...]
	symbol_by_slot: dict[int, CoffSymbol]

	def text_section(self) -> CoffSection | None:
		for section in self.sections:
			if section.name == ".text":
				return section
		return None

	def symbol_at(self, slot: int) -> CoffSymbol:
		return self.symbol_by_slot[slot]


class CoffReadError(ValueError):
	pass


def coff_object_read(data: bytes) -> CoffObject:
	"""Parse a complete COFF/i386 object into sections, relocs, and symbols."""
	if len(data) < COFF_HEADER_SIZE:
		raise CoffReadError(f"object is {len(data)} bytes, smaller than a COFF header")

	machine, section_count, _timestamp, symbol_table_ptr, symbol_count = struct.unpack_from(
		"<HHIII", data, 0
	)

	string_table = _string_table_read(data, symbol_table_ptr, symbol_count)
	symbols, symbol_by_slot = _symbols_read(data, symbol_table_ptr, symbol_count, string_table)

	sections = tuple(
		_section_read(data, COFF_HEADER_SIZE + i * COFF_SECTION_SIZE, string_table)
		for i in range(section_count)
	)
	return CoffObject(
		machine=machine,
		sections=sections,
		symbols=symbols,
		symbol_by_slot=symbol_by_slot,
	)


def _section_read(data: bytes, entry_offset: int, string_table: bytes) -> CoffSection:
	name = coff_name_field_decode(data[entry_offset : entry_offset + 8], string_table)
	(raw_size, raw_ptr, reloc_ptr, _line_ptr, reloc_count) = struct.unpack_from(
		"<IIIIH", data, entry_offset + 16
	)
	raw = data[raw_ptr : raw_ptr + raw_size] if raw_ptr else b""

	relocations: list[CoffReloc] = []
	for i in range(reloc_count):
		off, sym_idx, rtype = struct.unpack_from("<IIH", data, reloc_ptr + i * COFF_RELOC_SIZE)
		relocations.append(CoffReloc(offset=off, symbol_index=sym_idx, type=rtype))
	return CoffSection(name=name, raw=raw, relocations=tuple(relocations))


def _symbols_read(
	data: bytes, symbol_table_ptr: int, symbol_count: int, string_table: bytes
) -> tuple[tuple[CoffSymbol, ...], dict[int, CoffSymbol]]:
	symbols: list[CoffSymbol] = []
	by_slot: dict[int, CoffSymbol] = {}
	slot = 0
	while slot < symbol_count:
		base = symbol_table_ptr + slot * COFF_SYMBOL_SIZE
		name = coff_name_field_decode(data[base : base + 8], string_table)
		value, section_number, sym_type, storage_class, aux_count = struct.unpack_from(
			"<IhHBB", data, base + 8
		)
		symbol = CoffSymbol(
			name=name,
			value=value,
			section_number=section_number,
			type=sym_type,
			storage_class=storage_class,
		)
		symbols.append(symbol)
		by_slot[slot] = symbol
		slot += 1 + aux_count
	return tuple(symbols), by_slot


def _string_table_read(data: bytes, symbol_table_ptr: int, symbol_count: int) -> bytes:
	if not symbol_table_ptr:
		return b""
	string_table_start = symbol_table_ptr + symbol_count * COFF_SYMBOL_SIZE
	if string_table_start + 4 > len(data):
		return b""
	return data[string_table_start:]
