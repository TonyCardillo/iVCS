"""Read a Microsoft COFF/i386 object back into its constituent parts.

The inverse of `coff.py`. The whole-image splice verifier needs a function's
compiled machine code, its relocation records, and its symbol table pulled out
of a `.obj` so it can place the bytes at the function's real virtual address
and byte-compare against the original image. objdiff does its comparison inside
the Rust binary, so there is no other reader to lean on.

Only the subset iVCS produces and `cl.exe` emits for one function is modeled:
i386 objects, short/long symbol names, `IMAGE_REL_I386_{REL32,DIR32}`, and
section symbols with one aux record. Line numbers are ignored.
"""

import struct
from dataclasses import dataclass

from src.coff import (
	COFF_HEADER_SIZE,
	COFF_RELOC_SIZE,
	COFF_SECTION_SIZE,
	COFF_SYMBOL_SIZE,
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
	name = _short_or_long_name(data[entry_offset : entry_offset + 8], string_table)
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
		name = _short_or_long_name(data[base : base + 8], string_table)
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


def _short_or_long_name(name_field: bytes, string_table: bytes) -> str:
	"""Decode an 8-byte COFF name field: inline short name, or `\\0\\0\\0\\0`
	+ string-table offset for a long name."""
	if name_field[:4] == b"\x00\x00\x00\x00":
		offset = struct.unpack_from("<I", name_field, 4)[0]
		end = string_table.find(b"\x00", offset)
		return string_table[offset:end].decode("ascii")
	return name_field.rstrip(b"\x00").decode("ascii")
