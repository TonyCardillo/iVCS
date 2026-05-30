"""Minimal reader for a linked PE32 image — just enough to extract section bytes.

The real-relink path (Phase 4b) links committed objects with Link.Exe into a
PE/DLL and needs the laid-out section bytes back, at their virtual addresses, to
byte-compare against the original XBE section. Only what that requires is
modelled: the DOS stub's `e_lfanew`, the PE signature, the COFF file header, the
PE32 optional header's `ImageBase`, and the section table. Data directories,
imports, and relocations are ignored.
"""

import struct
from dataclasses import dataclass

_COFF_HEADER_SIZE = 20
_SECTION_ENTRY_SIZE = 40
_PE32_IMAGE_BASE_OFFSET = 28  # ImageBase within the PE32 optional header


class PeReadError(ValueError):
	pass


@dataclass(frozen=True)
class PeSection:
	name: str
	virtual_address: int  # absolute VA: ImageBase + RVA
	virtual_size: int
	raw: bytes

	def contains_va(self, va: int) -> bool:
		return self.virtual_address <= va < self.virtual_address + self.virtual_size


@dataclass(frozen=True)
class PeImage:
	image_base: int
	sections: tuple[PeSection, ...]

	def section_at_va(self, va: int) -> PeSection | None:
		for section in self.sections:
			if section.contains_va(va):
				return section
		return None


def pe_image_read(data: bytes) -> PeImage:
	"""Parse a linked PE32 image into its image base and sections."""
	if len(data) < 0x40 or data[:2] != b"MZ":
		raise PeReadError("not a PE image (missing MZ signature)")

	pe_off = struct.unpack_from("<I", data, 0x3C)[0]
	if pe_off + 4 > len(data) or data[pe_off : pe_off + 4] != b"PE\x00\x00":
		raise PeReadError("not a PE image (missing PE signature)")

	coff_off = pe_off + 4
	section_count = struct.unpack_from("<H", data, coff_off + 2)[0]
	opt_hdr_size = struct.unpack_from("<H", data, coff_off + 16)[0]

	opt_off = coff_off + _COFF_HEADER_SIZE
	image_base = struct.unpack_from("<I", data, opt_off + _PE32_IMAGE_BASE_OFFSET)[0]

	section_table_off = opt_off + opt_hdr_size
	sections = tuple(
		_section_read(data, section_table_off + i * _SECTION_ENTRY_SIZE, image_base)
		for i in range(section_count)
	)
	return PeImage(image_base=image_base, sections=sections)


def _section_read(data: bytes, entry_offset: int, image_base: int) -> PeSection:
	name = data[entry_offset : entry_offset + 8].rstrip(b"\x00").decode("ascii", "replace")
	virtual_size, rva, raw_size, raw_ptr = struct.unpack_from("<IIII", data, entry_offset + 8)
	raw = data[raw_ptr : raw_ptr + raw_size] if raw_ptr else b""
	return PeSection(
		name=name,
		virtual_address=image_base + rva,
		virtual_size=virtual_size,
		raw=raw,
	)
