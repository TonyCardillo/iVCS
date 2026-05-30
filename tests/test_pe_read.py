"""Tests for the minimal PE reader, exercised against hand-crafted images."""

import struct

import pytest

from src.pe_read import PeReadError, pe_image_read


def _make_pe(image_base: int, sections: list[tuple[str, int, bytes]]) -> bytes:
	"""Build a minimal-but-parseable PE32 with the given sections.

	sections: list of (name, rva, raw_bytes). Section raw data is laid out
	contiguously after the section table; virtual_size is len(raw_bytes).
	"""
	pe_off = 0x80
	opt_hdr_size = 0xE0
	sec_table_off = pe_off + 4 + 20 + opt_hdr_size
	raw_cursor = sec_table_off + len(sections) * 40

	section_entries = bytearray()
	section_blobs = bytearray()
	for name, rva, raw in sections:
		raw_ptr = sec_table_off + len(sections) * 40 + len(section_blobs)
		section_blobs += raw
		section_entries += name.encode("ascii").ljust(8, b"\x00") + struct.pack(
			"<IIII IIHHI",
			len(raw),  # VirtualSize
			rva,  # VirtualAddress (RVA)
			len(raw),  # SizeOfRawData
			raw_ptr,  # PointerToRawData
			0,
			0,
			0,
			0,
			0,
		)

	dos = bytearray(pe_off)
	dos[0:2] = b"MZ"
	struct.pack_into("<I", dos, 0x3C, pe_off)

	coff = struct.pack("<HHIIIHH", 0x014C, len(sections), 0, 0, 0, opt_hdr_size, 0x2102)

	opt = bytearray(opt_hdr_size)
	struct.pack_into("<H", opt, 0, 0x10B)  # PE32 magic
	struct.pack_into("<I", opt, 28, image_base)  # ImageBase at offset 28

	body = bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + bytes(section_entries)
	assert len(body) == raw_cursor
	return body + bytes(section_blobs)


class TestPeImageRead:
	def test_image_base_parsed(self):
		pe = pe_image_read(_make_pe(0x00170000, [(".text", 0x1000, b"\xc3")]))
		assert pe.image_base == 0x00170000

	def test_section_va_is_image_base_plus_rva(self):
		pe = pe_image_read(_make_pe(0x00170000, [(".text", 0x1000, b"\x90\xc3")]))
		text = pe.sections[0]
		assert text.name == ".text"
		assert text.virtual_address == 0x00171000
		assert text.raw == b"\x90\xc3"

	def test_multiple_sections(self):
		pe = pe_image_read(
			_make_pe(0x10000, [(".text", 0x1000, b"\xc3"), (".data", 0x2000, b"\x01\x02")])
		)
		assert [s.name for s in pe.sections] == [".text", ".data"]
		assert pe.sections[1].virtual_address == 0x12000

	def test_section_at_va_finds_containing_section(self):
		pe = pe_image_read(_make_pe(0x00170000, [(".text", 0x1000, b"\x90" * 0x100)]))
		found = pe.section_at_va(0x00171050)
		assert found is not None and found.name == ".text"
		assert pe.section_at_va(0x00180000) is None

	def test_rejects_non_pe(self):
		with pytest.raises(PeReadError):
			pe_image_read(b"not a pe file at all")
