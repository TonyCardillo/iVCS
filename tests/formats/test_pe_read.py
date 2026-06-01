"""Tests for the minimal PE reader, exercised against hand-crafted images."""

import struct

import pytest
from hypothesis import given
from hypothesis import strategies as st

from src.formats.pe_read import PeReadError, pe_image_read


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
	# Image-base parsing, VA = base + rva, raw bytes, and multiple sections in
	# order are covered by TestPeImageReadRoundTrip. What stays pins behaviour the
	# round-trip never exercises: section_at_va containment lookup and the
	# non-PE rejection.
	def test_section_at_va_finds_containing_section_example(self):
		pe = pe_image_read(_make_pe(0x00170000, [(".text", 0x1000, b"\x90" * 0x100)]))
		found = pe.section_at_va(0x00171050)
		assert found is not None and found.name == ".text"
		assert pe.section_at_va(0x00180000) is None

	def test_rejects_non_pe_example(self):
		with pytest.raises(PeReadError):
			pe_image_read(b"not a pe file at all")


# --- Property tests --------------------------------------------------------
# The examples each pin one image shape; this asserts the parse law they witness:
# pe_image_read inverts the writer for any section list — image base recovered,
# and each section's name, raw bytes, size, and VA (= base + rva) preserved in
# order.


@st.composite
def _section_list(draw):
	out: list[tuple[str, int, bytes]] = []
	for _ in range(draw(st.integers(1, 5))):
		name = draw(st.sampled_from([".text", ".data", ".rdata", "code", "blob"]))
		rva = draw(st.integers(min_value=0, max_value=0x00FF_F000)) & ~0xFFF | 0x1000
		raw = draw(st.binary(max_size=32))
		out.append((name, rva, raw))
	return out


class TestPeImageReadRoundTrip:
	@given(
		image_base=st.integers(min_value=0x10000, max_value=0x7000_0000), sections=_section_list()
	)
	def test_round_trip_recovers_base_and_sections(self, image_base, sections):
		pe = pe_image_read(_make_pe(image_base, sections))
		assert pe.image_base == image_base
		assert len(pe.sections) == len(sections)
		for (name, rva, raw), sec in zip(sections, pe.sections, strict=True):
			assert sec.name == name
			assert sec.raw == raw
			assert sec.virtual_size == len(raw)
			assert sec.virtual_address == image_base + rva
