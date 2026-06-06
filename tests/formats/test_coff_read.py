"""Round-trip tests for the COFF reader against the COFF writer."""

import struct

import pytest
from hypothesis import given
from hypothesis import strategies as st

from src.formats.coff import (
	COFF_HEADER_SIZE,
	IMAGE_FILE_MACHINE_I386,
	coff_object_build,
)
from src.formats.coff_read import CoffReadError, coff_object_read
from src.formats.relocs import RelocKind, RelocSite, ResolvedReloc


class TestMalformedObject:
	# A truncated or corrupt .obj must raise the module's own CoffReadError, not an
	# opaque struct.error. The splice verifier compiles untrusted cl.exe output and
	# only handles CoffReadError; a bare struct.error would escape (cf. relink #1).
	def _valid(self) -> bytes:
		return coff_object_build(b"\xc3", "fn_1", relocations=[])

	def test_truncated_object_raises_coff_read_error_example(self):
		obj = self._valid()
		with pytest.raises(CoffReadError):
			coff_object_read(obj[: len(obj) // 2])  # cuts through the symbol table

	def test_symbol_table_pointer_past_eof_raises_coff_read_error_example(self):
		obj = bytearray(self._valid())
		struct.pack_into("<I", obj, 8, len(obj) + 0x1000)  # PointerToSymbolTable @ +8
		with pytest.raises(CoffReadError):
			coff_object_read(bytes(obj))

	def test_section_count_past_eof_raises_coff_read_error_example(self):
		obj = bytearray(self._valid())
		struct.pack_into("<H", obj, 2, 0xFFFF)  # NumberOfSections @ +2
		with pytest.raises(CoffReadError):
			coff_object_read(bytes(obj))

	def test_section_reloc_count_overflow_raises_coff_read_error_example(self):
		obj = bytearray(self._valid())
		# Section 0's NumberOfRelocations is the uint16 at section_header + 32.
		struct.pack_into("<H", obj, COFF_HEADER_SIZE + 32, 0xFFFF)
		with pytest.raises(CoffReadError):
			coff_object_read(bytes(obj))

	def test_section_raw_pointer_past_eof_raises_coff_read_error_example(self):
		obj = bytearray(self._valid())
		# Section 0's PointerToRawData is the uint32 at section_header + 20.
		struct.pack_into("<I", obj, COFF_HEADER_SIZE + 20, len(obj) + 0x1000)
		with pytest.raises(CoffReadError):
			coff_object_read(bytes(obj))


class TestReadHeaderAndText:
	# Text-byte preservation, reloc-site zeroing, reloc offset/symbol resolution,
	# and long-name round-tripping are all covered by
	# TestRoundTripProperty.test_build_then_read_is_invertible. What stays pins
	# the i386 machine id and the .text-symbol-at-slot-0 layout the law omits.
	def test_machine_is_i386_example(self):
		obj = coff_object_read(coff_object_build(b"\xc3", "fn_1", relocations=[]))
		assert obj.machine == IMAGE_FILE_MACHINE_I386

	def test_section_symbol_resolvable_by_slot_example(self):
		# The .text section symbol lives at slot 0 in the writer's layout.
		obj = coff_object_read(coff_object_build(b"\xc3", "fn_1", relocations=[]))
		assert obj.symbol_at(0).name == ".text"


# --- Round-trip property ---------------------------------------------------
# The hand-built cases above pin specific shapes; this asserts the general law
# the writer/reader form an inverse pair, so any field they exchange survives.

# External symbol names that never collide with the function symbol or ".text".
# The `long` flag crosses the 8-byte inline/string-table boundary in both dirs.
_ext_names = st.builds(
	lambda i, long: f"_ext_{i}" + ("_padded_beyond_eight_bytes" if long else ""),
	st.integers(min_value=0, max_value=99),
	st.booleans(),
)


@st.composite
def _body_with_relocs(draw):
	"""A .text body plus non-overlapping reloc sites, each a 4-byte field."""
	chunks: list[bytes] = []
	relocs: list[ResolvedReloc] = []
	offset = 0
	for _ in range(draw(st.integers(min_value=0, max_value=5))):
		gap = draw(st.binary(min_size=0, max_size=4))
		chunks.append(gap)
		offset += len(gap)
		chunks.append(draw(st.binary(min_size=4, max_size=4)))  # writer zeroes this
		kind = draw(st.sampled_from([RelocKind.REL32, RelocKind.DIR32]))
		target = draw(st.integers(min_value=0, max_value=0xFFFFFFFF))
		relocs.append(ResolvedReloc(RelocSite(offset, kind, target), draw(_ext_names)))
		offset += 4
	chunks.append(draw(st.binary(min_size=1, max_size=4)))  # trailing gap; keeps body non-empty
	return b"".join(chunks), relocs


class TestRoundTripProperty:
	@given(payload=_body_with_relocs())
	def test_build_then_read_is_invertible(self, payload):
		body, relocs = payload
		obj = coff_object_read(coff_object_build(body, "fn_main", relocations=relocs))
		text = obj.text_section()
		assert text is not None

		# Bytes preserved, with exactly the reloc fields zeroed.
		expected = bytearray(body)
		for r in relocs:
			expected[r.site.imm_offset : r.site.imm_offset + 4] = b"\x00\x00\x00\x00"
		assert text.raw == bytes(expected)

		# One record per input reloc; offsets preserved (sites are non-overlapping).
		name_by_offset = {r.site.imm_offset: r.symbol_name for r in relocs}
		assert len(text.relocations) == len(relocs)
		assert {cr.offset for cr in text.relocations} == set(name_by_offset)

		# Each record's symbol index resolves to the name it was built with.
		for cr in text.relocations:
			assert obj.symbol_at(cr.symbol_index).name == name_by_offset[cr.offset]

		# The function symbol survives the trip.
		assert "fn_main" in {s.name for s in obj.symbols}
