"""Round-trip tests for the COFF reader against the COFF writer."""

from hypothesis import given
from hypothesis import strategies as st

from src.coff import (
	IMAGE_FILE_MACHINE_I386,
	IMAGE_SYM_ABSOLUTE,
	coff_absolute_symbols_build,
	coff_object_build,
)
from src.coff_read import coff_object_read
from src.relocs import RelocKind, RelocSite, ResolvedReloc


def _rel32(imm_offset: int, target_va: int, name: str) -> ResolvedReloc:
	return ResolvedReloc(
		site=RelocSite(imm_offset=imm_offset, kind=RelocKind.REL32, target_va=target_va),
		symbol_name=name,
	)


def _dir32(imm_offset: int, target_va: int, name: str) -> ResolvedReloc:
	return ResolvedReloc(
		site=RelocSite(imm_offset=imm_offset, kind=RelocKind.DIR32, target_va=target_va),
		symbol_name=name,
	)


class TestReadHeaderAndText:
	def test_machine_is_i386(self):
		obj = coff_object_read(coff_object_build(b"\xc3", "fn_1", relocations=[]))
		assert obj.machine == IMAGE_FILE_MACHINE_I386

	def test_text_bytes_round_trip_without_relocs(self):
		body = b"\x55\x8b\xec\x5d\xc3"
		obj = coff_object_read(coff_object_build(body, "fn_1", relocations=[]))
		assert obj.text_section().raw == body

	def test_text_bytes_have_reloc_sites_zeroed(self):
		# A call rel32 at offset 1: E8 <imm32>. The writer zeroes the imm32.
		body = b"\xe8\x11\x22\x33\x44\xc3"
		reloc = _rel32(1, 0x00400000, "_fn_00400000")
		obj = coff_object_read(coff_object_build(body, "fn_1", relocations=[reloc]))
		assert obj.text_section().raw[1:5] == b"\x00\x00\x00\x00"


class TestReadRelocations:
	def test_reloc_offsets_and_kinds_round_trip(self):
		body = b"\xe8\x00\x00\x00\x00" + b"\xff\x15\x00\x00\x00\x00" + b"\xc3"
		relocs = [
			_rel32(1, 0x00410000, "_fn_00410000"),
			_dir32(7, 0x00420000, "__imp__SomeKernelExport"),
		]
		obj = coff_object_read(coff_object_build(body, "fn_1", relocations=relocs))
		text = obj.text_section()
		assert len(text.relocations) == 2
		offsets = {r.offset for r in text.relocations}
		assert offsets == {1, 7}

	def test_reloc_symbol_index_points_at_named_symbol(self):
		body = b"\xe8\x00\x00\x00\x00\xc3"
		obj = coff_object_read(
			coff_object_build(body, "fn_1", relocations=[_rel32(1, 0x00430000, "_fn_00430000")])
		)
		text = obj.text_section()
		reloc = text.relocations[0]
		assert obj.symbol_at(reloc.symbol_index).name == "_fn_00430000"


class TestReadSymbols:
	def test_function_symbol_present(self):
		obj = coff_object_read(coff_object_build(b"\xc3", "fn_short", relocations=[]))
		names = {s.name for s in obj.symbols}
		assert "fn_short" in names

	def test_long_symbol_name_via_string_table(self):
		long_name = "_fn_00430000_with_a_very_long_padded_identifier"
		body = b"\xe8\x00\x00\x00\x00\xc3"
		obj = coff_object_read(
			coff_object_build(body, "fn_1", relocations=[_rel32(1, 0x00430000, long_name)])
		)
		names = {s.name for s in obj.symbols}
		assert long_name in names

	def test_section_symbol_resolvable_by_slot(self):
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


class TestAbsoluteSymbols:
	def test_value_is_the_virtual_address(self):
		obj = coff_object_read(
			coff_absolute_symbols_build({"_fn_00410000": 0x00410000, "__imp__NtClose@4": 0x88100})
		)
		by_name = {s.name: s for s in obj.symbols}
		assert by_name["_fn_00410000"].value == 0x00410000
		assert by_name["__imp__NtClose@4"].value == 0x88100

	def test_section_number_is_absolute(self):
		obj = coff_object_read(coff_absolute_symbols_build({"_data_00420000": 0x00420000}))
		assert obj.symbols[0].section_number == IMAGE_SYM_ABSOLUTE

	def test_no_sections(self):
		obj = coff_object_read(coff_absolute_symbols_build({"x": 1}))
		assert obj.sections == ()
		assert obj.text_section() is None
