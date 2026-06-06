"""Tests for the end-to-end XBE→target.obj orchestrator."""

from src.formats.carver import carver_target_obj_build
from src.formats.coff import IMAGE_REL_I386_REL32
from src.formats.coff_read import coff_object_read
from src.formats.xbe import SECTION_FLAG_EXECUTABLE, xbe_parse
from tests.formats.test_xbe import build_minimal_xbe


def _call_rel32(at_va: int, target_va: int) -> bytes:
	rel = (target_va - at_va - 5) & 0xFFFFFFFF
	return b"\xe8" + rel.to_bytes(4, "little")


class TestCarverTargetObjBuild:
	def test_threads_relocs_into_resulting_obj(self):
		fn_va = 0x00011000
		body = _call_rel32(fn_va, 0x00020000) + b"\xc3"
		parsed = xbe_parse(
			build_minimal_xbe(
				base_addr=0x00010000,
				size_of_image=0x00100000,
				sections=[
					(".text", SECTION_FLAG_EXECUTABLE, body + b"\x90" * 8, fn_va),
					(".other", SECTION_FLAG_EXECUTABLE, b"\xc3", 0x00020000),
				],
			)
		)
		blob = carver_target_obj_build(parsed, fn_va, len(body), "_caller")

		# Parse the result instead of substring-sniffing: the E8 call's imm32 site
		# (offset 1) must become exactly one REL32 reloc whose symbol resolves to the
		# callee, and the carved function must be the defined symbol under "_caller".
		obj = coff_object_read(blob)
		text = obj.text_section()
		assert text is not None
		(reloc,) = text.relocations
		assert reloc.offset == 1
		assert reloc.type == IMAGE_REL_I386_REL32
		assert obj.symbol_at(reloc.symbol_index).name == "_fn_00020000"
		assert "_caller" in {s.name for s in obj.symbols}
