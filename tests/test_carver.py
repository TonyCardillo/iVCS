"""Tests for the end-to-end XBE→target.obj orchestrator."""

from src.carver import carver_target_obj_build
from src.xbe import SECTION_FLAG_EXECUTABLE, xbe_parse
from tests.test_xbe import build_minimal_xbe


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
        # The external "_fn_00020000" must be in the symbol table somewhere
        assert b"_fn_00020000" in blob
