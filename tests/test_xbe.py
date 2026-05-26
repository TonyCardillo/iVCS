"""Tests for the XBE (Xbox Executable) loader.

The XBE format is documented in Cxbx-Reloaded's src/common/xbe/Xbe.h.
Header is 0x178 bytes minimum; section headers are 56 bytes each; section
name strings are null-terminated ASCII stored in the header region.
Virtual addresses inside the header region convert to file offsets via
(vaddr - base_addr).

These tests synthesize minimal valid XBEs at byte level rather than
shipping a real game .xbe; format conformance is the contract under test.
"""

import dataclasses
import struct
from io import BytesIO

import pytest

from src.xbe import (
    SECTION_FLAG_EXECUTABLE,
    SECTION_FLAG_WRITABLE,
    XbeFormatError,
    is_xbe_magic_valid,
    xbe_parse,
    xbe_section_find,
    xbe_section_read,
)


def build_minimal_xbe(
    base_addr: int = 0x00010000,
    sections: list[tuple[str, int, bytes]] | None = None,
) -> bytes:
    """Construct a syntactically-valid XBE byte stream for tests.

    sections: list of (name, flags, raw_data) tuples. Section raw addresses
    pack contiguously after the section name table.
    """
    sections = sections or []
    header_size = 0x178
    section_header_size = 56
    section_table_offset = header_size
    section_table_size = section_header_size * len(sections)

    name_table_offset = section_table_offset + section_table_size
    name_bytes = b""
    name_offsets: list[int] = []
    for name, _, _ in sections:
        name_offsets.append(len(name_bytes))
        name_bytes += name.encode("ascii") + b"\x00"

    raw_data_offset = name_table_offset + len(name_bytes)

    out = BytesIO()
    out.write(b"XBEH")
    out.write(b"\x00" * 256)  # digital signature
    out.write(struct.pack("<I", base_addr))
    out.write(struct.pack("<I", raw_data_offset))  # size of headers
    out.write(struct.pack("<I", 0))  # size of image
    out.write(struct.pack("<I", header_size))  # size of image header
    out.write(struct.pack("<I", 0))  # timedate
    out.write(struct.pack("<I", 0))  # certificate addr
    out.write(struct.pack("<I", len(sections)))
    out.write(struct.pack("<I", base_addr + section_table_offset))
    # The rest of the 0x178-byte header isn't read by the MVP parser; pad zero.
    out.write(b"\x00" * (header_size - out.tell()))

    raw_cursor = raw_data_offset
    for (name, flags, data), name_off in zip(sections, name_offsets, strict=True):
        out.write(struct.pack("<I", flags))
        out.write(struct.pack("<I", 0))  # virtual address (not exercised here)
        out.write(struct.pack("<I", len(data)))  # virtual size
        out.write(struct.pack("<I", raw_cursor))  # raw addr
        out.write(struct.pack("<I", len(data)))  # raw size
        out.write(struct.pack("<I", base_addr + name_table_offset + name_off))
        out.write(struct.pack("<I", 0))  # section ref count
        out.write(struct.pack("<I", 0))  # head shared ref count addr
        out.write(struct.pack("<I", 0))  # tail shared ref count addr
        out.write(b"\x00" * 20)  # section digest
        raw_cursor += len(data)

    out.write(name_bytes)
    for _, _, data in sections:
        out.write(data)

    return out.getvalue()


class TestMagicCheck:
    def test_valid_magic_passes(self):
        assert is_xbe_magic_valid(build_minimal_xbe()) is True

    def test_wrong_magic_fails(self):
        assert is_xbe_magic_valid(b"MZ\x90\x00" + b"\x00" * 100) is False

    def test_empty_data_fails(self):
        assert is_xbe_magic_valid(b"") is False

    def test_too_short_fails(self):
        assert is_xbe_magic_valid(b"XBE") is False


class TestHeaderParse:
    def test_header_fields_match_input(self):
        parsed = xbe_parse(build_minimal_xbe(base_addr=0x00020000))
        assert parsed.header.base_address == 0x00020000
        assert parsed.header.section_count == 0
        assert parsed.header.size_of_image_header == 0x178

    def test_bad_magic_raises(self):
        with pytest.raises(XbeFormatError, match="magic"):
            xbe_parse(b"NOPE" + b"\x00" * 1000)

    def test_truncated_header_raises(self):
        with pytest.raises(XbeFormatError, match="header"):
            xbe_parse(b"XBEH" + b"\x00" * 50)


class TestSectionEnumeration:
    def test_zero_sections(self):
        parsed = xbe_parse(build_minimal_xbe(sections=[]))
        assert parsed.sections == ()

    def test_single_section_attributes(self):
        section_data = b"\x90" * 16
        flags = SECTION_FLAG_EXECUTABLE
        parsed = xbe_parse(build_minimal_xbe(sections=[(".text", flags, section_data)]))

        assert len(parsed.sections) == 1
        s = parsed.sections[0]
        assert s.name == ".text"
        assert s.flags == flags
        assert s.is_executable is True
        assert s.is_writable is False
        assert s.virtual_size == 16
        assert s.raw_size == 16

    def test_multiple_sections_preserve_order(self):
        parsed = xbe_parse(
            build_minimal_xbe(
                sections=[
                    (".text", SECTION_FLAG_EXECUTABLE, b"\x90\x90"),
                    (".data", SECTION_FLAG_WRITABLE, b"\x01\x02\x03"),
                    (".rdata", 0, b"\xaa"),
                ]
            )
        )
        assert [s.name for s in parsed.sections] == [".text", ".data", ".rdata"]

    def test_section_flags_decoded(self):
        parsed = xbe_parse(
            build_minimal_xbe(
                sections=[
                    (".text", SECTION_FLAG_EXECUTABLE, b"\x00"),
                    (".data", SECTION_FLAG_WRITABLE, b"\x00"),
                ]
            )
        )
        text, data_section = parsed.sections
        assert text.is_executable and not text.is_writable
        assert data_section.is_writable and not data_section.is_executable


class TestSectionLookup:
    def test_find_existing_section(self):
        parsed = xbe_parse(
            build_minimal_xbe(
                sections=[
                    (".text", SECTION_FLAG_EXECUTABLE, b"\x90"),
                    (".data", SECTION_FLAG_WRITABLE, b"\x01"),
                ]
            )
        )
        text = xbe_section_find(parsed, ".text")
        assert text is not None and text.name == ".text"

    def test_find_missing_section_returns_none(self):
        parsed = xbe_parse(build_minimal_xbe(sections=[(".text", 0, b"\x90")]))
        assert xbe_section_find(parsed, ".nope") is None


class TestSectionRead:
    def test_section_bytes_round_trip(self):
        payload = b"hello there general kenobi"
        parsed = xbe_parse(build_minimal_xbe(sections=[(".text", SECTION_FLAG_EXECUTABLE, payload)]))
        section = xbe_section_find(parsed, ".text")
        assert xbe_section_read(parsed, section) == payload

    def test_section_bytes_for_each_of_multiple(self):
        sections = [
            (".text", SECTION_FLAG_EXECUTABLE, b"\xc3"),
            (".data", SECTION_FLAG_WRITABLE, b"\x42\x43"),
            (".rdata", 0, b"\xde\xad\xbe\xef"),
        ]
        parsed = xbe_parse(build_minimal_xbe(sections=sections))
        for name, _, expected in sections:
            section = xbe_section_find(parsed, name)
            assert xbe_section_read(parsed, section) == expected, name

    def test_section_bytes_truncated_data_raises(self):
        payload = b"\xaa" * 32
        data = build_minimal_xbe(sections=[(".text", 0, payload)])
        parsed = xbe_parse(data)
        section = parsed.sections[0]
        truncated = dataclasses.replace(parsed, data=data[: section.raw_address + 4])
        with pytest.raises(XbeFormatError, match="truncated"):
            xbe_section_read(truncated, section)
