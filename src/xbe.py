"""XBE (Xbox Executable) loader.

MVP: parse the header, enumerate sections, extract section bytes. No
kernel-thunk descrambling, no library version table, no certificate
parsing — those come later. Reference: Cxbx-Reloaded's src/common/xbe/Xbe.h.
"""

import struct
from dataclasses import dataclass, field
from pathlib import Path

XBE_MAGIC = b"XBEH"
HEADER_SIZE = 0x178
SECTION_HEADER_SIZE = 0x38

SECTION_FLAG_WRITABLE = 0x00000001
SECTION_FLAG_PRELOAD = 0x00000002
SECTION_FLAG_EXECUTABLE = 0x00000004
SECTION_FLAG_INSERTED_FILE = 0x00000008
SECTION_FLAG_HEAD_PAGE_RO = 0x00000010
SECTION_FLAG_TAIL_PAGE_RO = 0x00000020


class XbeFormatError(ValueError):
    """The byte stream is not a valid XBE."""


@dataclass(frozen=True)
class XbeHeader:
    base_address: int
    size_of_headers: int
    size_of_image: int
    size_of_image_header: int
    section_count: int
    section_headers_address: int
    entry_point_xor: int
    kernel_thunk_address_xor: int


@dataclass(frozen=True)
class XbeSection:
    name: str
    flags: int
    virtual_address: int
    virtual_size: int
    raw_address: int
    raw_size: int

    @property
    def is_executable(self) -> bool:
        return bool(self.flags & SECTION_FLAG_EXECUTABLE)

    @property
    def is_writable(self) -> bool:
        return bool(self.flags & SECTION_FLAG_WRITABLE)


@dataclass(frozen=True)
class ParsedXbe:
    header: XbeHeader
    sections: tuple[XbeSection, ...] = field(default_factory=tuple)
    data: bytes = b""


def is_xbe_magic_valid(data: bytes) -> bool:
    return len(data) >= 4 and data[:4] == XBE_MAGIC


def xbe_parse(data: bytes) -> ParsedXbe:
    """Parse an XBE byte stream into a ParsedXbe."""
    if not is_xbe_magic_valid(data):
        raise XbeFormatError(f"bad magic (expected {XBE_MAGIC!r}, got {data[:4]!r})")
    if len(data) < HEADER_SIZE:
        raise XbeFormatError(f"header truncated (need {HEADER_SIZE} bytes, got {len(data)})")

    header = _xbe_header_parse(data)
    sections = _xbe_sections_parse(data, header)
    return ParsedXbe(header=header, sections=sections, data=data)


def xbe_section_find(parsed: ParsedXbe, name: str) -> XbeSection | None:
    for section in parsed.sections:
        if section.name == name:
            return section
    return None


def xbe_section_read(parsed: ParsedXbe, section: XbeSection) -> bytes:
    """Return the raw bytes of a section from its file offset."""
    start = section.raw_address
    end = start + section.raw_size
    if end > len(parsed.data):
        raise XbeFormatError(
            f"section {section.name!r} truncated "
            f"(needs bytes [{start:#x}..{end:#x}], file is {len(parsed.data):#x} bytes)"
        )
    return parsed.data[start:end]


def xbe_load(path: Path | str) -> ParsedXbe:
    return xbe_parse(Path(path).read_bytes())


def _xbe_header_parse(data: bytes) -> XbeHeader:
    base_address = struct.unpack_from("<I", data, 0x104)[0]
    size_of_headers = struct.unpack_from("<I", data, 0x108)[0]
    size_of_image = struct.unpack_from("<I", data, 0x10C)[0]
    size_of_image_header = struct.unpack_from("<I", data, 0x110)[0]
    section_count = struct.unpack_from("<I", data, 0x11C)[0]
    section_headers_address = struct.unpack_from("<I", data, 0x120)[0]
    entry_point_xor = struct.unpack_from("<I", data, 0x128)[0]
    kernel_thunk_address_xor = struct.unpack_from("<I", data, 0x158)[0]

    return XbeHeader(
        base_address=base_address,
        size_of_headers=size_of_headers,
        size_of_image=size_of_image,
        size_of_image_header=size_of_image_header,
        section_count=section_count,
        section_headers_address=section_headers_address,
        entry_point_xor=entry_point_xor,
        kernel_thunk_address_xor=kernel_thunk_address_xor,
    )


def _xbe_sections_parse(data: bytes, header: XbeHeader) -> tuple[XbeSection, ...]:
    if header.section_count == 0:
        return ()

    table_offset = header.section_headers_address - header.base_address
    table_end = table_offset + SECTION_HEADER_SIZE * header.section_count
    if table_end > len(data):
        raise XbeFormatError(
            f"section table truncated "
            f"(needs bytes [{table_offset:#x}..{table_end:#x}], file is {len(data):#x} bytes)"
        )

    sections = []
    for i in range(header.section_count):
        entry_offset = table_offset + SECTION_HEADER_SIZE * i
        flags = struct.unpack_from("<I", data, entry_offset + 0x00)[0]
        virtual_address = struct.unpack_from("<I", data, entry_offset + 0x04)[0]
        virtual_size = struct.unpack_from("<I", data, entry_offset + 0x08)[0]
        raw_address = struct.unpack_from("<I", data, entry_offset + 0x0C)[0]
        raw_size = struct.unpack_from("<I", data, entry_offset + 0x10)[0]
        section_name_address = struct.unpack_from("<I", data, entry_offset + 0x14)[0]

        name = _xbe_section_name_read(data, header, section_name_address)
        sections.append(
            XbeSection(
                name=name,
                flags=flags,
                virtual_address=virtual_address,
                virtual_size=virtual_size,
                raw_address=raw_address,
                raw_size=raw_size,
            )
        )

    return tuple(sections)


def _xbe_section_name_read(data: bytes, header: XbeHeader, virtual_address: int) -> str:
    """Read a null-terminated ASCII name from the header region."""
    file_offset = virtual_address - header.base_address
    if file_offset < 0 or file_offset >= len(data):
        return ""

    end = data.find(b"\x00", file_offset)
    if end == -1 or end - file_offset > 64:
        return ""

    return data[file_offset:end].decode("ascii", errors="replace")
