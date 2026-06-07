"""XDVDFS (Xbox disc image / XISO) reader and file extractor.

An Xbox game disc is a 0x800-byte sector grid carrying the "Game Disc File
System". Its volume descriptor sits at sector 32 and opens with the ASCII magic
``MICROSOFT*XBOX*MEDIA``; it names a root directory, itself a binary search tree
of fixed-header-plus-name entries whose left/right children are stored as dword
offsets within the directory's own byte table. Retail rips prepend one of a few
fixed "video partition" base offsets ahead of sector 0, so the descriptor is
probed at each known offset.

Images run to several gigabytes, so files are streamed sector-by-sector rather
than read whole; only the (small) directory tables are materialized in memory.

Reference: xemu / extract-xiso, https://xboxdevwiki.net/Xbox_Game_Disc.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from struct import unpack_from
from typing import BinaryIO

SECTOR_SIZE = 0x800
XISO_MAGIC = b"MICROSOFT*XBOX*MEDIA"
_VOLUME_DESCRIPTOR_SECTOR = 32
_ENTRY_HEADER_SIZE = 14  # left, right, sector, size, attrs, name_len before the name
_ATTRIBUTE_DIRECTORY = 0x10
_DEFAULT_CHUNK_SIZE = 1 << 20

# Known image base offsets (bytes before sector 0): trimmed/redump, XGD1, XGD2,
# XGD3. The descriptor's magic is checked at each until one matches.
XISO_BASE_OFFSETS: tuple[int, ...] = (0x00000000, 0x18300000, 0x0FD90000, 0x02080000)


class XisoFormatError(ValueError):
	"""The byte stream is not a recognizable XDVDFS image, or a read ran short."""


@dataclass(frozen=True)
class XisoEntry:
	"""One directory entry: a file or subdirectory at a given start sector."""

	name: str
	sector: int
	size: int
	attributes: int

	@property
	def is_directory(self) -> bool:
		return bool(self.attributes & _ATTRIBUTE_DIRECTORY)


@dataclass(frozen=True)
class XisoVolume:
	"""A located volume: the base offset its sectors are measured from, plus the
	root directory's start sector and byte size."""

	base_offset: int
	root_sector: int
	root_size: int


def _read_at(stream: BinaryIO, offset: int, count: int) -> bytes:
	stream.seek(offset)
	data = stream.read(count)
	if len(data) != count:
		raise XisoFormatError(f"short read at {offset:#x}: wanted {count} bytes, got {len(data)}")
	return data


def xiso_volume_read(
	stream: BinaryIO, *, base_offsets: Sequence[int] = XISO_BASE_OFFSETS
) -> XisoVolume:
	"""Probe each known base offset for the volume descriptor and return the
	located volume. Raises XisoFormatError if none carries the magic."""
	for base in base_offsets:
		descriptor_offset = base + _VOLUME_DESCRIPTOR_SECTOR * SECTOR_SIZE
		try:
			descriptor = _read_at(stream, descriptor_offset, SECTOR_SIZE)
		except XisoFormatError:
			continue  # image too short for this base — try the next
		if descriptor[: len(XISO_MAGIC)] != XISO_MAGIC:
			continue
		root_sector, root_size = unpack_from("<II", descriptor, 0x14)
		return XisoVolume(base_offset=base, root_sector=root_sector, root_size=root_size)
	raise XisoFormatError(
		f"no XDVDFS volume descriptor (magic {XISO_MAGIC!r}) at any of base offsets "
		f"{[hex(b) for b in base_offsets]}"
	)


def _directory_table_parse(table: bytes) -> list[XisoEntry]:
	"""Walk a directory's binary-tree byte table into a flat entry list.

	Children are dword offsets within `table`; 0 (and the 0xFFFF padding
	sentinel) mean "no child". Traversal is seeded at the root entry (offset 0),
	guarded against malformed/out-of-range offsets and cycles, so padding bytes
	left over at sector boundaries are simply unreachable.
	"""
	entries: list[XisoEntry] = []
	stack = [0]
	seen: set[int] = set()
	while stack:
		dword_offset = stack.pop()
		if dword_offset in seen:
			continue
		seen.add(dword_offset)
		offset = dword_offset * 4
		if offset + _ENTRY_HEADER_SIZE > len(table):
			continue
		left, right, sector, size, attrs, name_len = unpack_from("<HHIIBB", table, offset)
		name_end = offset + _ENTRY_HEADER_SIZE + name_len
		if name_len == 0 or name_end > len(table):
			continue  # padding or truncated entry
		name = table[offset + _ENTRY_HEADER_SIZE : name_end].decode("latin-1")
		entries.append(XisoEntry(name=name, sector=sector, size=size, attributes=attrs))
		stack.extend(child for child in (left, right) if child not in (0x0000, 0xFFFF))
	return entries


def xiso_directory_entries(
	stream: BinaryIO, volume: XisoVolume, *, sector: int, size: int
) -> list[XisoEntry]:
	"""Read and parse the directory table at `sector` (spanning `size` bytes)."""
	offset = volume.base_offset + sector * SECTOR_SIZE
	return _directory_table_parse(_read_at(stream, offset, size))


def xiso_root_entries(stream: BinaryIO, volume: XisoVolume) -> list[XisoEntry]:
	"""List the volume's root directory."""
	return xiso_directory_entries(stream, volume, sector=volume.root_sector, size=volume.root_size)


def xiso_file_find(entries: Sequence[XisoEntry], name: str) -> XisoEntry | None:
	"""Find an entry by name, case-insensitively (disc filenames are not
	case-sensitive). Returns None if absent."""
	target = name.lower()
	return next((e for e in entries if e.name.lower() == target), None)


def xiso_entry_read(
	stream: BinaryIO,
	volume: XisoVolume,
	entry: XisoEntry,
	*,
	chunk_size: int = _DEFAULT_CHUNK_SIZE,
) -> Iterator[bytes]:
	"""Yield `entry`'s bytes in `chunk_size` pieces, seeking once to its start.

	Streaming keeps multi-GB images off the heap; the caller writes each chunk
	straight to disk (or joins them for small files)."""
	stream.seek(volume.base_offset + entry.sector * SECTOR_SIZE)
	remaining = entry.size
	while remaining > 0:
		chunk = stream.read(min(chunk_size, remaining))
		if not chunk:
			raise XisoFormatError(
				f"image ended {remaining} bytes before {entry.name!r} was complete"
			)
		remaining -= len(chunk)
		yield chunk


def xiso_entry_extract(
	stream: BinaryIO,
	volume: XisoVolume,
	entry: XisoEntry,
	dest: Path | str,
	*,
	chunk_size: int = _DEFAULT_CHUNK_SIZE,
) -> int:
	"""Stream `entry` out to `dest`, creating parent dirs. Returns bytes written."""
	dest = Path(dest)
	dest.parent.mkdir(parents=True, exist_ok=True)
	written = 0
	with dest.open("wb") as out:
		for chunk in xiso_entry_read(stream, volume, entry, chunk_size=chunk_size):
			out.write(chunk)
			written += len(chunk)
	return written


# ── Path-level convenience (open, locate, act, close) ────────────────────────
def xiso_image_root_list(iso_path: Path | str) -> list[XisoEntry]:
	"""List the root directory of the image at `iso_path`."""
	with Path(iso_path).open("rb") as stream:
		return xiso_root_entries(stream, xiso_volume_read(stream))


def xiso_image_file_extract(iso_path: Path | str, name: str, dest: Path | str) -> int:
	"""Extract the root-level file `name` from `iso_path` to `dest`. Returns
	bytes written; raises XisoFormatError if no such file (or it's a directory)."""
	with Path(iso_path).open("rb") as stream:
		volume = xiso_volume_read(stream)
		entry = xiso_file_find(xiso_root_entries(stream, volume), name)
		if entry is None or entry.is_directory:
			raise XisoFormatError(f"no file named {name!r} at the root of {Path(iso_path).name}")
		return xiso_entry_extract(stream, volume, entry, dest)


def xiso_default_xbe_extract(iso_path: Path | str, dest: Path | str) -> int:
	"""Extract the game's ``default.xbe`` from `iso_path` to `dest`."""
	return xiso_image_file_extract(iso_path, "default.xbe", dest)
