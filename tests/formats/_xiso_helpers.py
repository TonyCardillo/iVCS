"""Build minimal valid XDVDFS (XISO) images for tests — the inverse of the
xiso reader. Shared by tests/formats/test_xiso.py and tests/webui/test_webui.py
so neither reaches into the other for a disc-image fixture.

Layout: volume descriptor at sector 32, root directory table at sector 33, file
data from sector 34. The directory is a degenerate-but-valid right-spine BST
(sorted ascending, each entry's right child linked to the next) — enough for the
reader's in-order walk without balancing logic here.
"""

import struct

from src.formats.xiso import SECTOR_SIZE, XISO_MAGIC

_VD_SECTOR = 32
_ROOT_SECTOR = 33
_FIRST_DATA_SECTOR = 34
_ATTR_DIRECTORY = 0x10


def _entry_encode(name: str, sector: int, size: int, attrs: int, left: int, right: int) -> bytes:
	nb = name.encode("latin-1")
	raw = struct.pack("<HHIIBB", left, right, sector, size, attrs, len(nb)) + nb
	return raw + b"\xff" * (-len(raw) % 4)  # entries are dword-aligned, 0xFF padded


def xiso_directory_table_build(metas: list[tuple[str, int, int, int]]) -> bytes:
	"""Lay `metas` (name, sector, size, attrs) out as a valid right-spine BST."""
	items = sorted(metas, key=lambda m: m[0].upper())
	dword_offsets: list[int] = []
	cursor = 0
	for name, _sector, _size, _attrs in items:
		dword_offsets.append(cursor // 4)
		entry_len = 14 + len(name.encode("latin-1"))
		cursor += entry_len + (-entry_len % 4)
	table = b""
	for i, (name, sector, size, attrs) in enumerate(items):
		right = dword_offsets[i + 1] if i + 1 < len(items) else 0
		table += _entry_encode(name, sector, size, attrs, left=0, right=right)
	return table


def xiso_image_build(
	files: dict[str, bytes], *, base_offset: int = 0, dirs: tuple[str, ...] = ()
) -> bytes:
	"""Assemble a minimal valid XISO holding `files` (and empty `dirs`) at the
	root, optionally shifted by a fixed `base_offset` (a retail rip's preamble)."""
	metas: list[tuple[str, int, int, int]] = []
	blobs: list[tuple[int, bytes]] = []
	sector = _FIRST_DATA_SECTOR
	for name, content in files.items():
		metas.append((name, sector, len(content), 0x00))
		blobs.append((sector, content))
		sector += max(1, (len(content) + SECTOR_SIZE - 1) // SECTOR_SIZE)
	for name in dirs:
		metas.append((name, sector, SECTOR_SIZE, _ATTR_DIRECTORY))
		sector += 1

	table = xiso_directory_table_build(metas)
	img = bytearray(base_offset + sector * SECTOR_SIZE)

	vd = base_offset + _VD_SECTOR * SECTOR_SIZE
	img[vd : vd + len(XISO_MAGIC)] = XISO_MAGIC
	struct.pack_into("<II", img, vd + 0x14, _ROOT_SECTOR, len(table))
	img[vd + 0x7EC : vd + 0x800] = XISO_MAGIC  # trailing magic

	t = base_offset + _ROOT_SECTOR * SECTOR_SIZE
	img[t : t + len(table)] = table
	for sec, content in blobs:
		o = base_offset + sec * SECTOR_SIZE
		img[o : o + len(content)] = content
	return bytes(img)
