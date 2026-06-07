"""Tests for the XDVDFS (Xbox disc image / XISO) reader and extractor.

The format is the Xbox "Game Disc File System": a 0x800-byte sector grid whose
volume descriptor lives at sector 32 and opens with the ASCII magic
``MICROSOFT*XBOX*MEDIA``. The descriptor points at a root directory, which is a
binary tree of fixed-14-byte-plus-name entries; left/right children are stored
as dword offsets within the directory's own byte table (0 = no child). Retail
rips prepend one of a few fixed "video partition" base offsets before sector 0.

These tests synthesize tiny in-memory images at byte level rather than shipping
a multi-GB game disc; format conformance is the contract under test.
"""

from io import BytesIO

import pytest
from hypothesis import given
from hypothesis import strategies as st

from src.formats.xiso import (
	SECTOR_SIZE,
	XisoEntry,
	XisoFormatError,
	_directory_table_parse,
	xiso_default_xbe_extract,
	xiso_entry_read,
	xiso_file_find,
	xiso_image_file_extract,
	xiso_image_root_list,
	xiso_root_entries,
	xiso_volume_read,
)
from tests.formats._xiso_helpers import (
	xiso_directory_table_build as _directory_table_build,
)
from tests.formats._xiso_helpers import (
	xiso_image_build as _xiso_build,
)

_ROOT_SECTOR = 33
_ATTR_DIRECTORY = 0x10

_NAME = st.text(
	alphabet=st.characters(min_codepoint=0x21, max_codepoint=0x7E, blacklist_characters="/\\"),
	min_size=1,
	max_size=20,
)


# ── Volume descriptor ───────────────────────────────────────────────────────
class TestVolumeRead:
	def test_volume_read_locates_root_example(self):
		img = _xiso_build({"default.xbe": b"XBEH\x00\x00\x00\x00"})
		vol = xiso_volume_read(BytesIO(img))
		assert vol.base_offset == 0
		assert vol.root_sector == _ROOT_SECTOR

	def test_volume_read_detects_shifted_base_example(self):
		shift = 4 * SECTOR_SIZE
		img = _xiso_build({"default.xbe": b"XBEH"}, base_offset=shift)
		vol = xiso_volume_read(BytesIO(img), base_offsets=(0, shift))
		assert vol.base_offset == shift

	def test_volume_read_raises_without_magic_example(self):
		with pytest.raises(XisoFormatError):
			xiso_volume_read(BytesIO(bytes(40 * SECTOR_SIZE)))

	def test_volume_read_raises_on_truncated_image_example(self):
		with pytest.raises(XisoFormatError):
			xiso_volume_read(BytesIO(b"too short"))


# ── Directory table (pure tree walk) ────────────────────────────────────────
class TestDirectoryTableParse:
	def test_directory_table_parse_collects_all_entries_example(self):
		table = _directory_table_build(
			[("a.xbe", 34, 10, 0x00), ("b.xbe", 35, 20, 0x00), ("maps", 36, 2048, _ATTR_DIRECTORY)]
		)
		by_name = {e.name: e for e in _directory_table_parse(table)}
		assert set(by_name) == {"a.xbe", "b.xbe", "maps"}
		assert by_name["b.xbe"].sector == 35
		assert by_name["b.xbe"].size == 20
		assert by_name["maps"].is_directory
		assert not by_name["a.xbe"].is_directory

	@given(st.lists(_NAME, min_size=1, max_size=30, unique_by=lambda s: s.upper()))
	def test_directory_table_parse_recovers_every_name_oracle(self, names):
		metas = [(n, 34 + i, i, 0x00) for i, n in enumerate(names)]
		parsed = _directory_table_parse(_directory_table_build(metas))
		assert {e.name for e in parsed} == set(names)

	def test_directory_table_parse_ignores_padding_only_table_example(self):
		assert _directory_table_parse(b"\xff" * 16) == []


# ── Lookup ──────────────────────────────────────────────────────────────────
class TestFileFind:
	def test_file_find_is_case_insensitive_example(self):
		entries = [XisoEntry("Default.xbe", 34, 8, 0x00), XisoEntry("update.xbe", 40, 4, 0x00)]
		assert xiso_file_find(entries, "DEFAULT.XBE").sector == 34

	def test_file_find_missing_returns_none_example(self):
		assert xiso_file_find([XisoEntry("a", 1, 1, 0)], "b") is None


# ── Streaming extraction ────────────────────────────────────────────────────
class TestEntryRead:
	@given(st.binary(min_size=0, max_size=5000))
	def test_entry_read_roundtrips_content_invertible(self, content):
		img = _xiso_build({"default.xbe": content})
		stream = BytesIO(img)
		vol = xiso_volume_read(stream)
		entry = xiso_file_find(xiso_root_entries(stream, vol), "default.xbe")
		assert b"".join(xiso_entry_read(stream, vol, entry)) == content

	def test_entry_read_honors_small_chunks_example(self):
		content = bytes(range(256)) * 10
		img = _xiso_build({"f.bin": content})
		stream = BytesIO(img)
		vol = xiso_volume_read(stream)
		entry = xiso_file_find(xiso_root_entries(stream, vol), "f.bin")
		chunks = list(xiso_entry_read(stream, vol, entry, chunk_size=64))
		assert max(len(c) for c in chunks) <= 64
		assert b"".join(chunks) == content


# ── Path-level convenience ──────────────────────────────────────────────────
class TestImagePathHelpers:
	def test_image_root_list_names_example(self, tmp_path):
		iso = tmp_path / "game.iso"
		iso.write_bytes(_xiso_build({"default.xbe": b"XBEH", "update.xbe": b"u"}, dirs=("media",)))
		names = {e.name for e in xiso_image_root_list(iso)}
		assert names == {"default.xbe", "update.xbe", "media"}

	def test_default_xbe_extract_writes_file_example(self, tmp_path):
		payload = b"XBEH" + bytes(5000)
		iso = tmp_path / "game.iso"
		iso.write_bytes(_xiso_build({"default.xbe": payload, "dashupdate.xbe": b"x"}))
		dest = tmp_path / "out" / "halo.xbe"
		written = xiso_default_xbe_extract(iso, dest)
		assert written == len(payload)
		assert dest.read_bytes() == payload

	def test_image_file_extract_missing_raises_example(self, tmp_path):
		iso = tmp_path / "game.iso"
		iso.write_bytes(_xiso_build({"default.xbe": b"XBEH"}))
		with pytest.raises(XisoFormatError):
			xiso_image_file_extract(iso, "nope.xbe", tmp_path / "x")
