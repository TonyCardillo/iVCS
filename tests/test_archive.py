"""Tests for the !<arch> static-library parser."""

import pytest

from src.archive import ARCHIVE_MAGIC, ArchiveError, archive_members


def _member(name: str, data: bytes) -> bytes:
	header = (
		name.ljust(16).encode("ascii")
		+ b" " * 12  # date
		+ b" " * 6  # uid
		+ b" " * 6  # gid
		+ b" " * 8  # mode
		+ str(len(data)).ljust(10).encode("ascii")  # size
		+ b"`\n"  # end marker
	)
	assert len(header) == 60
	blob = header + data
	if len(data) % 2:  # 2-byte alignment pad
		blob += b"\n"
	return blob


def _archive(members: list[tuple[str, bytes]]) -> bytes:
	return ARCHIVE_MAGIC + b"".join(_member(n, d) for n, d in members)


class TestArchiveMembers:
	def test_rejects_bad_magic(self):
		with pytest.raises(ArchiveError):
			archive_members(b"not an archive")

	def test_reads_a_single_object_member(self):
		ar = _archive([("foo.obj/", b"\x01\x02\x03\x04")])
		members = archive_members(ar)
		assert len(members) == 1
		assert members[0].name == "foo.obj"
		assert members[0].data == b"\x01\x02\x03\x04"

	def test_skips_linker_symbol_table_members(self):
		ar = _archive(
			[
				("/", b"\x00\x00\x00\x00"),  # first linker member
				("/", b"\x00\x00\x00\x00"),  # second linker member
				("//", b"longnames\x00"),  # longnames member
				("bar.obj/", b"\xc3"),  # the only real object
			]
		)
		members = archive_members(ar)
		assert [m.name for m in members] == ["bar.obj"]

	def test_odd_sized_member_is_padded(self):
		# A 1-byte member forces the 2-byte alignment pad; the next member must
		# still be found at the correct offset.
		ar = _archive([("a.obj/", b"\xc3"), ("b.obj/", b"\x90\x90")])
		members = archive_members(ar)
		assert [(m.name, m.data) for m in members] == [("a.obj", b"\xc3"), ("b.obj", b"\x90\x90")]

	def test_longname_referenced_object_is_kept(self):
		# "/123" names an object whose real name lives in the longnames member;
		# it is a real object and must not be skipped like "/" or "//".
		ar = _archive([("/4", b"\xc3")])
		members = archive_members(ar)
		assert len(members) == 1
		assert members[0].data == b"\xc3"
