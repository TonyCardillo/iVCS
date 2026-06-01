"""Tests for the !<arch> static-library parser."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from src.formats.archive import ARCHIVE_MAGIC, ArchiveError, archive_members


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
	# Reading object members (single, multiple, skipping linker tables, 2-byte
	# alignment) is covered by TestArchiveRoundTrip. What stays pins behaviour the
	# round-trip generator never produces: a bad-magic rejection, and a longname-
	# referenced object ("/4") that must be kept rather than skipped like "/".
	def test_rejects_bad_magic_example(self):
		with pytest.raises(ArchiveError):
			archive_members(b"not an archive")

	def test_longname_referenced_object_is_kept_example(self):
		# "/4" names an object whose real name lives in the longnames member;
		# it is a real object and must not be skipped like "/" or "//".
		ar = _archive([("/4", b"\xc3")])
		members = archive_members(ar)
		assert len(members) == 1
		assert members[0].data == b"\xc3"


# --- Property tests --------------------------------------------------------
# The examples above each pin one member shape; this asserts the parse law they
# witness: archive_members inverts the writer for any member sequence — order,
# data, and 2-byte alignment preserved — keeping exactly the non-linker members
# with their trailing '/' stripped.

_NAME = st.text(
	alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._",
	min_size=1,
	max_size=14,
)


@st.composite
def _member_list(draw):
	out: list[tuple[str, bytes]] = []
	for _ in range(draw(st.integers(0, 6))):
		if draw(st.integers(0, 4)) == 0:
			# A linker symbol-table member that must be skipped.
			out.append((draw(st.sampled_from(["/", "//"])), draw(st.binary(max_size=8))))
		else:
			name = draw(_NAME) + ("/" if draw(st.booleans()) else "")
			out.append((name, draw(st.binary(max_size=40))))
	return out


class TestArchiveRoundTrip:
	@given(raw=_member_list())
	def test_round_trip_keeps_object_members_in_order(self, raw):
		got = archive_members(_archive(raw))
		expected = [(n.rstrip("/"), d) for n, d in raw if n not in ("/", "//")]
		assert [(m.name, m.data) for m in got] == expected
