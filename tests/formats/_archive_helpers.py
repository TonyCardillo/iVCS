"""Build `!<arch>` static-library blobs for tests — the inverse of archive_members.

Shared by tests/formats/test_archive.py and tests/analysis/test_libmatch.py so
neither has to reach into the other's internals for a fixture.
"""

from src.formats.archive import ARCHIVE_MAGIC


def ar_member(name: str, data: bytes) -> bytes:
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


def ar_blob(members: list[tuple[str, bytes]]) -> bytes:
	return ARCHIVE_MAGIC + b"".join(ar_member(n, d) for n, d in members)
