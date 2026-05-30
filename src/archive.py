"""Parse a Microsoft/Unix `!<arch>` static-library archive into its members.

XDK static libraries (`libcmt`, `libcp`, `d3d8`, ...) are `!<arch>` archives of
COFF objects — the actual SDK code a game statically links. The library matcher
reads each object's functions to fingerprint them, so it only needs the member
object bytes; the linker symbol-table members (`/` and `//`) carry no code and
are skipped.

Member layout: an 8-byte magic, then per member a 60-byte ASCII header (name,
date, uid, gid, mode, size, and a `` `\n `` end marker) followed by `size` bytes
of data, padded to a 2-byte boundary.
"""

from dataclasses import dataclass

ARCHIVE_MAGIC = b"!<arch>\n"
_HEADER_SIZE = 60
_NAME_FIELD = slice(0, 16)
_SIZE_FIELD = slice(48, 58)
_END_FIELD = slice(58, 60)


class ArchiveError(ValueError):
	pass


@dataclass(frozen=True)
class ArchiveMember:
	name: str
	data: bytes


def archive_members(data: bytes) -> list[ArchiveMember]:
	"""Parse an `!<arch>` archive, returning its object members (linker
	symbol-table members `/` and `//` are skipped)."""
	if data[: len(ARCHIVE_MAGIC)] != ARCHIVE_MAGIC:
		raise ArchiveError("not an !<arch> archive (bad magic)")

	members: list[ArchiveMember] = []
	pos = len(ARCHIVE_MAGIC)
	while pos + _HEADER_SIZE <= len(data):
		header = data[pos : pos + _HEADER_SIZE]
		if header[_END_FIELD] != b"`\n":
			break  # not a valid member header — stop rather than misread
		name = header[_NAME_FIELD].rstrip(b" ").decode("ascii", "replace")
		try:
			size = int(header[_SIZE_FIELD].decode("ascii").strip())
		except ValueError:
			break

		body_start = pos + _HEADER_SIZE
		body = data[body_start : body_start + size]
		pos = body_start + size
		if pos % 2:  # members are 2-byte aligned
			pos += 1

		if name in ("/", "//"):
			continue  # linker symbol table / longnames — no code
		members.append(ArchiveMember(name=name.rstrip("/"), data=body))
	return members
