"""Match a game's functions against XDK static-library signatures.

The XDK static libraries are the exact SDK code a title linked, so most of an
image's "SDK" functions are near-copies of a library object. We fingerprint each
library function and look the game's functions up against that signature DB,
recovering names for the SDK portion and leaving the game-specific code as the
real decompilation target — the FLIRT / signature-database idea, reusing the
coddog-style fingerprint index.

Matching is on the **relocation-invariant** hashes (opcode skeleton and operand
shape), never raw bytes: the linker patches a function's call targets and
absolute addresses when it places it in the image, so the game's bytes differ
from the library object's — but the opcodes and operand types are identical.

Functions are located by symbol type (`IMAGE_SYM_TYPE_FUNCTION`), not section
name, because library code sections are not always called `.text` (d3d8 uses
`D3D`/`D3D_RD`).
"""

import json
import struct
from dataclasses import dataclass
from pathlib import Path

from src.archive import archive_members
from src.coff import IMAGE_SYM_CLASS_EXTERNAL, IMAGE_SYM_TYPE_FUNCTION
from src.coff_read import CoffObject, coff_object_read
from src.fingerprint import Fingerprint, function_fingerprint


@dataclass(frozen=True)
class LibrarySignature:
	name: str
	opcode_hash: int
	equiv_hash: int
	size: int


def _object_function_fingerprints(obj: CoffObject) -> list[tuple[str, Fingerprint]]:
	"""Fingerprint every named function defined in a library object.

	A function is an external symbol of type FUNCTION; its bytes run from the
	symbol's offset to the next function in the same section (or the section end),
	which covers both one-function-per-section COMDAT objects and packed sections.
	"""
	by_section: dict[int, list[tuple[int, str]]] = {}
	for sym in obj.symbols:
		if (
			sym.storage_class == IMAGE_SYM_CLASS_EXTERNAL
			and sym.type == IMAGE_SYM_TYPE_FUNCTION
			and 1 <= sym.section_number <= len(obj.sections)
		):
			by_section.setdefault(sym.section_number, []).append((sym.value, sym.name))

	out: list[tuple[str, Fingerprint]] = []
	for section_number, syms in by_section.items():
		section = obj.sections[section_number - 1]
		syms.sort()
		for i, (value, name) in enumerate(syms):
			end = syms[i + 1][0] if i + 1 < len(syms) else len(section.raw)
			body = section.raw[value:end]
			if body:
				out.append((name, function_fingerprint(name, 0, len(body), body)))
	return out


def library_signatures(archive_bytes: bytes) -> list[LibrarySignature]:
	"""Fingerprint every function in an `!<arch>` static library.

	Members that don't parse as COFF (import descriptors, e.g. xboxkrnl.lib) are
	skipped — those are resolved through the kernel thunk table, not matched here.
	"""
	sigs: list[LibrarySignature] = []
	for member in archive_members(archive_bytes):
		try:
			obj = coff_object_read(member.data)
		except (ValueError, IndexError, struct.error):
			continue  # import descriptors and non-COFF members aren't matchable
		for name, fp in _object_function_fingerprints(obj):
			sigs.append(LibrarySignature(name, fp.opcode_hash, fp.equiv_hash, fp.size))
	return sigs


@dataclass(frozen=True)
class SignatureIndex:
	by_equiv: dict[int, frozenset[str]]
	by_opcode: dict[int, frozenset[str]]


def signature_index(signatures: list[LibrarySignature]) -> SignatureIndex:
	by_equiv: dict[int, set[str]] = {}
	by_opcode: dict[int, set[str]] = {}
	for sig in signatures:
		by_equiv.setdefault(sig.equiv_hash, set()).add(sig.name)
		by_opcode.setdefault(sig.opcode_hash, set()).add(sig.name)
	return SignatureIndex(
		by_equiv={h: frozenset(v) for h, v in by_equiv.items()},
		by_opcode={h: frozenset(v) for h, v in by_opcode.items()},
	)


@dataclass(frozen=True)
class LibMatch:
	"""A game function identified against the library DB. A single `names` entry
	is a confident identification; several means the signature is ambiguous
	(common for tiny functions that share an opcode skeleton)."""

	function: str
	va: int
	size: int
	names: tuple[str, ...]
	confidence: str  # "exact" (operand shape matched) | "skeleton" (opcodes only)

	@property
	def is_confident(self) -> bool:
		return len(self.names) == 1


def match_fingerprints(
	game_fingerprints: list[Fingerprint],
	index: SignatureIndex,
	*,
	min_size: int = 16,
) -> list[LibMatch]:
	"""Match game function fingerprints against the library signature index.

	Prefers an operand-shape (`equiv`) match; falls back to the opcode skeleton.
	Functions smaller than `min_size` bytes are skipped — their skeletons collide
	with hundreds of unrelated stubs, so a match would be meaningless.
	"""
	matches: list[LibMatch] = []
	for fp in game_fingerprints:
		if fp.size < min_size:
			continue
		names = index.by_equiv.get(fp.equiv_hash)
		confidence = "exact"
		if not names:
			names = index.by_opcode.get(fp.opcode_hash)
			confidence = "skeleton"
		if names:
			matches.append(
				LibMatch(fp.name, fp.va, fp.size, tuple(sorted(names)), confidence)
			)
	return matches


# --- Persistence: an SDK manifest the coverage report and web UI consume -----
#
# Only *confident* (single-name) matches are persisted as the excludable SDK set:
# excluding a function from the real decomp target must be high-precision, so an
# ambiguous skeleton-shared match is left out rather than risk hiding game code.


def sdk_manifest_write(path: Path, matches: list[LibMatch]) -> int:
	"""Write the confident SDK identifications to `path` as JSON; return the count."""
	entries = [
		{"va": f"0x{m.va:08X}", "name": m.names[0], "size": m.size, "confidence": m.confidence}
		for m in matches
		if m.is_confident
	]
	path.write_text(json.dumps({"sdk": entries}, indent=2) + "\n")
	return len(entries)


def sdk_manifest_load(path: Path) -> dict[int, str]:
	"""Load an SDK manifest into {virtual_address: library_name}."""
	raw = json.loads(path.read_text())
	return {int(entry["va"], 16): entry["name"] for entry in raw.get("sdk", [])}
