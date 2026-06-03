"""Binary-agnostic string cross-referencing for a function.

Recovers the string literals a function references — debug formats, error
messages, script/identifier names — by disassembling it and checking every
immediate and absolute-memory operand against the read-only data sections.

XBEs load at a fixed base and carry no relocation table, so data references are
baked into the code as raw 32-bit addresses (`push offset`, `mov reg, offset`,
`mov/lea reg, [abs]`). We treat any operand value that lands on a decodable
string in a non-executable section as a reference. No platform- or game-specific
knowledge — works on any parsed XBE, the basis for a project-wide naming-hint
"quick start" for a future reverse engineer.
"""

import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass

import capstone
from capstone import x86

from src.formats.xbe import (
	ParsedXbe,
	XbeFormatError,
	xbe_function_carve,
	xbe_section_containing_va,
	xbe_section_read,
)

_PRINTABLE = frozenset(range(0x20, 0x7F))


def string_at_va(
	parsed: ParsedXbe,
	va: int,
	*,
	min_len: int = 4,
	max_len: int = 200,
) -> str | None:
	"""Decode a NUL-terminated printable C string at `va`, or None.

	None when `va` is outside every section, isn't NUL-terminated within
	`max_len`, is shorter than `min_len`, or contains a non-printable byte.

	Note: we deliberately do NOT gate on the section's executable flag. XBEs
	routinely mark `.rdata`/`.data` executable, so that bit is no signal for
	"this is code"; the printable + NUL-terminated + length test is what
	separates a real string from a stray code/pointer address.
	"""
	section = xbe_section_containing_va(parsed, va)
	if section is None:
		return None
	data = xbe_section_read(parsed, section)
	start = va - section.virtual_address
	if start < 0 or start >= len(data):
		return None
	end = data.find(b"\x00", start, start + max_len + 1)
	if end == -1:
		return None
	raw = data[start:end]
	if len(raw) < min_len:
		return None
	if any(b not in _PRINTABLE for b in raw):
		return None
	return raw.decode("latin1")


def function_string_refs(
	parsed: ParsedXbe,
	va: int,
	size: int,
	*,
	min_len: int = 4,
	max_len: int = 200,
) -> tuple[str, ...]:
	"""The distinct string literals `va` references, in first-seen order.

	Scans immediate operands and absolute-memory displacements (base/index 0)
	of every instruction in the function body; keeps those that resolve to a
	decodable string in read-only data.

	A function that can't be carved (outside a section, past raw bytes) has no
	recoverable refs — return empty rather than aborting, mirroring
	project_fingerprints so a single bad function never breaks an autoname pass.
	"""
	try:
		body = xbe_function_carve(parsed, va, size)
	except XbeFormatError:
		return ()

	md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
	md.detail = True

	out: list[str] = []
	seen: set[str] = set()
	for instr in md.disasm(body, va):
		for candidate in _operand_address_candidates(instr):
			text = string_at_va(parsed, candidate, min_len=min_len, max_len=max_len)
			if text is None or text in seen:
				continue
			seen.add(text)
			out.append(text)
	return tuple(out)


def _operand_address_candidates(instr) -> list[int]:
	"""Absolute-address operand values worth probing: immediates and memory
	displacements with no base/index register (i.e. `[abs]`)."""
	candidates: list[int] = []
	for op in instr.operands:
		if op.type == x86.X86_OP_IMM:
			candidates.append(op.imm & 0xFFFFFFFF)
		elif op.type == x86.X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0:
			candidates.append(op.mem.disp & 0xFFFFFFFF)
	return candidates


@dataclass(frozen=True)
class NameSuggestion:
	va: int
	label: str


def function_autoname_label(parsed: ParsedXbe, va: int, size: int) -> str | None:
	"""The high-confidence auto-name label for a function, or None.

	Only when the function references *exactly one* string and it sanitizes to a
	usable label — the unambiguous case (e.g. a tiny accessor stub that returns a
	single name string). More than one referenced string is left for human
	judgement (surfaced as click-to-adopt hints, not auto-applied).
	"""
	refs = function_string_refs(parsed, va, size)
	if len(refs) != 1:
		return None
	return string_label_sanitize(refs[0])


def autoname_resolve(
	candidates: Iterable[tuple[int, str]],
	*,
	taken_labels: frozenset[str] = frozenset(),
) -> list[NameSuggestion]:
	"""Filter (va, label) candidates down to the safe-to-apply set.

	Drops any label that is not unique among the candidates (two functions
	wanting the same name is ambiguous, not high-confidence) or that is already
	taken by an existing rename. Preserves input order.
	"""
	pairs = list(candidates)
	counts = Counter(label for _, label in pairs)
	return [
		NameSuggestion(va=va, label=label)
		for va, label in pairs
		if counts[label] == 1 and label not in taken_labels
	]


_LABEL_STRIP = re.compile(r"[^a-z0-9]+")


def string_label_sanitize(text: str) -> str | None:
	"""Turn a referenced string into a C-identifier-ish label, or None.

	Lowercase, runs of non-alphanumerics collapse to a single `_`, surrounding
	`_` trimmed; a leading digit is prefixed with `_`. Returns None when nothing
	usable remains (e.g. all punctuation). Hyphenated script names like
	`game-engine-player` become `game_engine_player`.
	"""
	collapsed = _LABEL_STRIP.sub("_", text.lower()).strip("_")
	if not collapsed:
		return None
	if collapsed[0].isdigit():
		collapsed = "_" + collapsed
	return collapsed
