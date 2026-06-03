"""Detect and budget MSVC inline assembly in a decomp submission.

The agent is shown the target's disassembly. The degenerate way to "match" is
to paste that listing into an `__asm { ... }` block: MSVC 7.1 emits it almost
verbatim, so the score hits 100% with zero decompilation. That's re-assembly,
not matching.

A flat ban is wrong, though — real Xbox titles used inline asm sparingly
(`rdtsc`, `cpuid`, `int 3`, MMX blocks), and a genuine match of such a function
must contain those few instructions. So the signal isn't "asm present" but "how
much of the function is asm doing the work": a small absolute count AND a small
fraction of the target. `inline_asm_scan` measures it; the AsmBudget policy
decides; `compile_and_view_assembly` enforces by rejecting over-budget code.
"""

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class AsmScan:
	instruction_count: int
	mnemonics: tuple[str, ...]  # distinct mnemonics seen, in first-seen order


@dataclass(frozen=True)
class AsmBudget:
	"""A submission must stay under BOTH bounds. The absolute cap stops a big
	function being transcribed; the ratio cap stops a small one being fully
	asm'd even when its instruction count is under the absolute cap."""

	max_instructions: int = 8
	max_ratio: float = 0.10


# A no-op budget that nothing trips. For trusted, non-model code paths — e.g.
# carrying an already-gated, diff-verified solution to a byte-identical twin —
# where the anti-cheat gate does not apply and must not block a legitimate match.
ASM_BUDGET_DISABLED = AsmBudget(max_instructions=2**31 - 1, max_ratio=float("inf"))


# The keyword, single- or double-underscore. The lookbehind keeps it from
# matching inside an identifier (`my__asm_helper`, `_asmodeus`); \b keeps it
# from matching a prefix (`__asmfoo`).
_ASM_KEYWORD_RE = re.compile(r"(?<![\w$])(?:__asm|_asm)\b")

# A leading assembler label on a line: `name:` (but not `name::`, which would be
# a C++ scope, not an asm label). Consumes trailing whitespace so what remains
# is the instruction, if any.
_ASM_LABEL_RE = re.compile(r"^[A-Za-z_$@?.][\w$@?.]*:(?!:)\s*")

_MNEMONIC_RE = re.compile(r"[A-Za-z][\w]*")


def inline_asm_scan(c_code: str) -> AsmScan:
	"""Count inline-asm instructions in MSVC C source.

	Comments and string/char literals are stripped first so an `__asm` mentioned
	in prose or data never counts. Both the single-statement form
	(`__asm rdtsc`) and the block form (`__asm { ... }`) are handled; bare
	labels and `;` assembler comments inside a block do not count as
	instructions.
	"""
	code = _comments_and_literals_strip(c_code)
	count = 0
	mnemonics: list[str] = []
	consumed_to = 0  # end of the last block we counted, so its body isn't rescanned

	for match in _ASM_KEYWORD_RE.finditer(code):
		if match.start() < consumed_to:
			continue
		cursor = match.end()
		while cursor < len(code) and code[cursor] in " \t\r\n":
			cursor += 1

		if cursor < len(code) and code[cursor] == "{":
			close = code.find("}", cursor + 1)
			body = code[cursor + 1 : close if close != -1 else len(code)]
			found = _asm_block_mnemonics(body)
			consumed_to = (close + 1) if close != -1 else len(code)
		else:
			line_end = code.find("\n", match.end())
			segment = code[match.end() : line_end if line_end != -1 else len(code)]
			mnemonic = _asm_line_mnemonic(segment)
			found = [mnemonic] if mnemonic else []

		count += len(found)
		mnemonics.extend(found)

	return AsmScan(instruction_count=count, mnemonics=tuple(dict.fromkeys(mnemonics)))


def is_asm_within_budget(scan: AsmScan, target_instruction_count: int, budget: AsmBudget) -> bool:
	"""True if the submission's inline asm is within budget.

	Zero asm is always within budget. Otherwise it must be under the absolute
	cap AND under the ratio cap. When the target instruction count is unknown
	(<= 0), only the absolute cap applies — there's no denominator for a ratio.
	"""
	if scan.instruction_count == 0:
		return True
	if scan.instruction_count > budget.max_instructions:
		return False
	if target_instruction_count > 0:
		ratio = scan.instruction_count / target_instruction_count
		if ratio > budget.max_ratio:
			return False
	return True


def asm_rejection_message(scan: AsmScan, target_instruction_count: int, budget: AsmBudget) -> str:
	"""The tool-result text shown to the model when a submission is over budget.

	Instructive on purpose: name the count, the cap, and the offending mnemonics
	so the model corrects course (writes real C) instead of resubmitting asm and
	burning its iteration budget."""
	mnemonics = ", ".join(scan.mnemonics[:8]) or "(none)"
	lines = [
		"REJECTED: inline assembly over budget — not compiled.",
		f"You emitted {scan.instruction_count} inline-asm instruction(s) "
		f"({mnemonics}); the cap is {budget.max_instructions} and at most "
		f"{budget.max_ratio:.0%} of the function.",
		"Transcribing the target into `__asm` is re-assembly, not "
		"decompilation, and does not count as a match.",
		"Express this logic in C and let cl.exe generate the instructions. "
		"Reserve inline asm for the few instructions the original source "
		"genuinely required (e.g. rdtsc, cpuid, int 3).",
	]
	return "\n".join(lines)


def _asm_block_mnemonics(body: str) -> list[str]:
	"""Mnemonics of the instructions in an `__asm { ... }` body. Inner `__asm`
	prefixes (the multi-statement-per-line form) are treated as line breaks."""
	normalized = _ASM_KEYWORD_RE.sub("\n", body)
	found: list[str] = []
	for line in normalized.splitlines():
		mnemonic = _asm_line_mnemonic(line)
		if mnemonic:
			found.append(mnemonic)
	return found


def _asm_line_mnemonic(line: str) -> str | None:
	"""The mnemonic of a single asm line, or None for a blank line, a `;`
	comment, or a bare label. A label sharing the line with an instruction
	yields the instruction's mnemonic."""
	line = line.split(";", 1)[0].strip()  # `;` starts an assembler comment
	if not line:
		return None
	line = _ASM_LABEL_RE.sub("", line).strip()
	if not line:
		return None
	match = _MNEMONIC_RE.match(line)
	return match.group(0).lower() if match else None


def _comments_and_literals_strip(code: str) -> str:
	"""Replace C comments and string/char literals with blanks, preserving
	newlines so block structure (and line-based asm counting) stays intact.
	Stops an `__asm` that appears only in prose or data from being counted."""
	out: list[str] = []
	i, n = 0, len(code)
	while i < n:
		pair = code[i : i + 2]
		if pair == "//":
			end = code.find("\n", i)
			end = end if end != -1 else n
			out.append(" " * (end - i))
			i = end
		elif pair == "/*":
			end = code.find("*/", i + 2)
			end = (end + 2) if end != -1 else n
			out.append("".join("\n" if ch == "\n" else " " for ch in code[i:end]))
			i = end
		elif code[i] in "\"'":
			quote = code[i]
			out.append(" ")
			i += 1
			while i < n:
				if code[i] == "\\":
					out.append("  ")
					i += 2
					continue
				if code[i] == quote:
					out.append(" ")
					i += 1
					break
				out.append("\n" if code[i] == "\n" else " ")
				i += 1
		else:
			out.append(code[i])
			i += 1
	return "".join(out)


__all__ = [
	"ASM_BUDGET_DISABLED",
	"AsmBudget",
	"AsmScan",
	"asm_rejection_message",
	"inline_asm_scan",
	"is_asm_within_budget",
]
