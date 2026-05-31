"""Tests for binary-agnostic string cross-referencing (src.strings_xref).

A function's referenced string literals are recovered by disassembling it and
checking immediate / absolute-memory operands against the read-only data
sections — no platform- or game-specific assumptions.
"""

from src.strings_xref import (
	function_string_refs,
	string_at_va,
	string_label_sanitize,
)
from src.xbe import (
	SECTION_FLAG_EXECUTABLE,
	ParsedXbe,
	XbeHeader,
	XbeSection,
)

TEXT_VA = 0x00011000
RODATA_VA = 0x00020000


def _parsed(code: bytes, rodata: bytes) -> ParsedXbe:
	"""Two sections: executable .text at TEXT_VA (raw 0) and read-only .rdata at
	RODATA_VA (raw 0x1000). `parsed.data` packs both at their raw offsets."""
	text = XbeSection(
		name=".text",
		flags=SECTION_FLAG_EXECUTABLE,
		virtual_address=TEXT_VA,
		virtual_size=0x1000,
		raw_address=0,
		raw_size=0x1000,
	)
	rdata = XbeSection(
		name=".rdata",
		flags=0,  # not executable, not writable → read-only data
		virtual_address=RODATA_VA,
		virtual_size=0x1000,
		raw_address=0x1000,
		raw_size=0x1000,
	)
	data = bytearray(0x2000)
	data[0 : len(code)] = code
	data[0x1000 : 0x1000 + len(rodata)] = rodata
	header = XbeHeader(0x10000, 0, 0, 0, 2, 0, 0, 0)
	return ParsedXbe(header=header, sections=(text, rdata), data=bytes(data))


def _imm32(opcode: int, value: int) -> bytes:
	return bytes([opcode]) + value.to_bytes(4, "little")


class TestStringAtVa:
	def test_decodes_nul_terminated_string(self):
		parsed = _parsed(b"\xc3", b"hello world\x00")
		assert string_at_va(parsed, RODATA_VA) == "hello world"

	def test_none_outside_any_section(self):
		parsed = _parsed(b"\xc3", b"x\x00")
		assert string_at_va(parsed, 0x99990000) is None

	def test_decodes_string_in_exec_flagged_section(self):
		# XBEs mark .rdata/.data executable, so the exec flag must NOT gate
		# string decoding. A printable, NUL-terminated run in an exec-flagged
		# section is still a string. Here .text holds clean ASCII + NUL.
		parsed = _parsed(b"hello\x00", b"unused\x00")
		assert string_at_va(parsed, TEXT_VA) == "hello"

	def test_none_when_too_short(self):
		parsed = _parsed(b"\xc3", b"ab\x00")
		assert string_at_va(parsed, RODATA_VA, min_len=4) is None

	def test_none_when_not_printable(self):
		parsed = _parsed(b"\xc3", b"\x01\x02\x03\x04\x00")
		assert string_at_va(parsed, RODATA_VA) is None

	def test_none_when_not_terminated_within_max(self):
		parsed = _parsed(b"\xc3", b"A" * 64)  # no NUL
		assert string_at_va(parsed, RODATA_VA, max_len=16) is None


class TestFunctionStringRefs:
	def test_finds_push_immediate_string(self):
		# push RODATA_VA ; ret
		code = _imm32(0x68, RODATA_VA) + b"\xc3"
		parsed = _parsed(code, b"player-error\x00")
		assert function_string_refs(parsed, TEXT_VA, len(code)) == ("player-error",)

	def test_finds_absolute_memory_displacement(self):
		# mov eax, [RODATA_VA] (A1 disp32) ; ret
		code = _imm32(0xA1, RODATA_VA) + b"\xc3"
		parsed = _parsed(code, b"render flag\x00")
		assert function_string_refs(parsed, TEXT_VA, len(code)) == ("render flag",)

	def test_dedupes_preserving_first_seen_order(self):
		# push B ; push A ; push A ; ret  →  (B, A)
		va_a = RODATA_VA
		va_b = RODATA_VA + 0x10
		code = _imm32(0x68, va_b) + _imm32(0x68, va_a) + _imm32(0x68, va_a) + b"\xc3"
		rodata = bytearray(0x40)
		rodata[0x00 : 0x00 + 6] = b"alpha\x00"
		rodata[0x10 : 0x10 + 5] = b"beta\x00"
		parsed = _parsed(code, bytes(rodata))
		assert function_string_refs(parsed, TEXT_VA, len(code)) == ("beta", "alpha")

	def test_ignores_immediates_that_are_not_strings(self):
		# push 0x10 (a small constant, not an address) ; ret
		code = _imm32(0x68, 0x10) + b"\xc3"
		parsed = _parsed(code, b"unused\x00")
		assert function_string_refs(parsed, TEXT_VA, len(code)) == ()

	def test_empty_when_no_refs(self):
		parsed = _parsed(b"\xc3", b"unused\x00")
		assert function_string_refs(parsed, TEXT_VA, 1) == ()


class TestStringLabelSanitize:
	def test_haloscript_hyphen_to_underscore(self):
		assert string_label_sanitize("game-engine-player") == "game_engine_player"

	def test_spaces_and_punct_collapse(self):
		assert (
			string_label_sanitize("cached object render states!") == "cached_object_render_states"
		)

	def test_leading_digit_prefixed(self):
		assert string_label_sanitize("3d vector") == "_3d_vector"

	def test_empty_or_unusable_returns_none(self):
		assert string_label_sanitize("!!!") is None
		assert string_label_sanitize("") is None
