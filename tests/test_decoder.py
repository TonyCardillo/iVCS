"""Tests for the x86 decoder module."""

from hypothesis import given
from hypothesis import strategies as st

from src.decoder import Decoder, Instruction


class TestDecoder:
	"""Test suite for x86 decoder wrapper."""

	def test_empty_code_returns_empty_list(self):
		"""Decoding empty bytes should return empty instruction list."""
		decoder = Decoder()
		assert decoder.decode(b"") == []

	def test_base_address_is_used(self):
		"""Decoder should pass base address to Capstone."""
		decoder = Decoder(base_address=0x1000)
		instructions = decoder.decode(b"\x90")  # NOP
		assert instructions[0].address == 0x1000

	def test_returns_instruction_objects(self):
		"""Decoder should return Instruction dataclass instances."""
		decoder = Decoder()
		instructions = decoder.decode(b"\x90")  # NOP
		assert len(instructions) == 1
		assert isinstance(instructions[0], Instruction)
		assert hasattr(instructions[0], "address")
		assert hasattr(instructions[0], "mnemonic")
		assert hasattr(instructions[0], "op_str")
		assert hasattr(instructions[0], "size")

	@given(st.binary(min_size=1, max_size=100))
	def test_decode_never_crashes(self, code):
		"""Decoder should handle arbitrary bytes without crashing."""
		decoder = Decoder()
		instructions = decoder.decode(code)
		assert isinstance(instructions, list)
		for instr in instructions:
			assert isinstance(instr, Instruction)


class TestDecoderIntegration:
	"""
	Integration smoke tests - verify decoder + Capstone work correctly together.

	NOTE: These test the integration, not just our decoder wrapper. They ensure:
	1. Capstone is configured correctly for x86-32
	2. Common game code patterns disassemble as expected
	3. No regressions when upgrading Capstone versions
	"""

	def test_common_function_prologue(self):
		"""Verify standard function prologue disassembles correctly."""
		decoder = Decoder(base_address=0x1000)
		# push ebp; mov ebp, esp
		code = b"\x55\x89\xe5"
		instructions = decoder.decode(code)

		assert len(instructions) == 2
		assert instructions[0].mnemonic == "push"
		assert "ebp" in instructions[0].op_str
		assert instructions[1].mnemonic == "mov"
		assert "ebp" in instructions[1].op_str and "esp" in instructions[1].op_str

	def test_common_arithmetic(self):
		"""Verify common arithmetic operations used in games."""
		decoder = Decoder()

		# add eax, 10
		instrs = decoder.decode(b"\x83\xc0\x0a")
		assert instrs[0].mnemonic == "add"
		assert "eax" in instrs[0].op_str

		# sub esp, 0x10 (stack allocation)
		instrs = decoder.decode(b"\x83\xec\x10")
		assert instrs[0].mnemonic == "sub"
		assert "esp" in instrs[0].op_str

	def test_memory_access_patterns(self):
		"""Verify memory access patterns common in game code."""
		decoder = Decoder()

		# mov eax, [ebx] - pointer dereference
		instrs = decoder.decode(b"\x8b\x03")
		assert instrs[0].mnemonic == "mov"
		assert "eax" in instrs[0].op_str
		assert "ebx" in instrs[0].op_str

		# mov [ebp-4], eax - local variable store
		instrs = decoder.decode(b"\x89\x45\xfc")
		assert instrs[0].mnemonic == "mov"
		assert "ebp" in instrs[0].op_str

	def test_control_flow_instructions(self):
		"""Verify jump/call instructions for control flow."""
		decoder = Decoder(base_address=0x1000)

		# je (conditional jump)
		instrs = decoder.decode(b"\x74\x05")
		assert instrs[0].mnemonic == "je"

		# jmp (unconditional jump)
		instrs = decoder.decode(b"\xeb\x05")
		assert instrs[0].mnemonic == "jmp"

		# call
		instrs = decoder.decode(b"\xe8\x10\x00\x00\x00")
		assert instrs[0].mnemonic == "call"

		# ret
		instrs = decoder.decode(b"\xc3")
		assert instrs[0].mnemonic == "ret"

	def test_instruction_address_sequencing(self):
		"""Verify addresses increment correctly (critical for CFG building)."""
		decoder = Decoder(base_address=0x1000)
		# push ebp (1 byte); mov ebp, esp (2 bytes); ret (1 byte)
		code = b"\x55\x89\xe5\xc3"
		instrs = decoder.decode(code)

		assert instrs[0].address == 0x1000
		assert instrs[1].address == 0x1001  # 0x1000 + 1
		assert instrs[2].address == 0x1003  # 0x1001 + 2

		# Next instruction would be at 0x1004
		next_addr = instrs[2].address + instrs[2].size
		assert next_addr == 0x1004
