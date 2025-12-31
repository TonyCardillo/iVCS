"""x86 instruction decoder using Capstone."""

from dataclasses import dataclass

import capstone


@dataclass
class Instruction:
	"""Decoded x86 instruction."""

	address: int
	mnemonic: str
	op_str: str
	size: int


class Decoder:
	"""x86 instruction decoder."""

	def __init__(self, base_address: int = 0x0):
		self.base_address = base_address
		self._disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
		self._disassembler.skipdata = True  # Show data bytes instead of stopping

	def decode(self, code: bytes) -> list[Instruction]:
		"""Decode bytes into x86 instructions."""
		if not code:
			return []

		return [
			Instruction(
				address=i.address,
				mnemonic=i.mnemonic,
				op_str=i.op_str,
				size=i.size,
			)
			for i in self._disassembler.disasm(code, self.base_address)
		]
