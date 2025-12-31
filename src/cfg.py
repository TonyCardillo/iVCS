"""Simple, sound control flow graph extractor.

This module provides minimal CFG extraction for aiding the LLM purposes.
"""

from dataclasses import dataclass, field

from src.decoder import Instruction


@dataclass
class BasicBlock:
	"""A basic block: sequence of instructions with single entry/exit."""

	start_address: int
	instructions: list[Instruction] = field(default_factory=list)
	successors: list[int] = field(default_factory=list)

	@property
	def end_address(self) -> int:
		"""Get the address of the last instruction."""
		if not self.instructions:
			return self.start_address
		return self.instructions[-1].address


@dataclass
class ControlFlowGraph:
	"""Control flow graph: basic blocks with edges."""

	entry_address: int
	blocks: dict[int, BasicBlock] = field(default_factory=dict)

	def get_block(self, address: int) -> BasicBlock | None:
		"""Get basic block starting at address."""
		return self.blocks.get(address)

	def add_edge(self, from_addr: int, to_addr: int) -> None:
		"""Add edge between two blocks."""
		if from_addr in self.blocks and to_addr not in self.blocks[from_addr].successors:
			self.blocks[from_addr].successors.append(to_addr)


class CFGExtractor:
	"""Extract control flow graph from instructions.

	Simple, deterministic algorithm:
	1. Identify block boundaries (leaders)
	2. Split instructions into blocks
	3. Add edges based on control flow

	No heuristics, no assumptions - just direct analysis.
	"""

	TERMINATORS = {
		"ret",
		"jmp",
		"je",
		"jne",
		"jg",
		"jge",
		"jl",
		"jle",
		"ja",
		"jae",
		"jb",
		"jbe",
		"jo",
		"jno",
		"js",
		"jns",
		"jz",
		"jnz",
		"call",
	}

	def extract(self, instructions: list[Instruction]) -> ControlFlowGraph:
		"""Extract CFG from instruction list.

		Args:
			instructions: List of decoded instructions

		Returns:
			ControlFlowGraph with basic blocks and edges
		"""
		if not instructions:
			return ControlFlowGraph(entry_address=0, blocks={})

		leaders = self._find_leaders(instructions)
		blocks = self._create_blocks(instructions, leaders)

		cfg = ControlFlowGraph(entry_address=instructions[0].address, blocks=blocks)
		self._add_edges(cfg)

		return cfg

	def _find_leaders(self, instructions: list[Instruction]) -> set[int]:
		"""Find all leader addresses (start of basic blocks).

		A leader is:
		1. The first instruction (entry point)
		2. Target of any jump
		3. Instruction after a jump/call/ret
		"""
		leaders = {instructions[0].address}

		for i, instr in enumerate(instructions):
			if instr.mnemonic in self.TERMINATORS and i + 1 < len(instructions):
				leaders.add(instructions[i + 1].address)

			if instr.mnemonic.startswith("j") or instr.mnemonic == "call":
				target = self._parse_jump_target(instr)
				if target is not None:
					leaders.add(target)

		return leaders

	def _parse_jump_target(self, instr: Instruction) -> int | None:
		"""Parse jump target address from instruction.

		Returns None if target cannot be determined (indirect jump).
		"""
		op_str = instr.op_str.strip()
		if op_str.startswith("0x"):
			try:
				return int(op_str, 16)
			except ValueError:
				return None

		try:
			return int(op_str)
		except ValueError:
			return None

	def _create_blocks(self, instructions: list[Instruction], leaders: set[int]) -> dict[int, BasicBlock]:
		"""Split instructions into basic blocks at leader boundaries."""
		blocks: dict[int, BasicBlock] = {}
		current_block: BasicBlock | None = None

		for instr in instructions:
			if instr.address in leaders:
				if current_block:
					blocks[current_block.start_address] = current_block
				current_block = BasicBlock(start_address=instr.address)

			if current_block:
				current_block.instructions.append(instr)

		if current_block:
			blocks[current_block.start_address] = current_block

		return blocks

	def _add_edges(self, cfg: ControlFlowGraph) -> None:
		"""Add edges between basic blocks based on control flow."""
		for block in cfg.blocks.values():
			if not block.instructions:
				continue

			last_instr = block.instructions[-1]

			if last_instr.mnemonic == "jmp":
				target = self._parse_jump_target(last_instr)
				if target is not None:
					cfg.add_edge(block.start_address, target)

			elif last_instr.mnemonic.startswith("j") and last_instr.mnemonic != "jmp":
				target = self._parse_jump_target(last_instr)
				if target is not None:
					cfg.add_edge(block.start_address, target)

				next_addr = last_instr.address + last_instr.size
				if next_addr in cfg.blocks:
					cfg.add_edge(block.start_address, next_addr)

			elif last_instr.mnemonic == "call":
				next_addr = last_instr.address + last_instr.size
				if next_addr in cfg.blocks:
					cfg.add_edge(block.start_address, next_addr)

			elif last_instr.mnemonic == "ret":
				pass

			else:
				next_addr = last_instr.address + last_instr.size
				if next_addr in cfg.blocks:
					cfg.add_edge(block.start_address, next_addr)
