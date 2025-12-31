"""LLM-based decompilation agent.

Implements neural network decompilation:
1. Feed assembly to local LLM
2. Get C code back
3. Compile and verify
4. If mismatch, feed diff back to LLM
5. Repeat until perfect match

Inspired by: https://blog.chrislewis.au/the-unexpected-effectiveness-of-one-shot-decompilation-with-claude/
"""

import re
import time
from dataclasses import dataclass

from litellm import completion

from src.cfg import CFGExtractor
from src.decoder import Decoder, Instruction
from src.verifier import BinaryVerifier, CompilationResult, VerificationResult


@dataclass
class DecompilationResult:
	"""Result of decompilation attempt."""

	success: bool
	c_code: str
	iterations: int
	verification: VerificationResult | None = None
	error: str | None = None


class DecompilationAgent:
	"""Agent that uses LLM to decompile x86 to C.
	"""

	def __init__(
		self,
		decoder: Decoder | None = None,
		verifier: BinaryVerifier | None = None,
		model: str = "qwen/qwen3-4b-2507",
		api_base: str = "http://127.0.0.1:1234/v1",
		api_key: str = "sk-1234",
		max_retries: int = 3,
	):
		"""Initialize decompilation agent.

		Args:
			decoder: Instruction decoder (default: new Decoder)
			verifier: Binary verifier (default: new BinaryVerifier)
			model: LLM model identifier (will be prefixed with "openai/")
			api_base: Base URL for local LLM server
			api_key: API key for the endpoint (can be dummy for local servers)
			max_retries: Maximum retries for LLM API calls
		"""
		self.decoder = decoder or Decoder()
		self.verifier = verifier or BinaryVerifier()
		self.cfg_extractor = CFGExtractor()
		self.model = model
		self.api_base = api_base
		self.api_key = api_key
		self.max_retries = max_retries

	def decompile(
		self, binary: bytes, max_iterations: int = 5, base_address: int = 0, progress_callback=None
	) -> DecompilationResult:
		"""Decompile binary code to C using LLM.

		Args:
			binary: x86 machine code to decompile
			max_iterations: Maximum refinement iterations
			base_address: Base address for disassembly
			progress_callback: Optional callback(iteration, c_code, verification) called after each iteration

		Returns:
			DecompilationResult with C code and verification status
		"""
		self.decoder.base_address = base_address
		instructions = self.decoder.decode(binary)

		if not instructions:
			return DecompilationResult(success=False, c_code="", iterations=0, error="No instructions decoded")

		cfg = self.cfg_extractor.extract(instructions)

		assembly_text = self._format_assembly(instructions)
		cfg_text = self._format_cfg(cfg)

		c_code = ""
		verification = None
		best_result = None
		best_match_pct = -1.0

		for iteration in range(max_iterations):
			try:
				if iteration == 0:
					prompt = self._create_initial_prompt(assembly_text, cfg_text)
				elif verification and not verification.compilation_result.success:
					errors = verification.compilation_result.stderr
					prompt = self._create_compilation_error_prompt(assembly_text, cfg_text, c_code, errors)
				elif verification:
					match_pct = verification.match_percentage
					prompt = self._create_binary_diff_prompt(assembly_text, cfg_text, c_code, match_pct)
				else:
					prompt = self._create_initial_prompt(assembly_text, cfg_text)

				llm_response = self._call_llm(prompt)
				c_code = self._extract_c_code(llm_response)

				is_valid, error_msg = self._validate_c_code(c_code)
				if not is_valid:
					verification = VerificationResult(
						matches=False,
						compilation_result=CompilationResult(
							success=False,
							stderr=f"VALIDATION ERROR: {error_msg}\n\n"
							f"You used inline assembly, which is FORBIDDEN.\n"
							f"You must write pure C code that produces the same result.\n"
							f"Understand what the assembly does and write equivalent C operations.",
						),
					)
					if progress_callback:
						progress_callback(iteration + 1, c_code, verification)
					continue

			except Exception as e:
				if best_result is not None:
					return best_result
				return DecompilationResult(
					success=False,
					c_code=c_code,
					iterations=iteration + 1,
					error=f"LLM call failed: {e}",
				)

			verification = self.verifier.verify(binary, c_code)

			if verification.compilation_result.success:
				match_pct = verification.match_percentage
				if match_pct > best_match_pct:
					best_match_pct = match_pct
					best_result = DecompilationResult(
						success=verification.matches,
						c_code=c_code,
						iterations=iteration + 1,
						verification=verification,
					)

			if progress_callback:
				progress_callback(iteration + 1, c_code, verification)

			if verification.matches:
				return DecompilationResult(
					success=True,
					c_code=c_code,
					iterations=iteration + 1,
					verification=verification,
				)

		if best_result is not None:
			best_result.error = (
				f"Max iterations ({max_iterations}) reached - showing best ({best_match_pct:.1f}% match)"
			)
			return best_result

		return DecompilationResult(
			success=False,
			c_code=c_code,
			iterations=max_iterations,
			verification=verification,
			error=f"Max iterations ({max_iterations}) reached without successful compilation",
		)

	def _format_assembly(self, instructions: list[Instruction]) -> str:
		"""Format instructions as assembly listing for LLM.

		Args:
			instructions: List of decoded instructions

		Returns:
			Human-readable assembly listing
		"""
		lines = []
		for instr in instructions:
			addr_str = f"0x{instr.address:08x}"
			if instr.op_str:
				lines.append(f"{addr_str}: {instr.mnemonic} {instr.op_str}")
			else:
				lines.append(f"{addr_str}: {instr.mnemonic}")

		return "\n".join(lines)

	def _format_cfg(self, cfg) -> str:
		"""Format CFG as human-readable structure for LLM.

		Args:
			cfg: ControlFlowGraph

		Returns:
			Human-readable CFG description
		"""
		if not cfg.blocks:
			return "No control flow graph available"

		lines = []
		lines.append("CONTROL FLOW STRUCTURE:")
		lines.append("")

		lines.append(f"Entry: 0x{cfg.entry_address:08x}")
		lines.append("")

		sorted_blocks = sorted(cfg.blocks.items())

		for addr, block in sorted_blocks:
			end_addr = block.end_address
			num_instrs = len(block.instructions)

			if not block.instructions:
				block_type = "empty"
				successor_detail = ""
			else:
				last_instr = block.instructions[-1]

				if last_instr.mnemonic == "ret":
					block_type = "returns"
					successor_detail = ""
				elif last_instr.mnemonic.startswith("j") and last_instr.mnemonic != "jmp":
					block_type = "conditional branch"
					if len(block.successors) == 2:
						target = None
						for instr in block.instructions:
							if instr.mnemonic == last_instr.mnemonic:
								target = self.cfg_extractor._parse_jump_target(instr)
								break

						if target is not None and target in block.successors:
							fall_through = [s for s in block.successors if s != target][0]
							successor_detail = (
								f"\n    → if taken: 0x{target:08x}\n    → if not taken: 0x{fall_through:08x}"
							)
						else:
							successor_detail = "\n    → successors: " + ", ".join(
								f"0x{s:08x}" for s in block.successors
							)
					else:
						successor_detail = "\n    → successors: " + ", ".join(f"0x{s:08x}" for s in block.successors)
				elif last_instr.mnemonic == "jmp":
					block_type = "unconditional jump"
					successor_detail = "\n    → target: " + ", ".join(f"0x{s:08x}" for s in block.successors)
				elif last_instr.mnemonic == "call":
					block_type = "call"
					successor_detail = "\n    → continues at: " + ", ".join(f"0x{s:08x}" for s in block.successors)
				else:
					block_type = "fall-through"
					successor_detail = (
						"\n    → next: " + ", ".join(f"0x{s:08x}" for s in block.successors) if block.successors else ""
					)

			entry_marker = " (ENTRY)" if addr == cfg.entry_address else ""
			exit_marker = " (EXIT)" if not block.successors and block.instructions else ""

			block_info = f"  Block 0x{addr:08x}-0x{end_addr:08x}: {num_instrs} instructions"
			lines.append(f"{block_info}, {block_type}{entry_marker}{exit_marker}{successor_detail}")

		lines.append("")
		if len(cfg.blocks) == 1:
			lines.append("Graph: Single basic block")
		else:
			lines.append(f"Graph: {len(cfg.blocks)} basic blocks")

			exit_count = sum(1 for block in cfg.blocks.values() if not block.successors)
			if exit_count == 1:
				lines.append("Exits: Single exit point")
			else:
				lines.append(f"Exits: {exit_count} exit points")

			back_edges = []
			for addr, block in cfg.blocks.items():
				for succ in block.successors:
					if succ <= addr:
						back_edges.append((addr, succ))

			if back_edges:
				lines.append(f"Loops: {len(back_edges)} backward edge(s) detected")
				for from_addr, to_addr in back_edges:
					lines.append(f"  - 0x{from_addr:08x} → 0x{to_addr:08x}")

		return "\n".join(lines)

	def _extract_c_code(self, llm_response: str) -> str:
		"""Extract C code from markdown code blocks.

		Args:
			llm_response: Raw LLM response that may contain markdown

		Returns:
			Extracted C code, or original response if no code block found
		"""
		pattern = r"```c\s*\n(.*?)```"
		matches = re.findall(pattern, llm_response, re.DOTALL)

		if matches:
			return matches[0].strip()

		pattern = r"```\s*\n(.*?)```"
		matches = re.findall(pattern, llm_response, re.DOTALL)

		if matches:
			return matches[0].strip()

		return llm_response.strip()

	def _validate_c_code(self, c_code: str) -> tuple[bool, str | None]:
		"""Validate C code doesn't contain forbidden constructs.

		Args:
			c_code: C code to validate

		Returns:
			Tuple of (is_valid, error_message)
		"""
		inline_asm_patterns = [
			r"__asm__\s*\(",
			r"__asm__\s+volatile",
			r"\basm\s*\(",
			r"\basm\s+volatile",
		]

		for pattern in inline_asm_patterns:
			if re.search(pattern, c_code, re.IGNORECASE):
				return False, "Code contains inline assembly (__asm__ or asm())"

		return True, None

	def _call_llm(self, prompt: str) -> str:
		"""Call LLM API with retry logic.

		Args:
			prompt: Prompt to send to LLM

		Returns:
			LLM response text

		Raises:
			Exception: If all retries fail
		"""
		for attempt in range(self.max_retries):
			try:
				response = completion(
					model=f"openai/{self.model}",  # Add openai/ prefix for routing
					api_key=self.api_key,
					api_base=self.api_base,
					messages=[{"role": "user", "content": prompt}],
				)
				return response.choices[0].message.content
			except Exception as e:
				if attempt == self.max_retries - 1:
					raise Exception(f"LLM call failed after {self.max_retries} attempts: {e}") from e
				time.sleep(1)
		return ""

	def _create_initial_prompt(self, assembly: str, cfg: str) -> str:
		"""Create initial decompilation prompt.

		Args:
			assembly: Assembly code listing
			cfg: Control flow graph description

		Returns:
			Prompt for LLM
		"""
		return f"""You are decompiling x86-32 assembly to C code.
The goal is to generate C code that compiles to IDENTICAL machine code.

REQUIREMENTS:
1. Put your C code in a ```c code block - ONLY code inside this fence will be compiled and tested
2. You may write analysis, reasoning, or explanations outside the code fence
3. NO inline assembly (__asm__, asm(), or assembly directives) in the code fence - write pure C only
4. Compiler flags: gcc -m32 -O0 -fno-stack-protector -mpreferred-stack-boundary=2
5. Every byte must match - not just semantic equivalence
6. Function signature: int function_XXXXXXXX() where XXXXXXXX is the first instruction address

{cfg}

ASSEMBLY TO DECOMPILE:
{assembly}

KEY INSIGHTS:
- At -O0, gcc generates straightforward code with minimal optimization
- Function prologue/epilogue (push ebp; mov ebp, esp; pop ebp; ret) is automatic
- Operations that modify memory and then use the value require different C than operations that just compute
- The choice between x = x + 1 vs x += 1 vs x++ can affect generated code
- Control flow jumps indicate loop and branch structure - use the CFG

Think through the assembly, then generate the C code in a ```c block:"""

	def _create_compilation_error_prompt(self, assembly: str, cfg: str, c_code: str, errors: str) -> str:
		"""Create prompt with compilation error feedback.

		Args:
			assembly: Original assembly code
			cfg: Control flow graph description
			c_code: C code that failed to compile
			errors: Compilation error messages

		Returns:
			Prompt for LLM
		"""
		return f"""Your C code has compilation errors. Fix them.

COMPILATION ERRORS:
{errors}

YOUR PREVIOUS CODE:
{c_code}

{cfg}

TARGET ASSEMBLY:
{assembly}

The code must:
1. Compile successfully with: gcc -m32 -O0 -fno-stack-protector -mpreferred-stack-boundary=2
2. Be syntactically correct C (no inline assembly in the ```c fence)
3. Produce binary that matches the target assembly exactly

If the error mentions inline assembly, rewrite using pure C operations.
Use the CFG to verify your control flow structure is correct.
You may write reasoning or analysis outside the code fence - only code in the ```c block will be compiled.

Analyze the errors, then generate corrected C code in a ```c block:"""

	def _create_binary_diff_prompt(self, assembly: str, cfg: str, c_code: str, match_percentage: float) -> str:
		"""Create prompt with binary mismatch feedback.

		Args:
			assembly: Original assembly code
			cfg: Control flow graph description
			c_code: C code that compiled but doesn't match
			match_percentage: Percentage of matching bytes

		Returns:
			Prompt for LLM
		"""
		return f"""Your C code compiled but produces different binary output. Match: {match_percentage:.1f}% (need 100%)

{cfg}

TARGET ASSEMBLY:
{assembly}

YOUR CODE (generates different instructions):
{c_code}

Your code is semantically similar but the binary differs. At -O0, small C syntax changes affect output.
You may analyze the differences and reason about the solution outside the code fence.
Only code in the ```c block will be compiled and tested.

Think about what C changes would produce the exact assembly shown above,
then generate improved C code in a ```c block:"""


def decompile_to_c(binary: bytes, base_address: int = 0, max_iterations: int = 5) -> str:
	"""Convenience function to decompile binary to C.

	Args:
		binary: x86 machine code
		base_address: Base address for disassembly
		max_iterations: Maximum refinement iterations

	Returns:
		C source code (or error message)
	"""
	agent = DecompilationAgent()
	result = agent.decompile(binary, max_iterations, base_address)

	if result.success:
		return result.c_code
	else:
		return f"// Decompilation failed: {result.error}\n{result.c_code}"
