"""Binary verification for decompilation correctness.

This module provides deterministic verification that generated C code
compiles to the same binary as the original.

This is the foundation for neural network-based decompilation:
1. Generate C code (via Claude/agent)
2. Compile to binary
3. Compare with original
4. Iterate until perfect match
"""

import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CompilationResult:
	"""Result of compiling C code."""

	success: bool
	binary: bytes | None = None
	stdout: str = ""
	stderr: str = ""
	errors: list[str] = None

	def __post_init__(self):
		if self.errors is None:
			self.errors = []


@dataclass
class VerificationResult:
	"""Result of verifying decompilation correctness."""

	matches: bool
	compilation_result: CompilationResult
	diff: bytes | None = None  # Bytes that differ
	match_percentage: float = 0.0


class BinaryVerifier:
	"""Verify that C code compiles to match original binary.

	Uses gcc to compile C code and byte-by-byte comparison.
	Completely deterministic - no heuristics.
	"""

	def __init__(self, gcc_path: str = "gcc", compiler_flags: list[str] | None = None):
		"""Initialize verifier.

		Args:
			gcc_path: Path to gcc compiler
			compiler_flags: Additional compiler flags (default: x86-32 cross-compilation)
		"""
		self.gcc_path = gcc_path
		self.compiler_flags = compiler_flags or [
			"-target",
			"i386-unknown-linux-gnu",  # Cross-compile to x86-32
			"-m32",  # 32-bit
			"-O0",  # No optimization (preserve structure)
			"-fno-asynchronous-unwind-tables",  # No extra sections
			"-fno-stack-protector",  # No stack canaries
			"-fno-pie",  # No position independent executable
		]

	def _extract_text_section(self, elf_data: bytes) -> bytes | None:
		"""Extract .text section from ELF object file.

		Args:
			elf_data: Raw ELF file bytes

		Returns:
			.text section bytes, or None if not found
		"""
		if len(elf_data) < 52:  # Minimum ELF32 header size
			return None

		# Check ELF magic number
		if elf_data[:4] != b"\x7fELF":
			return None

		# Parse ELF32 header (little-endian)
		# We only care about section header table location
		e_shoff = struct.unpack_from("<I", elf_data, 32)[0]  # Section header offset
		e_shentsize = struct.unpack_from("<H", elf_data, 46)[0]  # Section header entry size
		e_shnum = struct.unpack_from("<H", elf_data, 48)[0]  # Number of section headers
		e_shstrndx = struct.unpack_from("<H", elf_data, 50)[0]  # String table section index

		if e_shoff == 0 or e_shnum == 0:
			return None

		# Read section header string table
		shstrtab_offset = e_shoff + (e_shstrndx * e_shentsize)
		if shstrtab_offset + 24 > len(elf_data):
			return None

		sh_offset = struct.unpack_from("<I", elf_data, shstrtab_offset + 16)[0]
		sh_size = struct.unpack_from("<I", elf_data, shstrtab_offset + 20)[0]

		if sh_offset + sh_size > len(elf_data):
			return None

		shstrtab = elf_data[sh_offset : sh_offset + sh_size]

		# Find .text section
		for i in range(e_shnum):
			sh_addr = e_shoff + (i * e_shentsize)
			if sh_addr + 40 > len(elf_data):
				continue

			# Parse section header
			sh_name_idx = struct.unpack_from("<I", elf_data, sh_addr)[0]
			sh_offset = struct.unpack_from("<I", elf_data, sh_addr + 16)[0]
			sh_size = struct.unpack_from("<I", elf_data, sh_addr + 20)[0]

			# Get section name
			if sh_name_idx >= len(shstrtab):
				continue

			name_end = shstrtab.find(b"\x00", sh_name_idx)
			if name_end == -1:
				continue

			section_name = shstrtab[sh_name_idx:name_end].decode("ascii", errors="ignore")

			# Found .text section!
			if section_name == ".text":
				if sh_offset + sh_size > len(elf_data):
					return None
				return elf_data[sh_offset : sh_offset + sh_size]

		return None

	def compile_c_code(self, c_code: str) -> CompilationResult:
		"""Compile C code to binary.

		Args:
			c_code: C source code to compile

		Returns:
			CompilationResult with success status and binary
		"""
		with tempfile.TemporaryDirectory() as tmpdir:
			tmppath = Path(tmpdir)
			c_file = tmppath / "input.c"
			o_file = tmppath / "output.o"

			# Write C code to file
			c_file.write_text(c_code)

			try:
				result = subprocess.run(
					[self.gcc_path, "-c", *self.compiler_flags, str(c_file), "-o", str(o_file)],
					capture_output=True,
					text=True,
					timeout=10,
				)

				if result.returncode == 0:
					binary = o_file.read_bytes()
					return CompilationResult(success=True, binary=binary, stdout=result.stdout, stderr=result.stderr)
				else:
					return CompilationResult(
						success=False,
						stdout=result.stdout,
						stderr=result.stderr,
						errors=[result.stderr],
					)

			except subprocess.TimeoutExpired:
				return CompilationResult(success=False, errors=["Compilation timeout (>10s) - possible infinite loop"])
			except FileNotFoundError:
				return CompilationResult(success=False, errors=[f"Compiler not found: {self.gcc_path}"])
			except Exception as e:
				return CompilationResult(success=False, errors=[f"Compilation error: {e}"])

	def verify(self, original_binary: bytes, c_code: str) -> VerificationResult:
		"""Verify C code compiles to match original binary.

		Args:
			original_binary: Original binary code (raw bytes or ELF object file)
			c_code: Generated C code

		Returns:
			VerificationResult with match status and differences
		"""
		compilation = self.compile_c_code(c_code)

		if not compilation.success:
			return VerificationResult(matches=False, compilation_result=compilation, match_percentage=0.0)

		compiled_full = compilation.binary

		compiled_text = self._extract_text_section(compiled_full)
		if compiled_text is None:
			compiled_text = compiled_full

		original_text = self._extract_text_section(original_binary)
		if original_text is None:
			original_text = original_binary

		if compiled_text == original_text:
			return VerificationResult(matches=True, compilation_result=compilation, match_percentage=100.0)

		match_percentage = self._calculate_match_percentage(original_text, compiled_text)
		diff = self._find_differences(original_text, compiled_text)

		return VerificationResult(
			matches=False,
			compilation_result=compilation,
			diff=diff,
			match_percentage=match_percentage,
		)

	def _calculate_match_percentage(self, original: bytes, compiled: bytes) -> float:
		"""Calculate percentage of matching bytes."""
		max_len = max(len(original), len(compiled))
		if max_len == 0:
			return 100.0

		matches = sum(1 for i in range(min(len(original), len(compiled))) if original[i] == compiled[i])

		return (matches / max_len) * 100.0

	def _find_differences(self, original: bytes, compiled: bytes) -> bytes:
		"""Find differing bytes between binaries.

		Returns bytes with differences marked (simplified version).
		"""
		# For now, just return XOR of bytes where they differ
		# In production, would want structured diff
		max_len = max(len(original), len(compiled))
		diff = bytearray(max_len)

		for i in range(max_len):
			orig_byte = original[i] if i < len(original) else 0
			comp_byte = compiled[i] if i < len(compiled) else 0
			diff[i] = orig_byte ^ comp_byte

		return bytes(diff)
