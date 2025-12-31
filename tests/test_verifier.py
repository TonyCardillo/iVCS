"""Tests for binary verification.

These tests verify that the compilation and verification system works correctly.
This is the foundation for neural network-based decompilation.
"""

import pytest

from src.verifier import BinaryVerifier


class TestBinaryVerifier:
	"""Test compilation and binary verification."""

	@pytest.fixture
	def verifier(self):
		"""Create binary verifier."""
		return BinaryVerifier()

	def test_valid_c_code_compiles(self, verifier):
		"""Valid C code should compile successfully."""
		c_code = """
int add(int a, int b) {
    return a + b;
}
"""

		result = verifier.compile_c_code(c_code)

		assert result.success, f"Compilation failed: {result.stderr}"
		assert result.binary is not None
		assert len(result.binary) > 0

	def test_invalid_c_code_fails_compilation(self, verifier):
		"""Invalid C code should fail to compile."""
		c_code = """
int broken() {
    undefined_variable = 5;  // Error: undefined
    return 0;
}
"""

		result = verifier.compile_c_code(c_code)

		assert not result.success
		assert len(result.errors) > 0
		assert result.binary is None

	def test_syntax_error_fails_compilation(self, verifier):
		"""Code with syntax errors should fail."""
		c_code = """
int broken() {
    return 0  // Missing semicolon
}
"""

		result = verifier.compile_c_code(c_code)

		assert not result.success

	def test_identical_code_matches(self, verifier):
		"""Identical C code should produce matching binary."""
		c_code = """
int simple() {
    return 42;
}
"""

		first_compile = verifier.compile_c_code(c_code)
		assert first_compile.success

		result = verifier.verify(first_compile.binary, c_code)

		assert result.matches
		assert result.match_percentage == 100.0
		assert result.compilation_result.success

	def test_different_code_does_not_match(self, verifier):
		"""Different C code should produce different binary."""
		c_code1 = """
int func() {
    return 42;
}
"""

		c_code2 = """
int func() {
    return 43;
}
"""

		first_compile = verifier.compile_c_code(c_code1)
		assert first_compile.success

		result = verifier.verify(first_compile.binary, c_code2)

		assert not result.matches
		assert result.compilation_result.success

	def test_verification_fails_on_compilation_error(self, verifier):
		"""Verification should fail if C code doesn't compile."""
		c_code = """
int broken() {
    undefined_var = 5;
    return 0;
}
"""

		original = b"\\x55\\x89\\xe5\\xb8\\x05\\x00\\x00\\x00\\x5d\\xc3"

		result = verifier.verify(original, c_code)

		assert not result.matches
		assert not result.compilation_result.success
		assert result.match_percentage == 0.0

	def test_match_percentage_calculated_correctly(self, verifier):
		"""Match percentage should reflect byte similarity."""
		c_code1 = """
int func() {
    return 42;
}
"""

		c_code2 = """
int func() {
    return 42;
}
"""

		first_compile = verifier.compile_c_code(c_code1)
		assert first_compile.success

		result = verifier.verify(first_compile.binary, c_code2)

		assert result.matches
		assert result.match_percentage == 100.0

	@pytest.mark.skip(reason="gcc may not be available in CI")
	def test_gcc_not_found_returns_error(self):
		"""Missing gcc should return appropriate error."""
		verifier = BinaryVerifier(gcc_path="/nonexistent/gcc")

		c_code = "int main() { return 0; }"
		result = verifier.compile_c_code(c_code)

		assert not result.success
		assert any("not found" in err.lower() for err in result.errors)

	def test_simple_function_compiles_to_machine_code(self, verifier):
		"""Verify that compiled output contains machine code."""
		c_code = """
int return_five() {
    return 5;
}
"""

		result = verifier.compile_c_code(c_code)

		assert result.success
		assert result.binary is not None

		# Object file should have magic bytes
		# ELF (Linux): 0x7F 'E' 'L' 'F'
		# Mach-O (macOS): 0xCE 0xFA 0xED 0xFE or 0xCF 0xFA 0xED 0xFE
		assert len(result.binary) > 4
		magic = result.binary[0:4]
		# Check for either ELF or Mach-O
		assert magic == b"\x7fELF" or magic in [b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"]
