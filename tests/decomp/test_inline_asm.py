"""Tests for the inline-assembly detector and budget policy.

The decomp agent can reach a high match% by transcribing the target listing
into an MSVC `__asm` block instead of decompiling it — re-assembly, not
matching. inline_asm_scan counts the asm instructions a submission carries so
the budget policy can reject transcription while tolerating the sparse asm a
real Xbox title genuinely used (rdtsc, cpuid, int 3, ...).
"""

from hypothesis import given
from hypothesis import strategies as st

from src.decomp.inline_asm import (
	AsmBudget,
	AsmScan,
	asm_rejection_message,
	inline_asm_scan,
	is_asm_within_budget,
)

# A pool of identifiers that must never be mistaken for the __asm keyword,
# including near-misses that embed the token.
_NON_ASM_IDENTS = st.sampled_from(
	["x", "count", "result", "my__asm_helper", "asmodeus", "_asmodeus", "reasm", "p_asm_buf"]
)


class TestScanNoAsm:
	def test_plain_c_has_no_asm_example(self):
		code = "int classify(int x) { int y; y = x + 1; return y; }\n"
		assert inline_asm_scan(code).instruction_count == 0

	def test_asm_substring_in_identifier_is_not_counted_example(self):
		# `my__asm_helper` embeds the token but is a plain identifier.
		code = "int my__asm_helper(int reasm) { return reasm; }\n"
		assert inline_asm_scan(code).instruction_count == 0

	def test_asm_inside_string_literal_is_not_counted_example(self):
		code = 'const char *s = "__asm { mov eax, 1 }"; int v = 0;\n'
		assert inline_asm_scan(code).instruction_count == 0

	def test_asm_inside_line_comment_is_not_counted_example(self):
		code = "int f(void) { // __asm mov eax, 1\n return 0; }\n"
		assert inline_asm_scan(code).instruction_count == 0

	def test_asm_inside_block_comment_is_not_counted_example(self):
		code = "int f(void) { /* __asm { mov eax, 1\n add eax, 2 } */ return 0; }\n"
		assert inline_asm_scan(code).instruction_count == 0

	@given(st.lists(_NON_ASM_IDENTS, min_size=0, max_size=8))
	def test_arbitrary_non_asm_identifiers_count_zero_invariant(self, idents):
		body = " ".join(f"int {name}_{i};" for i, name in enumerate(idents))
		code = f"void f(void) {{ {body} }}\n"
		assert inline_asm_scan(code).instruction_count == 0


class TestScanCounting:
	def test_single_statement_form_counts_one_example(self):
		code = "void f(void) { __asm rdtsc\n }\n"
		assert inline_asm_scan(code).instruction_count == 1

	def test_block_counts_each_instruction_example(self):
		code = (
			"void f(void) {\n"
			"  __asm {\n"
			"    push ebp\n"
			"    mov  ebp, esp\n"
			"    xor  eax, eax\n"
			"    pop  ebp\n"
			"    ret\n"
			"  }\n"
			"}\n"
		)
		assert inline_asm_scan(code).instruction_count == 5

	def test_labels_and_asm_comments_do_not_count_example(self):
		code = (
			"void f(void) {\n"
			"  __asm {\n"
			"    xor ecx, ecx       ; zero the counter\n"
			"  loop_top:            ; a bare label line\n"
			"    inc ecx\n"
			"    cmp ecx, 10\n"
			"    jl  loop_top\n"
			"  }\n"
			"}\n"
		)
		# 4 instructions (xor, inc, cmp, jl); the label line and comments don't count.
		assert inline_asm_scan(code).instruction_count == 4

	def test_label_sharing_a_line_with_an_instruction_counts_the_instruction_example(self):
		code = "void f(void) {\n  __asm {\n  again: mov eax, ebx\n  }\n}\n"
		assert inline_asm_scan(code).instruction_count == 1

	def test_single_underscore_alias_is_counted_example(self):
		code = "void f(void) {\n  _asm {\n    nop\n    nop\n  }\n}\n"
		assert inline_asm_scan(code).instruction_count == 2

	def test_mnemonics_are_collected_distinct_example(self):
		code = "void f(void) {\n  __asm {\n    mov eax, 1\n    mov ebx, 2\n    ret\n  }\n}\n"
		scan = inline_asm_scan(code)
		assert scan.instruction_count == 3
		assert set(scan.mnemonics) == {"mov", "ret"}

	@given(st.integers(min_value=0, max_value=40))
	def test_block_count_equals_number_of_emitted_instructions_oracle(self, n):
		instrs = "\n".join("    nop" for _ in range(n))
		code = f"void f(void) {{\n  __asm {{\n{instrs}\n  }}\n}}\n"
		assert inline_asm_scan(code).instruction_count == n

	@given(st.integers(min_value=0, max_value=20), st.text(alphabet="abcdefg ;\n", max_size=30))
	def test_appending_plain_c_does_not_change_count_invariant(self, n, trailing):
		instrs = "\n".join("    inc eax" for _ in range(n))
		core = f"void f(void) {{\n  __asm {{\n{instrs}\n  }}\n}}\n"
		# `trailing` is asm-free filler; the count must be unchanged by it.
		assert inline_asm_scan(core + trailing).instruction_count == n


class TestBudgetPolicy:
	def test_zero_asm_is_always_within_budget_invariant(self):
		scan = AsmScan(instruction_count=0, mnemonics=())
		# Within budget regardless of function size or thresholds.
		assert is_asm_within_budget(scan, target_instruction_count=0, budget=AsmBudget())
		assert is_asm_within_budget(scan, target_instruction_count=500, budget=AsmBudget())

	def test_sparse_asm_in_large_function_is_allowed_example(self):
		# 2 asm instructions (rdtsc) in a 300-instruction function: under both bounds.
		scan = AsmScan(instruction_count=2, mnemonics=("rdtsc",))
		assert is_asm_within_budget(scan, target_instruction_count=300, budget=AsmBudget())

	def test_transcription_exceeds_absolute_bound_example(self):
		scan = AsmScan(instruction_count=50, mnemonics=("mov", "push"))
		assert not is_asm_within_budget(scan, target_instruction_count=200, budget=AsmBudget())

	def test_small_function_dominated_by_asm_exceeds_ratio_bound_example(self):
		# 4 asm instructions is under the absolute cap, but it's 4/6 of the
		# function — the ratio bound must still reject it.
		scan = AsmScan(instruction_count=4, mnemonics=("mov",))
		budget = AsmBudget(max_instructions=8, max_ratio=0.10)
		assert not is_asm_within_budget(scan, target_instruction_count=6, budget=budget)

	def test_unknown_target_count_falls_back_to_absolute_bound_example(self):
		# No denominator (0/unknown): ratio can't be judged, absolute bound still applies.
		under = AsmScan(instruction_count=3, mnemonics=("mov",))
		over = AsmScan(instruction_count=20, mnemonics=("mov",))
		assert is_asm_within_budget(under, target_instruction_count=0, budget=AsmBudget())
		assert not is_asm_within_budget(over, target_instruction_count=0, budget=AsmBudget())

	def test_rejection_message_states_count_budget_and_mnemonics_example(self):
		scan = AsmScan(instruction_count=50, mnemonics=("mov", "push", "ret"))
		msg = asm_rejection_message(scan, target_instruction_count=60, budget=AsmBudget())
		assert "50" in msg  # how many they used
		assert str(AsmBudget().max_instructions) in msg  # the cap
		assert "mov" in msg  # the offending mnemonics, to orient the model
		assert "C" in msg  # tells them to write C

	@given(st.integers(min_value=1, max_value=200), st.integers(min_value=1, max_value=400))
	def test_within_budget_iff_under_both_bounds_oracle(self, count, target):
		budget = AsmBudget(max_instructions=8, max_ratio=0.10)
		scan = AsmScan(instruction_count=count, mnemonics=())
		expected = count <= budget.max_instructions and (count / target) <= budget.max_ratio
		assert (
			is_asm_within_budget(scan, target_instruction_count=target, budget=budget) is expected
		)
