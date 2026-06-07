"""Tests for the matching-decomp agent loop.

The loop drives an LLM (via a pluggable LLMClient) and the
compile_and_view_assembly tool against a single function. Tests
inject a FakeLLMClient with scripted responses and fake compile/diff
functions, so no Wine / cl.exe / objdiff-cli are needed.
"""

import json
from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st

from src.core.workspace import FunctionWorkspace
from src.decomp.agent_loop import (
	COMPILE_TOOL_NAME,
	AgentConfig,
	LLMClientError,
	_extract_c_code,
	_prior_best,
	_tool_call_id,
	agent_loop_run,
	ghidra_only_run,
)
from src.decomp.compile_tool import CompileOutput
from src.decomp.inline_asm import AsmBudget
from src.decomp.objdiff import (
	SYMBOL_KIND_FUNCTION,
	DiffInstruction,
	DiffInstructionRow,
	DiffKind,
	DiffResult,
	DiffSide,
	DiffSymbol,
)
from tests.decomp._fakes import (
	FakeLLMClient,
	assistant_text,
	assistant_tool_call,
)


def _make_workspace(tmp_path: Path, fn_name: str = "_classify") -> FunctionWorkspace:
	ws = FunctionWorkspace(root=tmp_path / "ws", function_name=fn_name)
	ws.initialize()
	ws.target_obj.write_bytes(b"\x00" * 16)
	ws.ctx_h.write_text("// kernel signatures\n")
	return ws


def _compile_ok(c_path: Path, obj_path: Path, root: Path) -> CompileOutput:
	obj_path.write_bytes(b"\x90" * 8)
	return CompileOutput(success=True)


def _compile_fail(c_path: Path, obj_path: Path, root: Path) -> CompileOutput:
	return CompileOutput(success=False, stderr="error C2143: syntax error\n")


def _diff_with_match_percent(symbol: str, match_percent: float) -> DiffResult:
	return DiffResult(
		left=DiffSide(
			symbols=(
				DiffSymbol(
					name=symbol,
					kind=SYMBOL_KIND_FUNCTION,
					match_percent=match_percent,
					instructions=(
						DiffInstructionRow(
							diff_kind=DiffKind.NONE,
							instruction=DiffInstruction(formatted="ret", mnemonic="ret"),
						),
					),
				),
			)
		)
	)


def _scripted_diff(*scores: float):
	"""Returns a diff_fn whose call N (0-indexed) yields the Nth score."""
	state = {"call": 0}

	def diff_fn(target, base, symbol):
		score = scores[state["call"]]
		state["call"] += 1
		return _diff_with_match_percent(symbol, score)

	return diff_fn


def _make_config(**overrides) -> AgentConfig:
	base = {
		"model": "fake/local",
		"max_iterations": 5,
		"hard_timeout_seconds": 60.0,
	}
	base.update(overrides)
	return AgentConfig(**base)


class TestImmediateMatch:
	def test_match_on_first_iteration(self, tmp_path):
		ws = _make_workspace(tmp_path)
		llm = FakeLLMClient(
			[
				assistant_tool_call(
					"compile_and_view_assembly", {"c_code": "int classify(int x){return x;}\n"}
				)
			]
		)
		result = agent_loop_run(
			workspace=ws,
			target_asm="ret",
			config=_make_config(),
			llm_client=llm,
			compile_fn=_compile_ok,
			diff_fn=_scripted_diff(100.0),
		)
		assert result.success is True
		assert result.best_match_percent == 100.0
		assert result.termination_reason == "matched"
		assert result.iterations == 1

	def test_match_at_or_above_100_finalizes_matched_example(self, tmp_path):
		# A diff percent at/above 100 (objdiff emits an unclamped float) must
		# finalize as matched, consistent with project.py's `>= 100.0` aggregator
		# threshold. An exact `== 100.0` check would loop forever on float noise.
		ws = _make_workspace(tmp_path)
		llm = FakeLLMClient(
			[
				assistant_tool_call(
					"compile_and_view_assembly", {"c_code": "int classify(int x){return x;}\n"}
				)
			]
		)
		result = agent_loop_run(
			workspace=ws,
			target_asm="ret",
			config=_make_config(),
			llm_client=llm,
			compile_fn=_compile_ok,
			diff_fn=_scripted_diff(100.0000001),
		)
		assert result.termination_reason == "matched"
		assert result.success is True

	def test_best_c_written_on_match(self, tmp_path):
		ws = _make_workspace(tmp_path)
		c_code = "int classify(int x){return x;}\n"
		llm = FakeLLMClient([assistant_tool_call("compile_and_view_assembly", {"c_code": c_code})])
		agent_loop_run(
			workspace=ws,
			target_asm="ret",
			config=_make_config(),
			llm_client=llm,
			compile_fn=_compile_ok,
			diff_fn=_scripted_diff(100.0),
		)
		assert ws.best_c.is_file()
		assert ws.best_c.read_text() == c_code

	def test_result_json_written(self, tmp_path):
		ws = _make_workspace(tmp_path)
		llm = FakeLLMClient(
			[assistant_tool_call("compile_and_view_assembly", {"c_code": "int x;\n"})]
		)
		agent_loop_run(
			workspace=ws,
			target_asm="ret",
			config=_make_config(),
			llm_client=llm,
			compile_fn=_compile_ok,
			diff_fn=_scripted_diff(100.0),
		)
		assert ws.result_json.is_file()
		data = json.loads(ws.result_json.read_text())
		assert data["success"] is True
		assert data["best_match_percent"] == 100.0
		assert data["model"] == "fake/local"


class TestCompileError:
	def test_compile_error_recovered(self, tmp_path):
		ws = _make_workspace(tmp_path)
		compile_calls = {"n": 0}

		def compile_fn(c_path, obj_path, root):
			compile_calls["n"] += 1
			if compile_calls["n"] == 1:
				return _compile_fail(c_path, obj_path, root)
			return _compile_ok(c_path, obj_path, root)

		llm = FakeLLMClient(
			[
				assistant_tool_call("compile_and_view_assembly", {"c_code": "broken("}),
				assistant_tool_call(
					"compile_and_view_assembly", {"c_code": "int classify(int x){return x;}\n"}
				),
			]
		)
		result = agent_loop_run(
			workspace=ws,
			target_asm="ret",
			config=_make_config(),
			llm_client=llm,
			compile_fn=compile_fn,
			diff_fn=_scripted_diff(100.0),
		)
		assert result.success is True
		assert result.iterations == 2


class TestLLMTransportError:
	def test_llm_error_finalizes_without_propagating_and_keeps_best_example(self, tmp_path):
		# A hung/unreachable LLM endpoint surfaces as LLMClientError from complete().
		# The loop must catch it, finalize with reason "llm_error", and preserve the
		# standing best — not let the exception unwind agent_loop_run and lose the run.
		ws = _make_workspace(tmp_path, fn_name="_foo")
		best_c = "int foo(){return 0;}\n"

		class FlakyClient:
			def __init__(self):
				self.calls = 0

			def complete(self, messages, tools):
				self.calls += 1
				if self.calls == 1:
					return assistant_tool_call("compile_and_view_assembly", {"c_code": best_c})
				raise LLMClientError("endpoint timed out after 240s")

		result = agent_loop_run(
			workspace=ws,
			target_asm="ret",
			config=_make_config(max_iterations=5),
			llm_client=FlakyClient(),
			compile_fn=_compile_ok,
			diff_fn=_scripted_diff(60.0),
		)
		assert result.termination_reason == "llm_error"
		assert result.success is False
		assert result.best_match_percent == 60.0
		assert ws.best_c.read_text() == best_c


class TestBudgetExhausted:
	def test_budget_exhausted_persists_best(self, tmp_path):
		ws = _make_workspace(tmp_path, fn_name="_foo")
		c_codes = [
			"// attempt 1\nint foo() { return 0; }\n",
			"// attempt 2 (best)\nint foo() { return 1; }\n",
			"// attempt 3 (regression)\nint foo() { return 2; }\n",
		]
		llm = FakeLLMClient(
			[assistant_tool_call("compile_and_view_assembly", {"c_code": c}) for c in c_codes]
		)
		result = agent_loop_run(
			workspace=ws,
			target_asm="ret",
			config=_make_config(max_iterations=3),
			llm_client=llm,
			compile_fn=_compile_ok,
			diff_fn=_scripted_diff(40.0, 75.0, 25.0),
		)
		assert result.success is False
		assert result.best_match_percent == 75.0
		assert result.termination_reason == "budget_exhausted"
		# best.c should be the attempt that scored 75%, not the latest one.
		assert ws.best_c.read_text() == c_codes[1]


class TestBestSoFar:
	def test_score_regression_does_not_overwrite_best(self, tmp_path):
		ws = _make_workspace(tmp_path, fn_name="_foo")
		c_codes = ["// 50%\n", "// 80%\n", "// 40%\n"]
		llm = FakeLLMClient(
			[assistant_tool_call("compile_and_view_assembly", {"c_code": c}) for c in c_codes]
		)
		agent_loop_run(
			workspace=ws,
			target_asm="ret",
			config=_make_config(max_iterations=3),
			llm_client=llm,
			compile_fn=_compile_ok,
			diff_fn=_scripted_diff(50.0, 80.0, 40.0),
		)
		assert ws.best_c.read_text() == c_codes[1]  # the 80% one

	def test_ties_keep_first_winner(self, tmp_path):
		ws = _make_workspace(tmp_path, fn_name="_foo")
		c_codes = ["// first 60\n", "// second 60\n"]
		llm = FakeLLMClient(
			[assistant_tool_call("compile_and_view_assembly", {"c_code": c}) for c in c_codes]
		)
		agent_loop_run(
			workspace=ws,
			target_asm="ret",
			config=_make_config(max_iterations=2),
			llm_client=llm,
			compile_fn=_compile_ok,
			diff_fn=_scripted_diff(60.0, 60.0),
		)
		# First winner stays; a tie does not overwrite (strict >).
		assert ws.best_c.read_text() == c_codes[0]


class TestModelByAttempt:
	def test_attempt_tagged_with_model_sidecar(self, tmp_path):
		ws = _make_workspace(tmp_path, fn_name="_foo")
		llm = FakeLLMClient(
			[assistant_tool_call("compile_and_view_assembly", {"c_code": "// a\n"})]
		)
		agent_loop_run(
			workspace=ws,
			target_asm="ret",
			config=_make_config(model="claude-haiku-4-5", max_iterations=1),
			llm_client=llm,
			compile_fn=_compile_ok,
			diff_fn=_scripted_diff(60.0),
		)
		assert ws.attempt_model_path(1).read_text() == "claude-haiku-4-5"

	def test_failed_compile_attempt_still_tagged(self, tmp_path):
		ws = _make_workspace(tmp_path, fn_name="_foo")
		llm = FakeLLMClient(
			[assistant_tool_call("compile_and_view_assembly", {"c_code": "// bad\n"})]
		)
		agent_loop_run(
			workspace=ws,
			target_asm="ret",
			config=_make_config(model="local", max_iterations=1),
			llm_client=llm,
			compile_fn=_compile_fail,
			diff_fn=_scripted_diff(),
		)
		assert ws.attempt_model_path(1).read_text() == "local"

	def test_result_json_records_best_model(self, tmp_path):
		ws = _make_workspace(tmp_path, fn_name="_foo")
		llm = FakeLLMClient(
			[assistant_tool_call("compile_and_view_assembly", {"c_code": "// a\n"})]
		)
		agent_loop_run(
			workspace=ws,
			target_asm="ret",
			config=_make_config(model="local", max_iterations=1),
			llm_client=llm,
			compile_fn=_compile_ok,
			diff_fn=_scripted_diff(70.0),
		)
		data = json.loads(ws.result_json.read_text())
		assert data["best_match_percent"] == 70.0
		assert data["model"] == "local"

	def test_all_attempts_fail_attributes_running_model_not_null(self, tmp_path):
		# A run where nothing compiles still records the model that ran — never
		# "model": null, which would lose attribution the whole design promises.
		ws = _make_workspace(tmp_path, fn_name="_foo")
		llm = FakeLLMClient(
			[assistant_tool_call("compile_and_view_assembly", {"c_code": "broken("})]
		)
		result = agent_loop_run(
			workspace=ws,
			target_asm="ret",
			config=_make_config(model="local", max_iterations=1),
			llm_client=llm,
			compile_fn=_compile_fail,
			diff_fn=_scripted_diff(),
		)
		assert result.success is False
		assert result.best_match_percent is None
		data = json.loads(ws.result_json.read_text())
		assert data["model"] == "local"

	def test_weaker_rerun_keeps_stronger_model_and_best_c(self, tmp_path):
		# Two AIs attack one function across two runs on the same workspace.
		# Model "alpha" reaches 80%; a later "beta" run only reaches 50%.
		# best.c and the recorded model must stay alpha's — its solution won.
		ws = _make_workspace(tmp_path, fn_name="_foo")
		agent_loop_run(
			workspace=ws,
			target_asm="ret",
			config=_make_config(model="alpha", max_iterations=1),
			llm_client=FakeLLMClient(
				[assistant_tool_call("compile_and_view_assembly", {"c_code": "// alpha 80\n"})]
			),
			compile_fn=_compile_ok,
			diff_fn=_scripted_diff(80.0),
		)
		result = agent_loop_run(
			workspace=ws,
			target_asm="ret",
			config=_make_config(model="beta", max_iterations=1),
			llm_client=FakeLLMClient(
				[assistant_tool_call("compile_and_view_assembly", {"c_code": "// beta 50\n"})]
			),
			compile_fn=_compile_ok,
			diff_fn=_scripted_diff(50.0),
		)
		assert result.best_match_percent == 80.0
		assert ws.best_c.read_text() == "// alpha 80\n"
		data = json.loads(ws.result_json.read_text())
		assert data["best_match_percent"] == 80.0
		assert data["model"] == "alpha"

	def test_stronger_rerun_takes_over_model_and_best_c(self, tmp_path):
		# The reverse: a later "beta" run beats alpha's 50% with 90%.
		ws = _make_workspace(tmp_path, fn_name="_foo")
		agent_loop_run(
			workspace=ws,
			target_asm="ret",
			config=_make_config(model="alpha", max_iterations=1),
			llm_client=FakeLLMClient(
				[assistant_tool_call("compile_and_view_assembly", {"c_code": "// alpha 50\n"})]
			),
			compile_fn=_compile_ok,
			diff_fn=_scripted_diff(50.0),
		)
		agent_loop_run(
			workspace=ws,
			target_asm="ret",
			config=_make_config(model="beta", max_iterations=1),
			llm_client=FakeLLMClient(
				[assistant_tool_call("compile_and_view_assembly", {"c_code": "// beta 90\n"})]
			),
			compile_fn=_compile_ok,
			diff_fn=_scripted_diff(90.0),
		)
		assert ws.best_c.read_text() == "// beta 90\n"
		data = json.loads(ws.result_json.read_text())
		assert data["model"] == "beta"


class TestBaselineCompileAttemptZero:
	def test_noop_when_no_attempt_zero_c(self, tmp_path):
		from src.decomp.agent_loop import _baseline_compile_attempt_zero

		ws = _make_workspace(tmp_path)
		calls = {"n": 0}

		def fake_compile(c, o, root):
			calls["n"] += 1
			return CompileOutput(success=True)

		_baseline_compile_attempt_zero(ws, compile_fn=fake_compile)
		assert calls["n"] == 0

	def test_skips_if_obj_already_present(self, tmp_path):
		from src.decomp.agent_loop import _baseline_compile_attempt_zero

		ws = _make_workspace(tmp_path)
		ws.attempt_paths(0).c.write_text("// already compiled")
		ws.attempt_paths(0).obj.write_bytes(b"\x90" * 8)
		calls = {"n": 0}

		def fake_compile(c, o, root):
			calls["n"] += 1
			return CompileOutput(success=True)

		_baseline_compile_attempt_zero(ws, compile_fn=fake_compile)
		assert calls["n"] == 0

	def test_compiles_when_c_present_no_obj(self, tmp_path):
		from src.decomp.agent_loop import _baseline_compile_attempt_zero

		ws = _make_workspace(tmp_path)
		ws.attempt_paths(0).c.write_text("void fn(void){}")

		def fake_compile(c, o, root):
			o.write_bytes(b"\x90" * 4)
			return CompileOutput(success=True)

		_baseline_compile_attempt_zero(ws, compile_fn=fake_compile)
		assert ws.attempt_paths(0).obj.is_file()

	def test_persists_stderr_on_compile_failure(self, tmp_path):
		from src.decomp.agent_loop import _baseline_compile_attempt_zero

		ws = _make_workspace(tmp_path)
		ws.attempt_paths(0).c.write_text("garbage")

		def fake_compile(c, o, root):
			return CompileOutput(success=False, stderr="error C2143: oh no")

		_baseline_compile_attempt_zero(ws, compile_fn=fake_compile)
		stderr_path = ws.attempt_paths(0).c.with_suffix(".stderr")
		assert stderr_path.is_file()
		assert "C2143" in stderr_path.read_text()


class TestGhidraWarmstartInSystemPrompt:
	def test_section_omitted_when_warmstart_absent(self, tmp_path):
		from src.decomp.agent_loop import _system_prompt_build

		ws = _make_workspace(tmp_path)
		prompt = _system_prompt_build(ws, "ret", AsmBudget())
		assert "Ghidra warm-start" not in prompt

	def test_section_included_when_warmstart_present(self, tmp_path):
		from src.decomp.agent_loop import _system_prompt_build

		ws = _make_workspace(tmp_path)
		ws.ghidra_warmstart.write_text("void FUN_002d0cf5(int param_1) { return; }\n")
		prompt = _system_prompt_build(ws, "ret", AsmBudget())
		assert "Ghidra warm-start draft" in prompt
		# FUN_ renamed to fn_ in the prompt copy so callee names match ctx.h.
		assert "fn_002D0CF5" in prompt
		assert "FUN_002d0cf5" not in prompt
		# Fenced as C so the model treats it as code.
		assert "```c" in prompt

	def test_warmstart_appears_after_ctx_h(self, tmp_path):
		from src.decomp.agent_loop import _system_prompt_build

		ws = _make_workspace(tmp_path)
		ws.ctx_h.write_text("// CTX_MARKER\n")
		ws.ghidra_warmstart.write_text("// WARMSTART_MARKER\n")
		prompt = _system_prompt_build(ws, "ret", AsmBudget())
		# ctx.h before warm-start: model sees types before the draft that uses them.
		assert prompt.index("CTX_MARKER") < prompt.index("WARMSTART_MARKER")

	def test_target_asm_is_code_fenced(self, tmp_path):
		from src.decomp.agent_loop import _system_prompt_build

		ws = _make_workspace(tmp_path)
		prompt = _system_prompt_build(ws, "0x00012080  c3  ret", AsmBudget())
		# asm should appear inside a ```asm fence so the model treats it
		# as code and so markdown-aware viewers don't reinterpret it.
		assert "```asm" in prompt
		asm_start = prompt.index("```asm")
		asm_end = prompt.index("```", asm_start + 6)
		between = prompt[asm_start:asm_end]
		assert "ret" in between

	def test_ctx_h_is_code_fenced(self, tmp_path):
		from src.decomp.agent_loop import _system_prompt_build

		ws = _make_workspace(tmp_path)
		ws.ctx_h.write_text("typedef int MARKER;\n")
		prompt = _system_prompt_build(ws, "ret", AsmBudget())
		# ctx.h section gets a ```c fence.
		ctx_idx = prompt.index("Context header")
		fence_idx = prompt.index("```c", ctx_idx)
		assert "MARKER" in prompt[fence_idx : fence_idx + 200]


class TestGhidraOnlyRun:
	def test_returns_ghidra_unavailable_when_no_attempt_zero(self, tmp_path):
		ws = _make_workspace(tmp_path)
		result = ghidra_only_run(
			workspace=ws,
			compile_fn=_compile_ok,
			diff_fn=_scripted_diff(),
		)
		assert result.success is False
		assert result.termination_reason == "ghidra_unavailable"
		assert result.best_match_percent is None
		data = json.loads(ws.result_json.read_text())
		assert data["model"] == "ghidra"

	def test_returns_compile_failed_when_baseline_doesnt_compile(self, tmp_path):
		ws = _make_workspace(tmp_path)
		ws.attempt_paths(0).c.write_text("garbage")
		result = ghidra_only_run(
			workspace=ws,
			compile_fn=_compile_fail,
			diff_fn=_scripted_diff(),
		)
		assert result.termination_reason == "compile_failed"
		assert result.best_match_percent is None
		data = json.loads(ws.result_json.read_text())
		assert data["model"] == "ghidra"

	def test_records_match_percent_for_partial_baseline(self, tmp_path):
		ws = _make_workspace(tmp_path, fn_name="_classify")
		ws.attempt_paths(0).c.write_text("int classify(int x){return x;}\n")
		result = ghidra_only_run(
			workspace=ws,
			compile_fn=_compile_ok,
			diff_fn=_scripted_diff(43.7),
		)
		assert result.termination_reason == "ghidra_only"
		assert result.best_match_percent == 43.7
		assert result.success is False
		data = json.loads(ws.result_json.read_text())
		assert data["best_match_percent"] == 43.7
		assert data["model"] == "ghidra"

	def test_full_match_baseline_reports_success(self, tmp_path):
		ws = _make_workspace(tmp_path, fn_name="_classify")
		ws.attempt_paths(0).c.write_text("// matches perfectly\n")
		ws.ghidra_warmstart.write_text("// matches perfectly\n")
		result = ghidra_only_run(
			workspace=ws,
			compile_fn=_compile_ok,
			diff_fn=_scripted_diff(100.0),
		)
		assert result.success is True
		assert result.termination_reason == "matched"
		assert result.best_match_percent == 100.0
		# best.c gets written so the aggregator counts this as a real match.
		assert ws.best_c.is_file()

	def test_full_match_at_or_above_100_reports_success_example(self, tmp_path):
		# Same `>= 100.0` threshold as the agent loop / aggregator: a float at or
		# just above 100 still counts as a full ghidra-only match.
		ws = _make_workspace(tmp_path, fn_name="_classify")
		ws.attempt_paths(0).c.write_text("// matches perfectly\n")
		ws.ghidra_warmstart.write_text("// matches perfectly\n")
		result = ghidra_only_run(
			workspace=ws,
			compile_fn=_compile_ok,
			diff_fn=_scripted_diff(100.0000001),
		)
		assert result.success is True
		assert result.termination_reason == "matched"
		assert ws.best_c.is_file()

	def test_best_c_is_normalized_source_not_raw_draft(self, tmp_path):
		# The bug: best.c was saved from the raw Ghidra draft (undefined4/FUN_/DAT_,
		# won't recompile) instead of the normalized 0000.c that actually matched.
		# best.c must be attempt-0's source minus the ctx.h preamble.
		ws = _make_workspace(tmp_path, fn_name="_fn_003808BE")
		ctx = ws.ctx_h.read_text()
		normalized = "void fn_003808BE(USHORT *p, USHORT v)\n{\n  *p = *p | v;\n}\n"
		ws.attempt_paths(0).c.write_text(ctx + "\n" + normalized)
		ws.ghidra_warmstart.write_text(
			"undefined4 __fastcall FUN_003808be(ushort *param_1)\n{\n  return DAT_00480118;\n}\n"
		)
		result = ghidra_only_run(
			workspace=ws, compile_fn=_compile_ok, diff_fn=_scripted_diff(100.0)
		)
		assert result.success is True
		best = ws.best_c.read_text()
		assert best == normalized
		assert "undefined4" not in best and "FUN_" not in best and "DAT_" not in best

	def test_canonicalizes_cached_obj_symbol_before_diff(self, tmp_path):
		# The reported bug: a cached 0000.obj carries a stale defined-symbol name
		# (e.g. an `@8` stdcall decoration from Ghidra's param guess) that no
		# longer matches the current workspace name (`@4` from the binary's ret).
		# _baseline_compile_attempt_zero early-returns when the obj exists, so it
		# never re-canonicalizes; objdiff then can't pair the symbol and scores it
		# None — counted as a phantom no-match. ghidra_only_run must canonicalize
		# the obj to workspace.function_name before diffing, regardless of caching.
		from src.formats.coff import (
			IMAGE_SYM_CLASS_EXTERNAL,
			IMAGE_SYM_TYPE_FUNCTION,
			coff_object_build,
		)
		from src.formats.coff_read import coff_object_read

		ws = _make_workspace(tmp_path, fn_name="_fn_00013D50@4")
		ws.attempt_paths(0).c.write_text("int __stdcall fn_00013D50(int){return 0;}\n")
		# A real COFF obj whose defined function symbol is the STALE name.
		stale = coff_object_build(b"\xc2\x04\x00", "_fn_00013D50@8", [])
		ws.attempt_paths(0).obj.write_bytes(stale)

		seen = {}

		def diff_fn(target, base, symbol):
			co = coff_object_read(Path(base).read_bytes())
			seen["base_defined"] = [
				s.name
				for s in co.symbols
				if s.storage_class == IMAGE_SYM_CLASS_EXTERNAL
				and s.section_number > 0
				and s.type == IMAGE_SYM_TYPE_FUNCTION
			]
			return _diff_with_match_percent(symbol, 29.25)

		result = ghidra_only_run(workspace=ws, compile_fn=_compile_ok, diff_fn=diff_fn)

		# The obj handed to objdiff must carry the canonical workspace name, so the
		# symbol pairs and the real partial match (29.25%) is recorded — not None.
		assert seen["base_defined"] == ["_fn_00013D50@4"]
		assert result.best_match_percent == 29.25

	def test_unavailable_baseline_keeps_prior_model_attribution(self, tmp_path):
		# The reported bug: a real model already earned the standing best (40% via
		# haiku across several attempts), then a ghidra-only pass ran where the
		# warm-start was unavailable. ghidra_only_run must NOT clobber result.json's
		# model -> "ghidra" / best -> None, or the UI shows "best by ghidra" and
		# "ghidra_unavailable" for a function a model actually worked.
		ws = _make_workspace(tmp_path, fn_name="_foo")
		agent_loop_run(
			workspace=ws,
			target_asm="ret",
			config=_make_config(model="claude-haiku-4-5", max_iterations=1),
			llm_client=FakeLLMClient(
				[assistant_tool_call("compile_and_view_assembly", {"c_code": "// haiku 40\n"})]
			),
			compile_fn=_compile_ok,
			diff_fn=_scripted_diff(40.0),
		)
		result = ghidra_only_run(workspace=ws, compile_fn=_compile_ok, diff_fn=_scripted_diff())
		assert result.termination_reason == "ghidra_unavailable"
		data = json.loads(ws.result_json.read_text())
		assert data["model"] == "claude-haiku-4-5"
		assert data["best_match_percent"] == 40.0
		assert ws.best_c.read_text() == "// haiku 40\n"

	def test_weaker_baseline_does_not_overwrite_stronger_prior(self, tmp_path):
		# A ghidra baseline that compiles but scores below the standing best leaves
		# the stronger model's attribution and best.c intact.
		ws = _make_workspace(tmp_path, fn_name="_foo")
		agent_loop_run(
			workspace=ws,
			target_asm="ret",
			config=_make_config(model="alpha", max_iterations=1),
			llm_client=FakeLLMClient(
				[assistant_tool_call("compile_and_view_assembly", {"c_code": "// alpha 80\n"})]
			),
			compile_fn=_compile_ok,
			diff_fn=_scripted_diff(80.0),
		)
		ws.attempt_paths(0).c.write_text("int foo(int x){return x;}\n")
		result = ghidra_only_run(workspace=ws, compile_fn=_compile_ok, diff_fn=_scripted_diff(43.7))
		assert result.best_match_percent == 80.0
		data = json.loads(ws.result_json.read_text())
		assert data["model"] == "alpha"
		assert data["best_match_percent"] == 80.0
		assert ws.best_c.read_text() == "// alpha 80\n"


class TestToollessResponse:
	def test_text_only_with_c_block_is_treated_as_tool_call(self, tmp_path):
		ws = _make_workspace(tmp_path)
		llm = FakeLLMClient(
			[
				assistant_text(
					"Sure, I'll try.\n```c\nint classify(int x){return x;}\n```\nThat should do it."
				),
			]
		)
		result = agent_loop_run(
			workspace=ws,
			target_asm="ret",
			config=_make_config(),
			llm_client=llm,
			compile_fn=_compile_ok,
			diff_fn=_scripted_diff(100.0),
		)
		assert result.success is True
		assert result.iterations == 1

	def test_text_only_no_c_block_terminates(self, tmp_path):
		ws = _make_workspace(tmp_path)
		llm = FakeLLMClient([assistant_text("I'm not sure how to start.")])
		result = agent_loop_run(
			workspace=ws,
			target_asm="ret",
			config=_make_config(),
			llm_client=llm,
			compile_fn=_compile_ok,
			diff_fn=_scripted_diff(100.0),
		)
		assert result.success is False
		assert result.termination_reason == "llm_no_progress"


class TestExtractCCode:
	# Code with no fence delimiters and no surrounding whitespace, so the two
	# encodings carry exactly the same payload.
	_code = (
		st.text(alphabet=st.characters(blacklist_characters="`"), max_size=200)
		.map(str.strip)
		.filter(bool)
	)

	@given(code=_code)
	def test_tool_call_and_fence_extract_the_same_code_oracle(self, code):
		# The same C, whether submitted as a tool call or as a ```c fence in
		# prose, must extract identically (the tool-call path is the oracle).
		via_tool = _extract_c_code(assistant_tool_call(COMPILE_TOOL_NAME, {"c_code": code}))
		via_fence = _extract_c_code(assistant_text(f"```c\n{code}\n```"))
		assert via_tool == via_fence == code

	@given(prose=st.text(alphabet=st.characters(blacklist_characters="`"), max_size=200))
	def test_returns_none_without_tool_call_or_fence_invariant(self, prose):
		assert _extract_c_code(assistant_text(prose)) is None


class TestToolCallIdAgreesWithExtractedCode:
	# _tool_call_id and _extract_c_code must agree on what "the tool call" is:
	# the compile tool. Otherwise a role:"tool" reply gets paired to a tool_use
	# the assistant never made for the compile tool — a malformed transcript.
	def test_foreign_tool_call_with_fence_has_no_compile_call_id(self):
		response = {
			"role": "assistant",
			"content": "```c\nint f(void){return 0;}\n```",
			"tool_calls": [
				{
					"id": "call_foreign",
					"type": "function",
					"function": {"name": "some_other_tool", "arguments": "{}"},
				}
			],
		}
		# Code is fence-sourced (the foreign call isn't the compile tool)...
		assert _extract_c_code(response) == "int f(void){return 0;}"
		# ...so there is no compile tool_call to pair a tool reply to.
		assert _tool_call_id(response) is None

	def test_compile_tool_call_id_returned_when_present(self):
		response = assistant_tool_call(
			COMPILE_TOOL_NAME, {"c_code": "int x;\n"}, tool_call_id="call_42"
		)
		assert _tool_call_id(response) == "call_42"


class TestPriorBestReconcile:
	"""_prior_best must recover from a clobbered result.json so a re-run inherits
	the true standing best (and never re-writes a weaker summary)."""

	def _write_diff(self, history: Path, n: int, pct: float, model: str) -> None:
		history.mkdir(parents=True, exist_ok=True)
		(history / f"{n:04d}.c").write_text(f"// {n}\n")
		(history / f"{n:04d}.diff.json").write_text(
			json.dumps(
				{
					"left": {
						"symbols": [
							{"name": "_foo", "kind": "SYMBOL_FUNCTION", "match_percent": pct}
						]
					}
				}
			)
		)
		(history / f"{n:04d}.model").write_text(model)

	def test_recovers_best_when_result_json_clobbered_to_null_example(self, tmp_path):
		ws = _make_workspace(tmp_path, fn_name="_foo")
		self._write_diff(ws.history_dir, 1, 79.8, "alpha")
		ws.result_json.write_text(
			json.dumps({"success": False, "best_match_percent": None, "model": "beta"})
		)
		best, model = _prior_best(ws)
		assert best == 79.8
		assert model == "alpha"

	def test_result_json_wins_when_stronger_than_history_example(self, tmp_path):
		ws = _make_workspace(tmp_path, fn_name="_foo")
		self._write_diff(ws.history_dir, 1, 40.0, "alpha")
		ws.result_json.write_text(
			json.dumps({"success": False, "best_match_percent": 90.0, "model": "beta"})
		)
		best, model = _prior_best(ws)
		assert best == 90.0
		assert model == "beta"
