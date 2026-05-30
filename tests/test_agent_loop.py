"""Tests for the matching-decomp agent loop.

The loop drives an LLM (via a pluggable LLMClient) and the
compile_and_view_assembly tool against a single function. Tests
inject a FakeLLMClient with scripted responses and fake compile/diff
functions, so no Wine / cl.exe / objdiff-cli are needed.
"""

import json
from pathlib import Path

from src.agent_loop import (
	AgentConfig,
	FakeLLMClient,
	agent_loop_run,
	assistant_text,
	assistant_tool_call,
	ghidra_only_run,
)
from src.compile_tool import CompileOutput
from src.objdiff import (
	SYMBOL_KIND_FUNCTION,
	DiffInstruction,
	DiffInstructionRow,
	DiffKind,
	DiffResult,
	DiffSide,
	DiffSymbol,
)
from src.workspace import FunctionWorkspace


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
		"api_base": "http://127.0.0.1:1234/v1",
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
		from src.agent_loop import _baseline_compile_attempt_zero

		ws = _make_workspace(tmp_path)
		calls = {"n": 0}

		def fake_compile(c, o, root):
			calls["n"] += 1
			return CompileOutput(success=True)

		_baseline_compile_attempt_zero(ws, compile_fn=fake_compile)
		assert calls["n"] == 0

	def test_skips_if_obj_already_present(self, tmp_path):
		from src.agent_loop import _baseline_compile_attempt_zero

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
		from src.agent_loop import _baseline_compile_attempt_zero

		ws = _make_workspace(tmp_path)
		ws.attempt_paths(0).c.write_text("void fn(void){}")

		def fake_compile(c, o, root):
			o.write_bytes(b"\x90" * 4)
			return CompileOutput(success=True)

		_baseline_compile_attempt_zero(ws, compile_fn=fake_compile)
		assert ws.attempt_paths(0).obj.is_file()

	def test_persists_stderr_on_compile_failure(self, tmp_path):
		from src.agent_loop import _baseline_compile_attempt_zero

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
		from src.agent_loop import _system_prompt_build

		ws = _make_workspace(tmp_path)
		prompt = _system_prompt_build(ws, "ret")
		assert "Ghidra warm-start" not in prompt

	def test_section_included_when_warmstart_present(self, tmp_path):
		from src.agent_loop import _system_prompt_build

		ws = _make_workspace(tmp_path)
		ws.ghidra_warmstart.write_text("void FUN_002d0cf5(int param_1) { return; }\n")
		prompt = _system_prompt_build(ws, "ret")
		assert "Ghidra warm-start draft" in prompt
		# FUN_ renamed to fn_ in the prompt copy so callee names match ctx.h.
		assert "fn_002D0CF5" in prompt
		assert "FUN_002d0cf5" not in prompt
		# Fenced as C so the model treats it as code.
		assert "```c" in prompt

	def test_warmstart_appears_after_ctx_h(self, tmp_path):
		from src.agent_loop import _system_prompt_build

		ws = _make_workspace(tmp_path)
		ws.ctx_h.write_text("// CTX_MARKER\n")
		ws.ghidra_warmstart.write_text("// WARMSTART_MARKER\n")
		prompt = _system_prompt_build(ws, "ret")
		# ctx.h before warm-start: model sees types before the draft that uses them.
		assert prompt.index("CTX_MARKER") < prompt.index("WARMSTART_MARKER")

	def test_target_asm_is_code_fenced(self, tmp_path):
		from src.agent_loop import _system_prompt_build

		ws = _make_workspace(tmp_path)
		prompt = _system_prompt_build(ws, "0x00012080  c3  ret")
		# asm should appear inside a ```asm fence so the model treats it
		# as code and so markdown-aware viewers don't reinterpret it.
		assert "```asm" in prompt
		asm_start = prompt.index("```asm")
		asm_end = prompt.index("```", asm_start + 6)
		between = prompt[asm_start:asm_end]
		assert "ret" in between

	def test_ctx_h_is_code_fenced(self, tmp_path):
		from src.agent_loop import _system_prompt_build

		ws = _make_workspace(tmp_path)
		ws.ctx_h.write_text("typedef int MARKER;\n")
		prompt = _system_prompt_build(ws, "ret")
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
