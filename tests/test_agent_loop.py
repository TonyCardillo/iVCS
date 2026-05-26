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
            [assistant_tool_call("compile_and_view_assembly", {"c_code": "int classify(int x){return x;}\n"})]
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
                assistant_tool_call("compile_and_view_assembly", {"c_code": "int classify(int x){return x;}\n"}),
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
