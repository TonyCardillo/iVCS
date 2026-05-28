"""Tests for compile_and_view_assembly.

The orchestration takes compile_fn and diff_fn as parameters so tests
can inject fakes without spawning real wine / cl.exe / objdiff-cli.
Defaults live in default_compile_fn / default_diff_fn and are
exercised in the recon scripts, not here.
"""

from pathlib import Path

from src.compile_tool import CompileOutput, compile_and_view_assembly, compile_error_format
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
    ws.ctx_h.write_text("// kernel signatures and types here\n")
    return ws


def _fake_compile_ok(c_path: Path, obj_path: Path, root: Path) -> CompileOutput:
    obj_path.write_bytes(b"\x90" * 8)
    return CompileOutput(success=True, stdout="", stderr="")


def _fake_compile_fail(c_path: Path, obj_path: Path, root: Path) -> CompileOutput:
    return CompileOutput(
        success=False,
        stdout="",
        stderr="hello.c(5): error C2143: syntax error : missing ';' before '{'\n",
    )


def _fake_diff_match(target: Path, base: Path, symbol: str) -> DiffResult:
    return DiffResult(
        left=DiffSide(
            symbols=(
                DiffSymbol(
                    name=symbol,
                    kind=SYMBOL_KIND_FUNCTION,
                    match_percent=100.0,
                    instructions=(),
                ),
            )
        )
    )


def _fake_diff_partial(target: Path, base: Path, symbol: str) -> DiffResult:
    rows = (
        DiffInstructionRow(
            diff_kind=DiffKind.NONE,
            instruction=DiffInstruction(formatted="mov eax, ebx", mnemonic="mov"),
        ),
        DiffInstructionRow(
            diff_kind=DiffKind.ARG_MISMATCH,
            instruction=DiffInstruction(formatted="jl short 0x10", mnemonic="jl"),
            arg_diff_indices=(1,),
        ),
    )
    return DiffResult(
        left=DiffSide(
            symbols=(
                DiffSymbol(
                    name=symbol,
                    kind=SYMBOL_KIND_FUNCTION,
                    match_percent=42.5,
                    instructions=rows,
                ),
            )
        )
    )


class TestSuccessfulCompile:
    def test_writes_concatenated_source(self, tmp_path):
        ws = _make_workspace(tmp_path)
        ws.ctx_h.write_text("typedef int MyInt;\n")
        result = compile_and_view_assembly(
            workspace=ws,
            c_code="int classify(int x) { return x; }\n",
            compile_fn=_fake_compile_ok,
            diff_fn=_fake_diff_match,
        )
        attempt = ws.attempt_paths(result.attempt_number)
        contents = attempt.c.read_text()
        assert "typedef int MyInt;" in contents
        assert "int classify" in contents

    def test_returns_match_percent(self, tmp_path):
        ws = _make_workspace(tmp_path)
        result = compile_and_view_assembly(
            workspace=ws,
            c_code="int classify(int x) { return x; }\n",
            compile_fn=_fake_compile_ok,
            diff_fn=_fake_diff_match,
        )
        assert result.success is True
        assert result.match_percent == 100.0
        assert result.error is None
        assert result.diff_result is not None

    def test_attempt_number_starts_at_1(self, tmp_path):
        ws = _make_workspace(tmp_path)
        result = compile_and_view_assembly(
            workspace=ws,
            c_code="int classify(int x) { return x; }\n",
            compile_fn=_fake_compile_ok,
            diff_fn=_fake_diff_match,
        )
        assert result.attempt_number == 1

    def test_attempt_number_increments(self, tmp_path):
        ws = _make_workspace(tmp_path)
        for expected in (1, 2, 3):
            result = compile_and_view_assembly(
                workspace=ws,
                c_code=f"// attempt {expected}\n",
                compile_fn=_fake_compile_ok,
                diff_fn=_fake_diff_match,
            )
            assert result.attempt_number == expected

    def test_obj_file_written(self, tmp_path):
        ws = _make_workspace(tmp_path)
        result = compile_and_view_assembly(
            workspace=ws,
            c_code="int x;\n",
            compile_fn=_fake_compile_ok,
            diff_fn=_fake_diff_match,
        )
        assert ws.attempt_paths(result.attempt_number).obj.is_file()


class TestPartialMatch:
    def test_partial_match_percent_propagated(self, tmp_path):
        ws = _make_workspace(tmp_path)
        result = compile_and_view_assembly(
            workspace=ws,
            c_code="int classify(int x) { return x; }\n",
            compile_fn=_fake_compile_ok,
            diff_fn=_fake_diff_partial,
        )
        assert result.success is True
        assert result.match_percent == 42.5

    def test_instruction_rows_accessible(self, tmp_path):
        ws = _make_workspace(tmp_path)
        result = compile_and_view_assembly(
            workspace=ws,
            c_code="int classify(int x) { return x; }\n",
            compile_fn=_fake_compile_ok,
            diff_fn=_fake_diff_partial,
        )
        fn_symbol = next(s for s in result.diff_result.function_symbols() if s.name == "_classify")
        assert len(fn_symbol.instructions) == 2
        assert fn_symbol.instructions[1].diff_kind == DiffKind.ARG_MISMATCH


class TestCompileFailure:
    def test_compile_error_returns_failure(self, tmp_path):
        ws = _make_workspace(tmp_path)
        result = compile_and_view_assembly(
            workspace=ws,
            c_code="int broken( {\n",
            compile_fn=_fake_compile_fail,
            diff_fn=_fake_diff_match,
        )
        assert result.success is False
        assert result.match_percent is None
        assert result.error is not None
        assert "error C2143" in result.error

    def test_compile_failure_still_writes_c_file(self, tmp_path):
        ws = _make_workspace(tmp_path)
        result = compile_and_view_assembly(
            workspace=ws,
            c_code="int broken( {\n",
            compile_fn=_fake_compile_fail,
            diff_fn=_fake_diff_match,
        )
        assert ws.attempt_paths(result.attempt_number).c.is_file()

    def test_compile_failure_does_not_call_diff(self, tmp_path):
        ws = _make_workspace(tmp_path)
        call_count = {"n": 0}

        def counting_diff(target, base, symbol):
            call_count["n"] += 1
            return _fake_diff_match(target, base, symbol)

        compile_and_view_assembly(
            workspace=ws,
            c_code="int broken( {\n",
            compile_fn=_fake_compile_fail,
            diff_fn=counting_diff,
        )
        assert call_count["n"] == 0


class TestSymbolNotInDiff:
    def test_unknown_symbol_match_percent_is_none(self, tmp_path):
        """If the diff is missing the function (e.g., LLM renamed it), match_percent is None."""
        ws = _make_workspace(tmp_path, fn_name="_classify")

        def diff_other_symbol(target, base, symbol):
            return DiffResult(
                left=DiffSide(
                    symbols=(
                        DiffSymbol(
                            name="_someone_else",
                            kind=SYMBOL_KIND_FUNCTION,
                            match_percent=99.0,
                            instructions=(),
                        ),
                    )
                )
            )

        result = compile_and_view_assembly(
            workspace=ws,
            c_code="int wrong_name(int x) { return x; }\n",
            compile_fn=_fake_compile_ok,
            diff_fn=diff_other_symbol,
        )
        assert result.success is True  # compile succeeded
        assert result.match_percent is None  # but our target symbol isn't there


class TestCompileErrorFormat:
    def test_uses_stdout_for_cl_errors(self):
        out = CompileOutput(
            success=False,
            stdout="src.c(12): error C2143: missing semicolon",
            stderr="",
        )
        msg = compile_error_format(out)
        assert "C2143" in msg
        assert "missing semicolon" in msg

    def test_strips_moltenvk_chatter_from_stderr(self):
        moltenvk = "\n".join((
            "[mvk-info] MoltenVK version 1.4.1",
            "\tVK_KHR_16bit_storage v1",
            "\tVK_KHR_8bit_storage v1",
            "[mvk-info] GPU device:",
            "\tmodel: Apple M4 Pro",
            "\tvendorID: 0x106b",
        ))
        out = CompileOutput(success=False, stdout="src.c(1): error C2143: bad", stderr=moltenvk)
        msg = compile_error_format(out)
        assert "C2143" in msg
        assert "MoltenVK" not in msg
        assert "VK_KHR" not in msg
        assert "Apple M4 Pro" not in msg

    def test_returns_placeholder_when_both_empty(self):
        out = CompileOutput(success=False, stdout="", stderr="")
        assert compile_error_format(out) == "compile failed (no output)"

    def test_keeps_non_noise_stderr(self):
        out = CompileOutput(
            success=False,
            stdout="",
            stderr="ld.exe: cannot find symbol _foo",
        )
        msg = compile_error_format(out)
        assert "cannot find symbol" in msg

    def test_filters_wine_err_lines(self):
        out = CompileOutput(
            success=False,
            stdout="error C2065: undeclared identifier",
            stderr="0114:err:kerberos:kerberos_LsaApInitializePackage no Kerberos support, expect problems",
        )
        msg = compile_error_format(out)
        assert "C2065" in msg
        assert "kerberos" not in msg.lower()
