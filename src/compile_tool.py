"""compile_and_view_assembly: the only tool the LLM agent gets.

Orchestrates one compile-and-diff cycle:
  1. Concatenate ctx.h + LLM-proposed C source (mizuchi pattern — no
     #include resolution; flat append at compile time).
  2. Compile via the supplied compile_fn (default: wine cl.exe).
  3. If compile failed, return the error to the LLM and skip diffing.
  4. Else, run objdiff via diff_fn (default: subprocess to objdiff-cli).
  5. Return structured CompileAndViewResult with match_percent etc.

compile_fn and diff_fn are parameters (not hardcoded) so tests can inject
fakes. The defaults in default_compile_fn / default_diff_fn shell out to
real binaries and are exercised in the recon scripts and end-to-end tests.
"""

import os
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from src.objdiff import DiffResult, objdiff_run
from src.workspace import FunctionWorkspace


@dataclass(frozen=True)
class CompileOutput:
    success: bool
    stdout: str = ""
    stderr: str = ""


@dataclass(frozen=True)
class CompileAndViewResult:
    success: bool
    attempt_number: int
    error: str | None = None
    match_percent: float | None = None
    diff_result: DiffResult | None = None


CompileFn = Callable[[Path, Path, Path], CompileOutput]
"""(c_source_path, output_obj_path, workspace_root) -> CompileOutput"""

DiffFn = Callable[[Path, Path, str], DiffResult]
"""(target_obj, base_obj, symbol_name) -> DiffResult"""


def compile_and_view_assembly(
    workspace: FunctionWorkspace,
    c_code: str,
    *,
    compile_fn: CompileFn,
    diff_fn: DiffFn,
) -> CompileAndViewResult:
    """Run one compile+diff cycle. Persists artifacts under workspace/history/."""
    attempt_n = workspace.next_attempt_number()
    paths = workspace.attempt_paths(attempt_n)

    combined_source = workspace.ctx_h.read_text() + "\n" + c_code
    paths.c.write_text(combined_source)

    compile_out = compile_fn(paths.c, paths.obj, workspace.root)
    if not compile_out.success:
        return CompileAndViewResult(
            success=False,
            attempt_number=attempt_n,
            error=compile_out.stderr or compile_out.stdout or "compile failed (no output)",
        )

    diff_result = diff_fn(workspace.target_obj, paths.obj, workspace.function_name)
    match_percent = _function_match_percent(diff_result, workspace.function_name)

    return CompileAndViewResult(
        success=True,
        attempt_number=attempt_n,
        match_percent=match_percent,
        diff_result=diff_result,
    )


def _function_match_percent(diff: DiffResult, function_name: str) -> float | None:
    for symbol in diff.function_symbols("left"):
        if symbol.name == function_name:
            return symbol.match_percent
    for symbol in diff.function_symbols("right"):
        if symbol.name == function_name:
            return symbol.match_percent
    return None


def default_compile_fn(c_source: Path, out_obj: Path, workspace_root: Path) -> CompileOutput:
    """Spawn widberg/msvc8.0p cl.exe under Wine.

    Configured by environment variables:
      IVCS_MSVC_DIR  — root of the widberg toolchain (default
                       /Users/entmoot/Code/msvc8.0p, matches recon setup)
      IVCS_WINE      — wine binary (default "wine")
    """
    msvc_dir = Path(os.environ.get("IVCS_MSVC_DIR", "/Users/entmoot/Code/msvc8.0p"))
    wine = os.environ.get("IVCS_WINE", "wine")

    msvc_w = _winepath(wine, str(msvc_dir))
    src_w = _winepath(wine, str(c_source.absolute()))
    obj_w = _winepath(wine, str(out_obj.absolute()))

    env = os.environ.copy()
    env["WINEPATH"] = f"{msvc_w}\\bin;{msvc_w}\\PlatformSDK\\bin"
    env["INCLUDE"] = (
        f"{msvc_w}\\ATLMFC\\INCLUDE;{msvc_w}\\INCLUDE;{msvc_w}\\PlatformSDK\\include"
    )
    env["LIB"] = f"{msvc_w}\\ATLMFC\\LIB;{msvc_w}\\LIB;{msvc_w}\\PlatformSDK\\lib"
    env.setdefault("WINEDEBUG", "err+all,fixme-all")

    completed = subprocess.run(
        [
            wine,
            str(msvc_dir / "bin" / "cl.exe"),
            "/nologo",
            "/c",
            "/O2",
            f"/Fo{obj_w}",
            src_w,
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )

    success = completed.returncode == 0 and out_obj.is_file()
    return CompileOutput(success=success, stdout=completed.stdout, stderr=completed.stderr)


def default_diff_fn(target: Path, base: Path, symbol: str) -> DiffResult:
    """Spawn objdiff-cli via the wrapper in src/objdiff.py.

    Configured by IVCS_OBJDIFF_CLI (default "objdiff-cli" — must be on PATH).
    """
    cli = os.environ.get("IVCS_OBJDIFF_CLI", "objdiff-cli")
    return objdiff_run(target_obj=target, base_obj=base, symbol=symbol, cli_path=cli)


def _winepath(wine: str, unix_path: str) -> str:
    """Convert a unix path to a wine-style path (Z:\\... or similar)."""
    result = subprocess.run(
        [wine, "winepath", "-w", unix_path],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    return result.stdout.strip()
