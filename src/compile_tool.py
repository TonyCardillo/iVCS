"""compile_and_view_assembly: the only tool the LLM agent gets.

compile_fn and diff_fn are injected so tests can run without spawning Wine
or objdiff-cli; default_compile_fn / default_diff_fn bind to the real
binaries via the IVCS_* environment variables documented below.
"""

import os
import re
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
    """Persists per-attempt artifacts under workspace.history_dir."""
    attempt_n = workspace.next_attempt_number()
    paths = workspace.attempt_paths(attempt_n)

    combined_source = workspace.ctx_h.read_text() + "\n" + c_code
    paths.c.write_text(combined_source)

    compile_out = compile_fn(paths.c, paths.obj, workspace.root)
    if not compile_out.success:
        return CompileAndViewResult(
            success=False,
            attempt_number=attempt_n,
            error=compile_error_format(compile_out),
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

    IVCS_MSVC_DIR (default /Users/entmoot/Code/msvc8.0p) and IVCS_WINE
    (default "wine") override the toolchain location.
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
    """IVCS_OBJDIFF_CLI (default "objdiff-cli", expected on PATH) overrides the binary."""
    cli = os.environ.get("IVCS_OBJDIFF_CLI", "objdiff-cli")
    return objdiff_run(target_obj=target, base_obj=base, symbol=symbol, cli_path=cli)


_WINE_NOISE_RE = re.compile(
    r"^\s*(\[mvk-|VK_|MoltenVK|GPU |pipelineCacheUUID|Metal Shading|"
    r"\d+:err:|\d+:fixme:|model:|type:|vendorID:|deviceID:|"
    r"supports the following|Read-Write Texture|Created VkInstance|"
    r"The following \d+ Vulkan)",
    re.IGNORECASE,
)


def _wine_noise_filter(text: str) -> str:
    """Strip MoltenVK / Vulkan / Wine chatter from a stderr stream.

    cl.exe writes diagnostics to stdout when run under Wine; Wine pollutes
    stderr with its own startup noise. We want to drop that noise so the
    LLM sees real compiler errors instead of pages of Vulkan extensions.
    """
    if not text:
        return ""
    kept: list[str] = []
    for line in text.splitlines():
        if _WINE_NOISE_RE.match(line):
            continue
        # Indented continuation lines that follow a Vulkan/MoltenVK block.
        if line.startswith("\t") and kept and not kept[-1]:
            continue
        kept.append(line)
    # Collapse runs of blank lines.
    out: list[str] = []
    for line in kept:
        if line.strip() == "" and out and out[-1].strip() == "":
            continue
        out.append(line)
    return "\n".join(out).strip()


def compile_error_format(out: CompileOutput) -> str:
    """Build a clean error message for the LLM from a failed compile.

    cl.exe writes real errors to stdout. Wine writes its own noise to
    stderr. Prefer stdout; append filtered stderr only if non-empty after
    noise removal.
    """
    parts: list[str] = []
    if out.stdout and out.stdout.strip():
        parts.append(out.stdout.strip())
    cleaned_stderr = _wine_noise_filter(out.stderr)
    if cleaned_stderr:
        parts.append("--- stderr ---\n" + cleaned_stderr)
    return "\n".join(parts) or "compile failed (no output)"


def _winepath(wine: str, unix_path: str) -> str:
    result = subprocess.run(
        [wine, "winepath", "-w", unix_path],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    return result.stdout.strip()
