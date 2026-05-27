"""Launch a matching-decomp run for one function from the UI.

Carves the target function from the parsed XBE, synthesizes a fresh
target.obj, writes a minimal ctx.h (only if absent), and spawns a
daemon thread running agent_loop_run. Returns a JobInfo handle that
the caller drops into a registry. The JobInfo mutates in-place as the
thread progresses, so the UI can read state/iter/match% by reference.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

import capstone

from src.agent_loop import AgentConfig, agent_loop_run
from src.carver import carver_target_obj_build
from src.compile_tool import default_compile_fn, default_diff_fn
from src.llm_clients import LiteLLMClient
from src.project import FunctionEntry, Project
from src.workspace import FunctionWorkspace
from src.xbe import ParsedXbe, xbe_function_carve, xbe_load


_DEFAULT_CTX_H = """\
/* Minimal stub written by the launcher when no ctx.h existed.
 * Add typedefs, externs, and forward decls as the LLM needs them,
 * then re-run; the launcher won't overwrite a hand-edited ctx.h. */
typedef unsigned char    BYTE;
typedef unsigned short   WORD;
typedef unsigned long    DWORD;
typedef unsigned __int64 DWORD64;
typedef int              BOOL;
typedef long             LONG;
typedef long             NTSTATUS;
typedef unsigned int     UINT;
typedef void *           PVOID;
typedef void *           HANDLE;
typedef char *           LPSTR;
typedef const char *     LPCSTR;
"""


@dataclass
class JobInfo:
    workspace_path: Path
    function_name: str
    va: int
    size: int
    model: str
    max_iterations: int
    hard_timeout_seconds: float
    state: str = "pending"  # "pending" | "running" | "done" | "error"
    started_at: float = 0.0
    finished_at: float | None = None
    iterations_completed: int = 0
    best_match_percent: float | None = None
    termination_reason: str | None = None
    error: str | None = None
    _thread: threading.Thread | None = field(default=None, repr=False)

    def is_active(self) -> bool:
        return self.state in ("pending", "running")


def launch_decomp_job(
    project: Project,
    fn: FunctionEntry,
    *,
    model: str = "claude-haiku-4-5",
    max_iterations: int = 8,
    hard_timeout_seconds: float = 180.0,
    api_key: str | None = None,
    parsed_xbe: ParsedXbe | None = None,
) -> JobInfo:
    """Carve, prepare workspace, and spawn the agent loop in a daemon thread.

    Returns immediately after the thread starts. The returned JobInfo
    mutates as the run progresses; readers see state, iterations, and
    best_match_percent advance live.
    """
    key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError("ANTHROPIC_API_KEY not set in environment")

    parsed = parsed_xbe if parsed_xbe is not None else xbe_load(project.xbe_path)

    body = xbe_function_carve(parsed, fn.va, fn.size)
    mangled = _infer_mangled_name(body, fn.name)
    obj_bytes = carver_target_obj_build(parsed, fn.va, fn.size, mangled)
    target_asm = _disassemble_listing(parsed, fn.va, fn.size)

    workspace_path = project.workspace_for(fn)
    workspace = FunctionWorkspace(root=workspace_path, function_name=mangled)
    workspace.initialize()
    workspace.target_obj.write_bytes(obj_bytes)
    if not workspace.ctx_h.is_file():
        workspace.ctx_h.write_text(_compose_ctx_h(fn.name, mangled))

    job = JobInfo(
        workspace_path=workspace_path,
        function_name=mangled,
        va=fn.va,
        size=fn.size,
        model=model,
        max_iterations=max_iterations,
        hard_timeout_seconds=hard_timeout_seconds,
    )

    def _run() -> None:
        job.state = "running"
        job.started_at = time.time()
        try:
            llm = LiteLLMClient(model=f"anthropic/{model}", api_key=key)
            config = AgentConfig(
                model=model,
                api_base="",
                max_iterations=max_iterations,
                hard_timeout_seconds=hard_timeout_seconds,
            )
            result = agent_loop_run(
                workspace=workspace,
                target_asm=target_asm,
                config=config,
                llm_client=llm,
                compile_fn=default_compile_fn,
                diff_fn=default_diff_fn,
            )
            job.iterations_completed = result.iterations
            job.best_match_percent = result.best_match_percent
            job.termination_reason = result.termination_reason
            job.state = "done"
        except Exception as e:  # noqa: BLE001 — surface any failure to the UI
            job.error = f"{type(e).__name__}: {e}"
            job.state = "error"
        finally:
            job.finished_at = time.time()

    t = threading.Thread(target=_run, daemon=True, name=f"decomp-{fn.name}")
    job._thread = t
    t.start()
    return job


def _infer_mangled_name(body: bytes, base: str) -> str:
    """MSVC stdcall mangling from the function's first ret-style instruction.

    `ret 0` (c3) → cdecl/no-args: returns "_<base>".
    `ret <imm16>` (c2 NN NN) → stdcall: returns "_<base>@<imm>".
    No ret found in the disassembly: falls back to "_<base>".
    """
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = False
    for _addr, _size, mnem, op in md.disasm_lite(body, 0):
        if mnem == "ret":
            if op:
                try:
                    return f"_{base}@{int(op, 0)}"
                except ValueError:
                    return f"_{base}"
            return f"_{base}"
    return f"_{base}"


def _format_target_forward_decl(name: str, mangled: str) -> str | None:
    """Forward decl that pins the target's calling convention for MSVC.

    Returns None when no decl is needed: cdecl is MSVC's default, so a
    plain `int <name>(...)` definition already produces the matching
    `_<name>` symbol. For stdcall we MUST declare the function before
    the body, otherwise MSVC won't emit the `@N` suffix and the symbol
    won't pair with target.obj in objdiff.

    Uses `int` placeholders sized to the popped byte count (typically
    one int per 4 bytes). The LLM may swap to a more specific type in
    both the decl and the definition (they must agree), but the byte
    sizing must remain.
    """
    if "@" not in mangled:
        return None
    suffix = mangled.rsplit("@", 1)[1]
    try:
        byte_count = int(suffix)
    except ValueError:
        return None
    if byte_count == 0:
        return f"int __stdcall {name}(void);"
    if byte_count % 4 != 0:
        return (
            f"/* WARNING: target pops {byte_count} bytes — non-32-bit args. */\n"
            f"int __stdcall {name}(int);"
        )
    args = ", ".join(["int"] * (byte_count // 4))
    return f"int __stdcall {name}({args});"


def _compose_ctx_h(name: str, mangled: str) -> str:
    """Build the auto-stub ctx.h: typedefs plus the target's forward decl."""
    forward = _format_target_forward_decl(name, mangled)
    if forward is None:
        return _DEFAULT_CTX_H
    return (
        _DEFAULT_CTX_H
        + "\n"
        + "/* Forward decl pins the target's calling convention so MSVC emits the\n"
        + " * matching mangled symbol. Edit the param types here AND in your\n"
        + " * definition if you want concrete types; keep the byte sizing intact. */\n"
        + forward + "\n"
    )


def _disassemble_listing(parsed: ParsedXbe, fn_va: int, size: int) -> str:
    body = xbe_function_carve(parsed, fn_va, size)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    lines = []
    for instr in md.disasm(body, fn_va):
        lines.append(
            f"{instr.address:#010x}  {instr.bytes.hex():<14} "
            f"{instr.mnemonic} {instr.op_str}"
        )
    return "\n".join(lines)
