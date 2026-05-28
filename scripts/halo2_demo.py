#!/usr/bin/env python3
"""End-to-end matching-decomp demo on a small real Halo 2 function.

Target: fn_002D1D94 — 23-byte stdcall(1 arg) that wraps RtlNtStatusToDosError
and an internal helper. Small enough for Haiku to plausibly match; rich
enough to exercise both the FF 15 / __imp__ kernel-call path and a REL32
internal-call path.

Run: ANTHROPIC_API_KEY=... uv run python scripts/halo2_demo.py
"""

import os
import shutil
import sys
from pathlib import Path

import capstone

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from src.agent_loop import AgentConfig, agent_loop_run  # noqa: E402
from src.carver import carver_target_obj_build  # noqa: E402
from src.compile_tool import default_compile_fn, default_diff_fn  # noqa: E402
from src.llm_clients import LiteLLMClient  # noqa: E402
from src.workspace import FunctionWorkspace  # noqa: E402
from src.xbe import xbe_function_carve, xbe_load  # noqa: E402

XBE_PATH = Path("/tmp/halo2_default.xbe")
WORKSPACE_ROOT = Path("/tmp/halo2_demo_fn_002D1D94")
FUNCTION_VA = 0x002D1D94
FUNCTION_NAME = "_fn_002D1D94@4"

CTX_H = """\
/* Minimal typedefs + externs for fn_002D1D94 — hand-rolled for the demo. */
typedef unsigned long  DWORD;
typedef long           NTSTATUS;

__declspec(dllimport) DWORD __stdcall RtlNtStatusToDosError(NTSTATUS Status);

/* Forward decl pins the calling convention so MSVC emits the @4 mangling
 * that matches the carved target symbol. */
DWORD __stdcall fn_002D1D94(NTSTATUS Status);

/* Internal helper — best-guess cdecl. */
DWORD fn_002D1D66(DWORD x);
"""


def main() -> int:
	if not XBE_PATH.is_file():
		print(f"ERROR: missing {XBE_PATH}", file=sys.stderr)
		return 1

	parsed = xbe_load(XBE_PATH)
	fn_size = _function_size_by_scan(parsed, FUNCTION_VA)
	print(f"target: {FUNCTION_NAME} at {FUNCTION_VA:#x}, size={fn_size} bytes")

	obj_bytes = carver_target_obj_build(parsed, FUNCTION_VA, fn_size, FUNCTION_NAME)
	print(f"synthesized target.obj: {len(obj_bytes)} bytes")

	asm_listing = _disassemble_listing(parsed, FUNCTION_VA, fn_size)
	print("--- disassembly ---")
	print(asm_listing)
	print("---")

	if WORKSPACE_ROOT.exists():
		shutil.rmtree(WORKSPACE_ROOT)
	workspace = FunctionWorkspace(root=WORKSPACE_ROOT, function_name=FUNCTION_NAME)
	workspace.initialize()
	workspace.target_obj.write_bytes(obj_bytes)
	workspace.ctx_h.write_text(CTX_H)
	print(f"workspace ready at {WORKSPACE_ROOT}")

	api_key = os.environ.get("ANTHROPIC_API_KEY")
	if not api_key:
		print("ERROR: ANTHROPIC_API_KEY not set", file=sys.stderr)
		return 1
	llm = LiteLLMClient(model="anthropic/claude-haiku-4-5", api_key=api_key)
	config = AgentConfig(
		model="claude-haiku-4-5",
		api_base="",
		max_iterations=8,
		hard_timeout_seconds=180.0,
	)

	print("running agent loop...")
	result = agent_loop_run(
		workspace=workspace,
		target_asm=asm_listing,
		config=config,
		llm_client=llm,
		compile_fn=default_compile_fn,
		diff_fn=default_diff_fn,
	)

	print("\n=== Result ===")
	print(f"  reason       : {result.termination_reason}")
	print(f"  success      : {result.success}")
	print(f"  iterations   : {result.iterations}")
	print(f"  best match % : {result.best_match_percent}")
	if workspace.best_c.is_file():
		print(f"\n  best.c:\n{workspace.best_c.read_text()}")
	return 0 if result.success else 2


def _function_size_by_scan(parsed, fn_va: int, max_size: int = 4096) -> int:
	body = xbe_function_carve(parsed, fn_va, max_size)
	md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
	md.detail = True
	for instr in md.disasm(body, fn_va):
		if instr.mnemonic == "ret" or instr.mnemonic.startswith("retn"):
			return (instr.address + instr.size) - fn_va
	raise RuntimeError(f"no ret found within {max_size} bytes of {fn_va:#x}")


def _disassemble_listing(parsed, fn_va: int, size: int) -> str:
	body = xbe_function_carve(parsed, fn_va, size)
	md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
	lines = [
		f"{instr.address:#010x}  {instr.bytes.hex():<14} {instr.mnemonic} {instr.op_str}"
		for instr in md.disasm(body, fn_va)
	]
	return "\n".join(lines)


if __name__ == "__main__":
	raise SystemExit(main())
