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

from src.agent_loop import AgentConfig, agent_loop_run, ghidra_only_run
from src.carver import carver_target_obj_build
from src.compile_tool import default_compile_fn, default_diff_fn
from src.ghidra_decompile import (
	GhidraError,
	ghidra_config_from_env,
	ghidra_decompile_function,
	ghidra_project_ensure,
	ghidra_pseudo_c_normalize,
)
from src.llm_clients import LiteLLMClient
from src.project import FunctionEntry, Project
from src.relocs import RelocKind, RelocSite, relocs_discover, relocs_kernel_ordinal_at
from src.workspace import FunctionWorkspace
from src.xbe import ParsedXbe, xbe_function_carve, xbe_load, xbe_section_containing_va
from src.xboxkrnl import (
	KernelFunctionSig,
	KernelVariableSig,
	xboxkrnl_mangled_byte_count,
	xboxkrnl_name_get,
	xboxkrnl_signature_get,
)

_DEFAULT_CTX_H = """\
typedef unsigned char    BYTE;
typedef unsigned char    UCHAR;
typedef char             CHAR;
typedef unsigned short   WORD;
typedef unsigned short   USHORT;
typedef unsigned long    DWORD;
typedef unsigned long    ULONG;
typedef unsigned __int64 DWORD64;
typedef unsigned __int64 ULONGLONG;
typedef int              BOOL;
typedef long             LONG;
typedef long             NTSTATUS;
typedef unsigned int     UINT;
typedef unsigned int     SIZE_T;
typedef unsigned long    ULONG_PTR;
typedef unsigned long    ACCESS_MASK;
typedef __int64          LARGE_INTEGER;
typedef void *           PVOID;
typedef void *           HANDLE;
typedef char *           LPSTR;
typedef const char *     LPCSTR;
typedef ULONG *          PULONG;
typedef HANDLE *         PHANDLE;
typedef LARGE_INTEGER *  PLARGE_INTEGER;
typedef void *           POBJECT_ATTRIBUTES;
typedef void *           PIO_STATUS_BLOCK;
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
	wipe_history: bool = False,
	reset_ctx_h: bool = False,
	use_ghidra_warmstart: bool = False,
) -> JobInfo:
	"""Carve, prepare workspace, and spawn the agent loop in a daemon thread.

	Returns immediately after the thread starts. The returned JobInfo
	mutates as the run progresses; readers see state, iterations, and
	best_match_percent advance live.
	"""
	is_ghidra_only = model == "ghidra"
	if is_ghidra_only:
		# Ghidra-only runs need the warm-start to have anything to compile.
		use_ghidra_warmstart = True
		key = None
	else:
		key = api_key or os.environ.get("ANTHROPIC_API_KEY")
		if not key:
			raise RuntimeError("ANTHROPIC_API_KEY not set in environment")

	parsed = parsed_xbe if parsed_xbe is not None else xbe_load(project.xbe_path)

	body = xbe_function_carve(parsed, fn.va, fn.size)
	mangled = _infer_mangled_name(body, fn.name)
	obj_bytes = carver_target_obj_build(parsed, fn.va, fn.size, mangled)
	target_asm = _disassemble_listing(parsed, fn.va, fn.size)
	callee_decls = _extract_rel32_callee_decls(parsed, fn.va, fn.size)
	kernel_imports = _extract_kernel_imports(parsed, fn.va, fn.size)

	workspace_path = project.workspace_for(fn)
	workspace = FunctionWorkspace(root=workspace_path, function_name=mangled)
	workspace.initialize()
	if wipe_history:
		_wipe_workspace_history(workspace)
	workspace.target_obj.write_bytes(obj_bytes)
	if reset_ctx_h or not workspace.ctx_h.is_file():
		workspace.ctx_h.write_text(_compose_ctx_h(fn.name, mangled, callee_decls, kernel_imports))

	if use_ghidra_warmstart and not workspace.ghidra_warmstart.is_file():
		try:
			cfg = ghidra_config_from_env(project.xbe_path)
			ghidra_project_ensure(cfg)
			draft = ghidra_decompile_function(fn.va, cfg)
			workspace.ghidra_warmstart.write_text(draft)
		except GhidraError as e:
			# Best-effort: log and continue without the draft.
			import sys

			print(f"[launcher] Ghidra warm-start failed for {fn.name}: {e}", file=sys.stderr)

	_mirror_warmstart_as_attempt_zero(workspace)

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
			if is_ghidra_only:
				result = ghidra_only_run(
					workspace=workspace,
					compile_fn=default_compile_fn,
					diff_fn=default_diff_fn,
				)
			else:
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


def _mirror_warmstart_as_attempt_zero(workspace: FunctionWorkspace) -> None:
	"""Write ghidra_warmstart.c as 0000.c with ctx.h prepended.

	Ghidra emits pseudo-C (undefined4, byte, FUN_xxxxxxxx...) which MSVC
	won't accept. We normalize during the mirror so attempt 0 has a real
	shot at compiling; the un-normalized draft stays at ghidra_warmstart.c
	so the LLM sees Ghidra's "undefined" signal in its system prompt.
	"""
	if not workspace.ghidra_warmstart.is_file():
		return
	target = workspace.attempt_paths(0).c
	if target.is_file():
		return
	ctx = workspace.ctx_h.read_text() if workspace.ctx_h.is_file() else ""
	normalized = ghidra_pseudo_c_normalize(workspace.ghidra_warmstart.read_text())
	target.write_text(ctx + "\n" + normalized)


def _wipe_workspace_history(workspace: FunctionWorkspace) -> None:
	"""Clear prior run artifacts: history/, result.json, best.c.

	Preserves target.obj (re-written by the caller anyway) and ctx.h
	(user may have hand-edited it; let them keep their changes).
	"""
	if workspace.history_dir.is_dir():
		for entry in workspace.history_dir.iterdir():
			if entry.is_file():
				entry.unlink()
	if workspace.result_json.is_file():
		workspace.result_json.unlink()
	if workspace.best_c.is_file():
		workspace.best_c.unlink()


def _infer_convention_from_bytes(body: bytes) -> tuple[str, int]:
	"""First ret instruction classifies the calling convention.

	Returns ('stdcall', byte_count) for `ret imm16`, ('cdecl', 0) for `ret`
	or when no ret is found within the scanned bytes.
	"""
	md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
	md.detail = False
	for _addr, _size, mnem, op in md.disasm_lite(body, 0):
		if mnem == "ret":
			if op:
				try:
					return ("stdcall", int(op, 0))
				except ValueError:
					return ("cdecl", 0)
			return ("cdecl", 0)
	return ("cdecl", 0)


def _infer_mangled_name(body: bytes, base: str) -> str:
	"""MSVC stdcall mangling from the function's first ret-style instruction."""
	conv, byte_count = _infer_convention_from_bytes(body)
	if conv == "stdcall":
		return f"_{base}@{byte_count}"
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


def _compose_ctx_h(
	name: str,
	mangled: str,
	callee_decls: tuple[str, ...] = (),
	kernel_imports: tuple[str, ...] = (),
) -> str:
	"""Build the auto-stub ctx.h: typedefs, target forward decl, kernel
	import decls, same-binary callee decls."""
	parts = [_DEFAULT_CTX_H]
	forward = _format_target_forward_decl(name, mangled)
	if forward is not None:
		parts.append("\n/* Target — pins mangling. */\n" + forward + "\n")
	if kernel_imports:
		decls = "\n".join(_format_kernel_decl(n) for n in kernel_imports)
		parts.append("\n/* xboxkrnl imports. */\n" + decls + "\n")
	if callee_decls:
		parts.append(
			"\n/* Same-binary callees. Return type is `int` by default; refine "
			"if the diff shows the result is consumed differently. */\n"
			+ "\n".join(callee_decls)
			+ "\n"
		)
	return "".join(parts)


def _format_callee_decl(name: str, conv: str, byte_count: int) -> str:
	"""Forward decl for a same-binary callee given its inferred convention.

	Return is always `int` — for call sites that don't use the result this
	is identical to `void`; for ones that consume EAX it's correct.
	K&R `int name()` (cdecl) accepts any arg list, so the LLM can call it
	with whatever count it infers from the target asm without a redecl.
	"""
	if conv == "stdcall":
		if byte_count == 0:
			return f"int __stdcall {name}(void);"
		if byte_count % 4 == 0:
			args = ", ".join(["int"] * (byte_count // 4))
			return f"int __stdcall {name}({args});"
		return f"int __stdcall {name}(int);  /* WARN: target pops {byte_count} bytes */"
	return f"int {name}();"


def _format_kernel_decl(name: str) -> str:
	"""Emit a `__declspec(dllimport)` decl for a kernel export.

	Uses the hand-curated signature when present; otherwise falls back
	to int placeholders sized by the export's `@N` byte count.
	"""
	sig = xboxkrnl_signature_get(name)
	if isinstance(sig, KernelVariableSig):
		return f"extern __declspec(dllimport) {sig.var_type} {name};"
	if isinstance(sig, KernelFunctionSig):
		args = ", ".join(sig.arg_types) if sig.arg_types else "void"
		if sig.varargs:
			args = args + ", ..." if sig.arg_types else "..."
			return f"__declspec(dllimport) {sig.return_type} {name}({args});"
		return f"__declspec(dllimport) {sig.return_type} __stdcall {name}({args});"
	byte_count = xboxkrnl_mangled_byte_count(name)
	if byte_count is None:
		return f"__declspec(dllimport) int {name}();"
	if byte_count == 0:
		return f"__declspec(dllimport) int __stdcall {name}(void);"
	if byte_count % 4 != 0:
		return f"__declspec(dllimport) int __stdcall {name}(int);"
	args = ", ".join(["int"] * (byte_count // 4))
	return f"__declspec(dllimport) int __stdcall {name}({args});"


def _rel32_callee_vas_from_sites(
	sites: list[RelocSite],
	is_executable_va,
	self_va: int,
) -> tuple[int, ...]:
	"""Pure filter: keep REL32 sites whose target VA is in an executable
	section, dedupe, sort, and drop the self-VA (target is already declared)."""
	seen: set[int] = set()
	for site in sites:
		if site.kind != RelocKind.REL32:
			continue
		if not is_executable_va(site.target_va):
			continue
		if site.target_va == self_va:
			continue
		seen.add(site.target_va)
	return tuple(sorted(seen))


def _extract_rel32_callee_decls(parsed: ParsedXbe, fn_va: int, fn_size: int) -> tuple[str, ...]:
	"""Forward decls for same-binary callees of fn_va, with convention inferred
	from the first ret in each callee's bytes."""
	body = xbe_function_carve(parsed, fn_va, fn_size)
	sites = relocs_discover(body, fn_va)

	def is_executable(va: int) -> bool:
		section = xbe_section_containing_va(parsed, va)
		return section is not None and section.is_executable

	callee_vas = _rel32_callee_vas_from_sites(sites, is_executable, self_va=fn_va)
	decls: list[str] = []
	for va in callee_vas:
		name = f"fn_{va:08X}"
		try:
			callee_body = xbe_function_carve(parsed, va, 256)
		except (ValueError, IndexError):
			decls.append(_format_callee_decl(name, "cdecl", 0))
			continue
		conv, byte_count = _infer_convention_from_bytes(callee_body)
		decls.append(_format_callee_decl(name, conv, byte_count))
	return tuple(decls)


def _extract_kernel_imports(parsed: ParsedXbe, fn_va: int, fn_size: int) -> tuple[str, ...]:
	"""Scan DIR32 sites for kernel-thunk references; return plain export
	names (e.g., 'NtClose'), deduped and sorted."""
	body = xbe_function_carve(parsed, fn_va, fn_size)
	sites = relocs_discover(body, fn_va)
	seen: set[str] = set()
	for site in sites:
		if site.kind != RelocKind.DIR32:
			continue
		ordinal = relocs_kernel_ordinal_at(site.target_va, parsed)
		if ordinal is None:
			continue
		name = xboxkrnl_name_get(ordinal)
		if name is not None:
			seen.add(name)
	return tuple(sorted(seen))


def _disassemble_listing(parsed: ParsedXbe, fn_va: int, size: int) -> str:
	body = xbe_function_carve(parsed, fn_va, size)
	md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
	lines = [
		f"{instr.address:#010x}  {instr.bytes.hex():<14} {instr.mnemonic} {instr.op_str}"
		for instr in md.disasm(body, fn_va)
	]
	return "\n".join(lines)
