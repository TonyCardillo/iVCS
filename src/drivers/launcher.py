"""Launch a matching-decomp run for one function from the UI.

Carves the target function from the parsed XBE, synthesizes a fresh
target.obj, writes a minimal ctx.h (only if absent), and spawns a
daemon thread running agent_loop_run. Returns a JobInfo handle that
the caller drops into a registry. The JobInfo mutates in-place as the
thread progresses, so the UI can read state/iter/match% by reference.
"""

from __future__ import annotations

import os
import re
import sys
import threading
import time
import traceback
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import capstone

from src.core.project import FunctionEntry, Project
from src.core.workspace import FunctionWorkspace
from src.decomp.agent_loop import AgentConfig, agent_loop_run, ghidra_only_run
from src.decomp.compile_tool import default_compile_fn, default_diff_fn
from src.decomp.ghidra_decompile import (
	GhidraError,
	ghidra_config_from_env,
	ghidra_decompile_function,
	ghidra_project_ensure,
	ghidra_pseudo_c_normalize,
	ghidra_structs_dump,
)
from src.decomp.llm_clients import llm_client_for, llm_recorded_model
from src.drivers.sweep import SweepOutcome, sweep_outcome_classify
from src.formats.carver import carver_target_obj_build
from src.formats.relocs import (
	RelocKind,
	RelocSite,
	callee_convention_at,
	convention_from_bytes,
	relocs_discover,
	relocs_kernel_ordinal_at,
)
from src.formats.xbe import ParsedXbe, xbe_function_carve, xbe_load, xbe_section_containing_va
from src.formats.xboxkrnl import (
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
/* Ghidra's function element type: `code *` is a function pointer, so `code`
   must be a function type for an indirect call `(**(code **)x)()` to compile.
   `int` return suits both ignored- and consumed-result call sites. */
typedef int              code();
/* --- Ghidra p-code intrinsics (universal decompiler output) ----------------
   Odd-width integer types and the CONCAT/SUB/ZEXT/SEXT/CARRY pseudo-ops Ghidra
   emits for sub-register and multi-word arithmetic. Harmless when unused; they
   let a warm-start draft compile so the agent inherits a working baseline. */
typedef int              int3;
typedef unsigned int     uint3;
typedef __int64          int5;
typedef __int64          int6;
typedef __int64          int7;
typedef unsigned __int64 uint5;
typedef unsigned __int64 uint6;
typedef unsigned __int64 uint7;
#define CONCAT11(h,l) \
((unsigned short)(((unsigned int)(unsigned char)(h) << 8) | (unsigned char)(l)))
#define CONCAT13(h,l) (((unsigned int)(unsigned char)(h) << 24) | ((unsigned int)(l) & 0xffffff))
#define CONCAT22(h,l) (((unsigned int)(unsigned short)(h) << 16) | (unsigned short)(l))
#define CONCAT31(h,l) (((unsigned int)(h) << 8) | (unsigned char)(l))
#define CONCAT44(h,l) (((unsigned __int64)(unsigned int)(h) << 32) | (unsigned int)(l))
#define SUB41(x,n)    ((unsigned char)((unsigned int)(x) >> ((n) * 8)))
#define SUB42(x,n)    ((unsigned short)((unsigned int)(x) >> ((n) * 8)))
#define SUB81(x,n)    ((unsigned char)((unsigned __int64)(x) >> ((n) * 8)))
#define SUB84(x,n)    ((unsigned int)((unsigned __int64)(x) >> ((n) * 8)))
#define ZEXT12(x)     ((unsigned short)(unsigned char)(x))
#define ZEXT14(x)     ((unsigned int)(unsigned char)(x))
#define ZEXT18(x)     ((unsigned __int64)(unsigned char)(x))
#define ZEXT24(x)     ((unsigned int)(unsigned short)(x))
#define ZEXT28(x)     ((unsigned __int64)(unsigned short)(x))
#define ZEXT48(x)     ((unsigned __int64)(unsigned int)(x))
#define SEXT14(x)     ((int)(signed char)(x))
#define SEXT18(x)     ((__int64)(signed char)(x))
#define SEXT24(x)     ((int)(short)(x))
#define SEXT28(x)     ((__int64)(short)(x))
#define SEXT48(x)     ((__int64)(int)(x))
#define CARRY1(a,b) \
((unsigned char)((unsigned char)(a) + (unsigned char)(b)) < (unsigned char)(a))
#define CARRY2(a,b) \
((unsigned short)((unsigned short)(a) + (unsigned short)(b)) < (unsigned short)(a))
#define CARRY4(a,b) \
((unsigned int)((unsigned int)(a) + (unsigned int)(b)) < (unsigned int)(a))
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
	iterations_completed: int = 0
	best_match_percent: float | None = None
	termination_reason: str | None = None
	error: str | None = None

	def is_active(self) -> bool:
		return self.state in ("pending", "running")


def prepare_decomp_workspace(
	project: Project,
	fn: FunctionEntry,
	*,
	parsed: ParsedXbe,
	label_for: Callable[[int], str] | None = None,
	wipe_history: bool = False,
	reset_ctx_h: bool = False,
	use_ghidra_warmstart: bool = False,
) -> tuple[FunctionWorkspace, str]:
	"""Carve the target, synth target.obj, compose ctx.h, mirror the warm-start.

	The shared front half of a decomp run: everything up to (but not including)
	the agent loop. Returns the initialized workspace and the target disassembly
	listing. Used by both the web UI's threaded launch and the batch runner.
	"""
	body = xbe_function_carve(parsed, fn.va, fn.size)
	sites = relocs_discover(body, fn.va)
	conventions = _rel32_callee_conventions(parsed, sites, fn.va)
	mangled = _infer_mangled_name(body, fn.name)
	obj_bytes = carver_target_obj_build(parsed, fn.va, fn.size, mangled)
	target_asm = _disassemble_listing(body, fn.va)
	callee_decls = _callee_decls_from_conventions(conventions, label_for=label_for)
	kernel_imports = _extract_kernel_imports(parsed, sites)

	workspace = FunctionWorkspace(root=project.workspace_for(fn), function_name=mangled)
	workspace.initialize()
	if wipe_history:
		_wipe_workspace_history(workspace)
	workspace.target_obj.write_bytes(obj_bytes)

	# Fetch the Ghidra draft and harvest the struct layouts it references before
	# composing ctx.h, so the typedefs the draft needs are in place and the
	# warm-start's `<Type>_<addr>` instances can be rewritten against them.
	struct_decls, struct_names = (
		_prepare_ghidra_warmstart(workspace, project, fn) if use_ghidra_warmstart else ("", ())
	)

	if reset_ctx_h or not workspace.ctx_h.is_file():
		workspace.ctx_h.write_text(
			_compose_ctx_h(fn.name, mangled, callee_decls, kernel_imports, struct_decls)
		)

	_mirror_warmstart_as_attempt_zero(
		workspace,
		struct_names=struct_names,
		stdcall_target=fn.name if "@" in mangled else None,
		callee_arities=_callee_arities_from_conventions(conventions),
	)
	return workspace, target_asm


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
	label_for: Callable[[int], str] | None = None,
) -> JobInfo:
	"""Carve, prepare workspace, and spawn the agent loop in a daemon thread.

	Returns immediately after the thread starts. The returned JobInfo
	mutates as the run progresses; readers see state, iterations, and
	best_match_percent advance live.
	"""
	is_ghidra_only = model == "ghidra"
	is_local = model == "local"
	if is_ghidra_only:
		# Ghidra-only runs need the warm-start to have anything to compile.
		use_ghidra_warmstart = True
		key = None
	elif is_local:
		# A local OpenAI-compatible server (LM Studio) needs no Anthropic key.
		key = None
	else:
		key = api_key or os.environ.get("ANTHROPIC_API_KEY")
		if not key:
			raise RuntimeError("ANTHROPIC_API_KEY not set in environment")

	parsed = parsed_xbe if parsed_xbe is not None else xbe_load(project.xbe_path)
	workspace, target_asm = prepare_decomp_workspace(
		project,
		fn,
		parsed=parsed,
		label_for=label_for,
		wipe_history=wipe_history,
		reset_ctx_h=reset_ctx_h,
		use_ghidra_warmstart=use_ghidra_warmstart,
	)

	# Record the resolved model name (e.g. the LM Studio model id for "local"),
	# so attempts, best.c, and the banner name the real AI, not the run mode.
	recorded_model = llm_recorded_model(model)
	job = JobInfo(
		workspace_path=workspace.root,
		function_name=workspace.function_name,
		va=fn.va,
		size=fn.size,
		model=recorded_model,
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
				llm = llm_client_for(model, api_key=key)
				config = AgentConfig(
					model=recorded_model,
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
		except Exception as e:  # noqa: BLE001 — a daemon thread must not die; report to the UI
			# Log the traceback so a genuine bug (e.g. an AttributeError from a
			# refactor) is visible in the server log, not just stashed as a
			# one-line UI string indistinguishable from a model/compile failure.
			sys.stderr.write(f"[decomp] {fn.name} failed: {type(e).__name__}: {e}\n")
			traceback.print_exc()
			job.error = f"{type(e).__name__}: {e}"
			job.state = "error"

	threading.Thread(target=_run, daemon=True, name=f"decomp-{fn.name}").start()
	return job


def ghidra_sweep_attempt_one(
	project: Project,
	fn: FunctionEntry,
	*,
	parsed: ParsedXbe,
	compile_fn=default_compile_fn,
	diff_fn=default_diff_fn,
	label_for: Callable[[int], str] | None = None,
) -> SweepOutcome:
	"""Baseline one function for a project sweep: prepare its Ghidra warm-start
	workspace, then compile + diff attempt 0 with no LLM.

	Runs synchronously (the sweep's worker thread drives the queue) and returns a
	classified SweepOutcome. Compile/diff are injected for testability; they bind
	to Wine + objdiff by default.

	`reset_ctx_h=True`: the sweep is a baseline pass over *untouched* functions, so
	regenerating ctx.h costs no hand-tuned work and is required for prelude
	improvements (new typedefs, the p-code intrinsics) to reach functions that were
	prepared by an earlier sweep — a cached ctx.h would otherwise pin them to the
	old prelude and miss every later fix.
	"""
	workspace, _target_asm = prepare_decomp_workspace(
		project,
		fn,
		parsed=parsed,
		label_for=label_for,
		use_ghidra_warmstart=True,
		reset_ctx_h=True,
	)
	result = ghidra_only_run(workspace=workspace, compile_fn=compile_fn, diff_fn=diff_fn)
	return sweep_outcome_classify(fn.va, fn.name, result)


def _mirror_warmstart_as_attempt_zero(
	workspace: FunctionWorkspace,
	*,
	struct_names: tuple[str, ...] = (),
	stdcall_target: str | None = None,
	callee_arities: dict[str, int] | None = None,
) -> None:
	"""Write ghidra_warmstart.c as 0000.c with ctx.h prepended.

	Ghidra emits pseudo-C (undefined4, byte, FUN_xxxxxxxx...) which MSVC
	won't accept. We normalize during the mirror so attempt 0 has a real
	shot at compiling; the un-normalized draft stays at ghidra_warmstart.c
	so the LLM sees Ghidra's "undefined" signal in its system prompt.

	`struct_names` (the layouts harvested into ctx.h) lets the normalizer
	rewrite the draft's `<Type>_<addr>` struct instances to typed derefs;
	`stdcall_target` pins the draft's definition to `int __stdcall` so it
	agrees with the stdcall forward decl in ctx.h; `callee_arities` pads
	under-count call sites to satisfy strict `@N` callee prototypes.
	"""
	if not workspace.ghidra_warmstart.is_file():
		return
	paths = workspace.attempt_paths(0)
	ctx = workspace.ctx_h.read_text() if workspace.ctx_h.is_file() else ""
	normalized = ghidra_pseudo_c_normalize(
		workspace.ghidra_warmstart.read_text(),
		struct_names=struct_names,
		stdcall_target=stdcall_target,
		callee_arities=callee_arities,
	)
	content = ctx + "\n" + normalized
	# Regenerate when the freshly-normalized content differs from what's on disk,
	# so normalizer improvements (e.g. DAT_ rewrites) reach already-prepared
	# functions instead of being frozen by a stale baseline. Invalidate the
	# compiled/diffed artifacts so the baseline recompiles against the new source.
	if paths.c.is_file() and paths.c.read_text() == content:
		return
	paths.c.write_text(content)
	for stale in (paths.obj, paths.diff_json):
		if stale.is_file():
			stale.unlink()


def _prepare_ghidra_warmstart(
	workspace: FunctionWorkspace, project: Project, fn: FunctionEntry
) -> tuple[str, tuple[str, ...]]:
	"""Best-effort: fetch the Ghidra pseudo-C draft (if absent) and harvest the
	struct layouts it references.

	Returns (struct_decls, struct_names) for ctx.h synthesis and warm-start
	normalization. On any GhidraError, logs and returns empties so the run
	proceeds without struct context (or without the draft entirely).
	"""
	cfg = ghidra_config_from_env(project.xbe_path)
	try:
		# ensure() is idempotent and cheap once bootstrapped — run it even when the
		# draft is already cached, so the struct dump still has a project to query
		# after the Ghidra data dir is evicted (e.g. a /tmp wipe on reboot).
		# Otherwise cached functions silently lose their type context.
		ghidra_project_ensure(cfg)
		if not workspace.ghidra_warmstart.is_file():
			draft = ghidra_decompile_function(fn.va, cfg)
			workspace.ghidra_warmstart.write_text(draft)
		header = ghidra_structs_dump(cfg)
	except GhidraError as e:
		print(f"[launcher] Ghidra warm-start prep failed for {fn.name}: {e}", file=sys.stderr)
		return "", ()
	return _select_referenced_structs(header, workspace.ghidra_warmstart.read_text())


_STRUCT_BLOCK_PATTERN = re.compile(r"typedef (?:struct|union) \{.*?\}\s*([A-Za-z_]\w*)\s*;", re.S)


def _struct_referenced(name: str, text: str) -> bool:
	"""True if `text` uses `name` as a type or as a `<name>_<8hex>` instance."""
	return re.search(rf"\b{re.escape(name)}(?:_[0-9a-fA-F]{{8}})?\b", text) is not None


def _select_referenced_structs(struct_header: str, draft: str) -> tuple[str, tuple[str, ...]]:
	"""Pick the harvested typedef blocks the draft references, plus their
	by-value dependency closure, re-wrapped in pack(1) (offsets depend on it).

	Returns (header_text, names). Selection is driven entirely by the harvested
	names, so it is binary-agnostic — no fixed struct list. Empty when nothing
	matches, so ctx.h stays lean for functions that touch no structs."""
	blocks = [(m.group(1), m.group(0)) for m in _STRUCT_BLOCK_PATTERN.finditer(struct_header)]
	if not blocks:
		return "", ()
	by_name = dict(blocks)
	referenced = {name for name, _ in blocks if _struct_referenced(name, draft)}
	# Pull in any harvested struct used by-value inside an already-selected one.
	changed = True
	while changed:
		changed = False
		for name, _block in blocks:
			if name in referenced:
				continue
			if any(_struct_referenced(name, by_name[r]) for r in referenced):
				referenced.add(name)
				changed = True
	if not referenced:
		return "", ()
	selected = [block for name, block in blocks if name in referenced]
	text = "#pragma pack(push, 1)\n\n" + "\n\n".join(selected) + "\n\n#pragma pack(pop)\n"
	names = tuple(name for name, _ in blocks if name in referenced)
	return text, names


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


def _infer_mangled_name(body: bytes, base: str) -> str:
	"""MSVC stdcall mangling from the function's first ret-style instruction."""
	conv, byte_count = convention_from_bytes(body)
	if conv == "stdcall":
		return f"_{base}@{byte_count}"
	return f"_{base}"


def _stdcall_arglist(byte_count: int) -> tuple[str, bool]:
	"""The `int`-placeholder parameter list for a stdcall popping `byte_count`
	bytes — one int per 4 bytes, `void` for zero. The bool flags an irregular
	count (not a multiple of 4); callers surface that as a warning and fall back
	to a single `int`."""
	if byte_count == 0:
		return "void", False
	if byte_count % 4 == 0:
		return ", ".join(["int"] * (byte_count // 4)), False
	return "int", True


def _stdcall_irregular_warning(byte_count: int) -> str:
	return f"WARNING: target pops {byte_count} bytes — non-32-bit args."


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
	args, irregular = _stdcall_arglist(byte_count)
	decl = f"int __stdcall {name}({args});"
	if irregular:
		return f"/* {_stdcall_irregular_warning(byte_count)} */\n{decl}"
	return decl


def _compose_ctx_h(
	name: str,
	mangled: str,
	callee_decls: tuple[str, ...] = (),
	kernel_imports: tuple[str, ...] = (),
	struct_decls: str = "",
) -> str:
	"""Build the auto-stub ctx.h: typedefs, Ghidra-harvested struct layouts,
	target forward decl, kernel import decls, same-binary callee decls."""
	parts = [_DEFAULT_CTX_H]
	if struct_decls:
		parts.append("\n/* Ghidra-harvested struct layouts. */\n" + struct_decls)
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


def _format_callee_decl(name: str, conv: str, byte_count: int, *, label: str | None = None) -> str:
	"""Forward decl for a same-binary callee given its inferred convention.

	Return is always `int` — for call sites that don't use the result this
	is identical to `void`; for ones that consume EAX it's correct.
	K&R `int name()` (cdecl) accepts any arg list, so the LLM can call it
	with whatever count it infers from the target asm without a redecl.

	`label`, when it differs from the machine `name`, is appended as a trailing
	comment — the symbol the compiler/diff sees stays `fn_<va>` (the verification
	anchor), while the human name rides along so the model reads it in context.
	"""
	if conv == "stdcall":
		args, irregular = _stdcall_arglist(byte_count)
		decl = f"int __stdcall {name}({args});"
		if irregular:
			decl += f"  /* {_stdcall_irregular_warning(byte_count)} */"
	else:
		decl = f"int {name}();"
	if label and label != name:
		decl += f"  // {label}"
	return decl


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
	args, _ = _stdcall_arglist(byte_count)
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


def _rel32_callee_conventions(
	parsed: ParsedXbe, sites: list[RelocSite], fn_va: int
) -> list[tuple[int, str, int]]:
	"""[(va, convention, popped_bytes)] for each same-binary REL32 callee of
	fn_va, given its already-discovered relocation `sites`. Same inference the
	carver uses for target.obj's call-site symbol, so ctx.h decls and relocation
	decoration always agree."""

	def is_executable(va: int) -> bool:
		section = xbe_section_containing_va(parsed, va)
		return section is not None and section.is_executable

	callee_vas = _rel32_callee_vas_from_sites(sites, is_executable, self_va=fn_va)
	return [(va, *callee_convention_at(parsed, va)) for va in callee_vas]


_C_IDENT_RE = re.compile(r"^[A-Za-z_]\w*$")

# Labels we must never turn into a `#define` alias: C89 keywords and the typedef
# names ctx.h already provides. Aliasing one of these would rewrite legitimate
# tokens in the model's code (e.g. `#define int fn_X`) and break the compile.
# fmt: off
_C89_KEYWORDS = frozenset((
	"auto", "break", "case", "char", "const", "continue", "default", "do", "double",
	"else", "enum", "extern", "float", "for", "goto", "if", "int", "long", "register",
	"return", "short", "signed", "sizeof", "static", "struct", "switch", "typedef",
	"union", "unsigned", "void", "volatile", "while",
))
# fmt: on
_CTX_TYPE_NAMES = frozenset(re.findall(r"\b([A-Za-z_]\w*)\s*;", _DEFAULT_CTX_H))
_RESERVED_ALIAS_NAMES = _C89_KEYWORDS | _CTX_TYPE_NAMES


def _callee_alias_line(label: str | None, name: str) -> str | None:
	"""`#define <label> <name>` so the model may call a renamed callee by its
	real name while the compiled call still emits the `name` (fn_<va>) symbol
	objdiff pairs on — the alias is a pure source-level token rewrite, invisible
	to the relocation the compiler emits.

	None when the label is missing, equals the machine name, isn't a plain C
	identifier, or would shadow a C keyword / ctx.h typedef.
	"""
	if not label or label == name:
		return None
	if not _C_IDENT_RE.match(label) or label in _RESERVED_ALIAS_NAMES:
		return None
	return f"#define {label} {name}"


def _callee_decls_from_conventions(
	conventions: list[tuple[int, str, int]],
	*,
	label_for: Callable[[int], str] | None = None,
) -> tuple[str, ...]:
	"""Forward decls for same-binary callees, from precomputed (va, convention,
	popped_bytes) triples.

	`label_for(va)` supplies the human label for each callee. When it differs
	from `fn_<va>` it rides along as a trailing comment AND, if it's a safe C
	identifier, as a `#define <label> fn_<va>` so the model can call the callee
	by its real name and still emit the matching symbol. Aliases are de-duped
	(a label is defined at most once) to avoid macro redefinition.
	"""
	decls: list[str] = []
	seen_aliases: set[str] = set()
	for va, conv, byte_count in conventions:
		name = f"fn_{va:08X}"
		label = label_for(va) if label_for else None
		decl = _format_callee_decl(name, conv, byte_count, label=label)
		alias = _callee_alias_line(label, name)
		if alias is not None and label not in seen_aliases:
			seen_aliases.add(label)
			decl = f"{decl}\n{alias}"
		decls.append(decl)
	return tuple(decls)


def _callee_arities_from_conventions(conventions: list[tuple[int, str, int]]) -> dict[str, int]:
	"""{callee_name: stdcall arg count} for the stdcall callees, from precomputed
	(va, convention, popped_bytes) triples.

	Lets the warm-start normalizer pad under-count Ghidra call sites up to the
	arity the `@N`-pinned prototype demands (Ghidra routinely under-counts)."""
	return {
		f"fn_{va:08X}": byte_count // 4
		for va, conv, byte_count in conventions
		if conv == "stdcall" and byte_count > 0
	}


def _extract_kernel_imports(parsed: ParsedXbe, sites: list[RelocSite]) -> tuple[str, ...]:
	"""Scan precomputed DIR32 sites for kernel-thunk references; return plain
	export names (e.g., 'NtClose'), deduped and sorted."""
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


def _disassemble_listing(body: bytes, fn_va: int) -> str:
	md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
	lines = [
		f"{instr.address:#010x}  {instr.bytes.hex():<14} {instr.mnemonic} {instr.op_str}"
		for instr in md.disasm(body, fn_va)
	]
	return "\n".join(lines)
