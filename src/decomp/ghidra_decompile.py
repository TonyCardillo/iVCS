"""Ghidra-headless warm-start: pseudo-C drafts for the matching-decomp agent.

Two operations:
- ghidra_project_ensure: idempotently import + analyze an XBE into a Ghidra
  project. Pays the ~100s analysis cost once.
- ghidra_decompile_function: invoke a Java post-script that decompiles
  one function by VA and writes C source to a file. Project must already
  exist (re-imports would re-pay the analysis cost).
"""

import os
import re
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from pathlib import Path

from src.paths import GHIDRA_HOME, GHIDRA_PROJECT_DIR, GHIDRA_SCRIPTS_DIR

_GHIDRA_SCRIPTS_DIR = GHIDRA_SCRIPTS_DIR
_DECOMPILE_SCRIPT = "DecompileOne.java"
_DUMP_STRUCTS_SCRIPT = "DumpStructs.java"
_XBE_LOADER = "XbeLoader"
_ANALYSIS_SUCCESS_MARKER = "REPORT: Analysis succeeded"
_IMPORT_SUCCESS_MARKER = "REPORT: Import succeeded"
_LOCK_ERROR_MARKER = "Unable to lock project"
_LOCK_RETRY_ATTEMPTS = 3
_LOCK_RETRY_BACKOFF_SECONDS = 2.0


class GhidraError(RuntimeError):
	pass


@dataclass(frozen=True)
class GhidraConfig:
	ghidra_home: Path
	project_dir: Path
	xbe_path: Path
	project_name: str = "ivcs"
	script_dir: Path = _GHIDRA_SCRIPTS_DIR

	@property
	def analyze_headless(self) -> Path:
		return self.ghidra_home / "support" / "analyzeHeadless"

	@property
	def program_name(self) -> str:
		return self.xbe_path.name

	@property
	def project_gpr(self) -> Path:
		return self.project_dir / f"{self.project_name}.gpr"

	@property
	def project_rep(self) -> Path:
		"""The project's data directory. Ghidra identifies a project by its
		`.gpr`; a `.rep` left behind without one is a partial/corrupt state."""
		return self.project_dir / f"{self.project_name}.rep"

	@property
	def project_lock(self) -> Path:
		return self.project_dir / f"{self.project_name}.lock"

	@property
	def structs_h(self) -> Path:
		"""Cache path for the harvested struct-layout header (one per project)."""
		return self.project_dir / f"{self.project_name}.structs.h"


AnalyzeHeadlessFn = Callable[[list[str]], "subprocess.CompletedProcess[str]"]
"""(argv) -> CompletedProcess. Injected for testing; default spawns the real binary."""


def ghidra_config_from_env(xbe_path: Path) -> GhidraConfig:
	"""Defaults match the install path documented in docs/ghidra_setup.md.

	IVCS_GHIDRA_HOME, IVCS_GHIDRA_PROJECT_DIR, IVCS_GHIDRA_PROJECT_NAME
	override the per-host bits.

	Default project name = XBE filename stem, so multiple XBEs each get
	their own analyzed project under the cache dir instead of sharing one and
	re-analyzing on every switch.
	"""
	default_ghidra_home = GHIDRA_HOME
	home = Path(
		os.environ.get(
			"IVCS_GHIDRA_HOME",
			str(default_ghidra_home),
		)
	)
	project_dir = Path(os.environ.get("IVCS_GHIDRA_PROJECT_DIR", str(GHIDRA_PROJECT_DIR)))
	project_name = os.environ.get("IVCS_GHIDRA_PROJECT_NAME") or xbe_path.stem
	return GhidraConfig(
		ghidra_home=home,
		project_dir=project_dir,
		xbe_path=xbe_path,
		project_name=project_name,
	)


def _is_bootstrapped(config: GhidraConfig) -> bool:
	"""True only if the marker `.gpr` exists AND the `.rep` holds a committed
	program database.

	Ghidra's `.gpr` is merely a marker file — legitimately 0 bytes; the program
	lives under `.rep/idata/`, bucketed into numbered subdirectories (`idata/00/
	<id>.prp` + `<id>.db/`). An import killed mid-write (a cancelled sweep, a
	/tmp eviction) leaves the marker and an `idata/` holding only its `~index`
	stubs but no program bucket. Such a partial project passes a naive
	`.gpr` is_file() check, yet every decompile against it produces no output —
	failing identically for every function in a sweep. Requiring a real program
	bucket (any subdirectory under `idata/`) rebuilds the partial import instead
	of trusting it.
	"""
	if not config.project_gpr.is_file():
		return False
	idata = config.project_rep / "idata"
	if not idata.is_dir():
		return False
	return any(child.is_dir() for child in idata.iterdir())


def ghidra_project_ensure(
	config: GhidraConfig,
	*,
	analyze_headless_fn: AnalyzeHeadlessFn | None = None,
	timeout_seconds: float = 600.0,
) -> None:
	"""No-op if the project is already bootstrapped (see `_is_bootstrapped`).

	A `.gpr` marker by itself is not enough: a leftover `.rep` from an import
	killed mid-write holds the marker but no committed program, and Ghidra
	refuses to import over an existing `.rep` (it will not recreate one). Clear
	any such partial state first so the bootstrap starts clean, and verify a
	real program actually lands afterward rather than trusting Ghidra's exit
	code and log marker alone — otherwise the failure surfaces much later, and
	far more cryptically, as a "project not bootstrapped" error from
	ghidra_decompile_function.
	"""
	if _is_bootstrapped(config):
		return

	config.project_dir.mkdir(parents=True, exist_ok=True)
	_clear_partial_project(config)
	argv = _import_argv(config)
	run = analyze_headless_fn or partial(_default_run, timeout_seconds=timeout_seconds)
	result = run(argv)

	if result.returncode != 0 or _ANALYSIS_SUCCESS_MARKER not in (result.stdout or ""):
		raise GhidraError(
			f"project bootstrap failed (rc={result.returncode})\n"
			f"--- argv ---\n{argv}\n"
			f"--- stdout (tail) ---\n{_tail(result.stdout)}\n"
			f"--- stderr (tail) ---\n{_tail(result.stderr)}"
		)

	if not _is_bootstrapped(config):
		raise GhidraError(
			f"bootstrap reported success but no committed program landed under "
			f"{config.project_rep} (stale or locked Ghidra project state?)\n"
			f"--- argv ---\n{argv}\n"
			f"--- stdout (tail) ---\n{_tail(result.stdout)}"
		)


def ghidra_decompile_function(
	va: int,
	config: GhidraConfig,
	*,
	analyze_headless_fn: AnalyzeHeadlessFn | None = None,
	timeout_seconds: float = 120.0,
) -> str:
	"""Returns the pseudo-C for the function at `va`. Project must exist."""
	if not _is_bootstrapped(config):
		raise GhidraError(
			f"project not bootstrapped: {config.project_dir} has no committed program. "
			"Call ghidra_project_ensure first."
		)

	with tempfile.NamedTemporaryFile(
		mode="r", suffix=".c", delete=False, dir=config.project_dir
	) as f:
		out_path = Path(f.name)
	try:
		argv = _decompile_argv(config, va, out_path)
		run = analyze_headless_fn or partial(_default_run, timeout_seconds=timeout_seconds)
		result = _run_with_lock_retry(argv, run)
		if result.returncode != 0:
			raise GhidraError(
				f"decompile failed for va=0x{va:08x} (rc={result.returncode})\n"
				f"--- stdout (tail) ---\n{_tail(result.stdout)}\n"
				f"--- stderr (tail) ---\n{_tail(result.stderr)}"
			)
		if not out_path.is_file() or out_path.stat().st_size == 0:
			raise GhidraError(
				f"decompile produced no output for va=0x{va:08x}\n"
				f"--- stdout (tail) ---\n{_tail(result.stdout)}"
			)
		return out_path.read_text()
	finally:
		out_path.unlink(missing_ok=True)


def ghidra_structs_dump(
	config: GhidraConfig,
	*,
	analyze_headless_fn: AnalyzeHeadlessFn | None = None,
	force: bool = False,
	timeout_seconds: float = 120.0,
) -> str:
	"""Harvest Ghidra's composite type layouts as C typedefs.

	Returns the contents of a header declaring every struct/union the
	XbeLoader symbol DB recognizes (XBE_FILE_HEADER, ...). The result is
	project-wide and stable, so it is cached at `config.structs_h` and reused
	across functions; pass `force=True` to re-dump. Project must already be
	bootstrapped (see ghidra_project_ensure)."""
	if config.structs_h.is_file() and not force:
		return config.structs_h.read_text()
	if not _is_bootstrapped(config):
		raise GhidraError(
			f"project not bootstrapped: {config.project_dir} has no committed program. "
			"Call ghidra_project_ensure first."
		)

	config.project_dir.mkdir(parents=True, exist_ok=True)
	with tempfile.NamedTemporaryFile(
		mode="r", suffix=".h", delete=False, dir=config.project_dir
	) as f:
		out_path = Path(f.name)
	try:
		argv = _dump_structs_argv(config, out_path)
		run = analyze_headless_fn or partial(_default_run, timeout_seconds=timeout_seconds)
		result = _run_with_lock_retry(argv, run)
		if result.returncode != 0:
			raise GhidraError(
				f"struct dump failed (rc={result.returncode})\n"
				f"--- stdout (tail) ---\n{_tail(result.stdout)}\n"
				f"--- stderr (tail) ---\n{_tail(result.stderr)}"
			)
		if not out_path.is_file() or out_path.stat().st_size == 0:
			raise GhidraError(
				f"struct dump produced no output\n--- stdout (tail) ---\n{_tail(result.stdout)}"
			)
		header = out_path.read_text()
	finally:
		out_path.unlink(missing_ok=True)

	config.structs_h.write_text(header)
	return header


def _run_with_lock_retry(
	argv: list[str],
	run: AnalyzeHeadlessFn,
	*,
	attempts: int = _LOCK_RETRY_ATTEMPTS,
	backoff_seconds: float = _LOCK_RETRY_BACKOFF_SECONDS,
	sleep_fn: Callable[[float], None] = time.sleep,
) -> subprocess.CompletedProcess[str]:
	"""Retry when Ghidra reports `Unable to lock project` (transient JVM-shutdown race)."""
	if attempts < 1:
		raise ValueError(f"attempts must be >= 1, got {attempts}")
	for attempt in range(attempts):
		result = run(argv)
		stdout = result.stdout or ""
		stderr = result.stderr or ""
		if _LOCK_ERROR_MARKER not in stdout and _LOCK_ERROR_MARKER not in stderr:
			return result
		if attempt == attempts - 1:
			return result
		sleep_fn(backoff_seconds * (2**attempt))
	raise AssertionError("unreachable: loop returns on the final attempt")


def _clear_partial_project(config: GhidraConfig) -> None:
	"""Remove the marker `.gpr`, the `.rep` data dir, and any stray `.lock`, so a
	fresh import can recreate the project from scratch. A no-op for the parts
	that are absent. Only reached once `_is_bootstrapped` is false (no committed
	program), so nothing usable is discarded. The `.rep` must go because Ghidra
	will not import over an existing one — that partial dir is exactly what
	stalls the re-import — and the marker goes with it to keep the pair clean."""
	config.project_gpr.unlink(missing_ok=True)
	if config.project_rep.is_dir():
		shutil.rmtree(config.project_rep, ignore_errors=True)
	config.project_lock.unlink(missing_ok=True)


def _import_argv(config: GhidraConfig) -> list[str]:
	return [
		str(config.analyze_headless),
		str(config.project_dir),
		config.project_name,
		"-import",
		str(config.xbe_path),
		"-overwrite",
		"-loader",
		_XBE_LOADER,
	]


def _decompile_argv(config: GhidraConfig, va: int, out_path: Path) -> list[str]:
	return [
		str(config.analyze_headless),
		str(config.project_dir),
		config.project_name,
		"-process",
		config.program_name,
		"-noanalysis",
		"-scriptPath",
		str(config.script_dir),
		"-postScript",
		_DECOMPILE_SCRIPT,
		f"0x{va:08x}",
		str(out_path),
	]


def _dump_structs_argv(config: GhidraConfig, out_path: Path) -> list[str]:
	return [
		str(config.analyze_headless),
		str(config.project_dir),
		config.project_name,
		"-process",
		config.program_name,
		"-noanalysis",
		"-scriptPath",
		str(config.script_dir),
		"-postScript",
		_DUMP_STRUCTS_SCRIPT,
		str(out_path),
	]


def _default_run(
	argv: list[str], timeout_seconds: float = 600.0
) -> subprocess.CompletedProcess[str]:
	return subprocess.run(
		argv,
		capture_output=True,
		text=True,
		check=False,
		timeout=timeout_seconds,
	)


def _tail(s: str | None, lines: int = 40) -> str:
	if not s:
		return "(empty)"
	parts = s.splitlines()
	return "\n".join(parts[-lines:])


_PSEUDO_C_TYPE_MAP = {
	"undefined8": "__int64",
	"undefined7": "__int64",
	"undefined6": "__int64",
	"undefined5": "__int64",
	"undefined4": "int",
	"undefined3": "int",
	"undefined2": "short",
	"undefined1": "char",
	"undefined": "void",
	# Ghidra's x87 80-bit extended types (universal decompiler output). MSVC has
	# no 80-bit float and its `long double` is 8 bytes, so `double` both compiles
	# and is the closest match; the agent refines from there.
	"float10": "double",
	"unkbyte10": "double",
	"byte": "BYTE",
	"ushort": "USHORT",
	"uint": "UINT",
	"ulong": "ULONG",
	"dword": "DWORD",
	"qword": "ULONGLONG",
	"longlong": "__int64",
	"ulonglong": "ULONGLONG",
	"bool": "int",  # Ghidra emits C99 bool; MSVC 7.1 /TC is C89
	# NOTE: `code` is intentionally NOT mapped. It's Ghidra's function element
	# type, used as `code *` for function pointers; mapping it to `void` turns an
	# indirect call `(**(code **)x)()` into an uncallable `(**(void **)x)()`
	# (C2100). ctx.h typedefs `code` as a function type so such calls compile.
}

_PSEUDO_C_TYPE_PATTERN = re.compile(
	r"\b(" + "|".join(re.escape(k) for k in _PSEUDO_C_TYPE_MAP) + r")\b"
)
_PSEUDO_C_FUN_PATTERN = re.compile(r"\bFUN_([0-9a-fA-F]{8})\b")
# Match DAT_, _DAT_ (overlap variant), PTR_DAT_ (pointer-at-address), and
# PTR_LAB_ (pointer-at-address holding a code-label pointer) globals. All denote
# a global at a fixed address, so all rewrite identically to an absolute deref.
# Bare LAB_ is deliberately excluded — it's a valid local goto target.
_DAT_PREFIX = r"(?:_?(?:PTR_)?DAT_|PTR_LAB_)"
_PSEUDO_C_DAT_ADDR_PATTERN = re.compile(r"&\s*" + _DAT_PREFIX + r"([0-9a-fA-F]{8})\b")
_PSEUDO_C_DAT_PATTERN = re.compile(r"\b" + _DAT_PREFIX + r"([0-9a-fA-F]{8})\b")
_PSEUDO_C_BOOL_LITERAL_PATTERN = re.compile(r"\b(true|false)\b")
_PSEUDO_C_THISCALL_PATTERN = re.compile(r"\b__thiscall\b\s*")


def _pseudo_c_dat_rewrite(c: str) -> str:
	"""Rewrite Ghidra's DAT_<addr> globals to absolute-address references.

	Xbox images load at a fixed base, so a global accessed as DAT_004618c8 is
	an absolute disp32 in the original; target.obj carries no relocation for
	it. An `extern` decl would emit one (mismatch); an absolute-address deref
	emits the same baked disp32, so the draft both compiles and can match.

	`int` is a 4-byte default; byte/word accesses may read too wide, but the
	agent refines from there. `&DAT_x` collapses to a plain pointer cast.
	"""
	c = _PSEUDO_C_DAT_ADDR_PATTERN.sub(lambda m: f"((int *)0x{m.group(1)})", c)
	c = _PSEUDO_C_DAT_PATTERN.sub(lambda m: f"(*(int *)0x{m.group(1)})", c)
	return c


_SUBPIECE_PATTERN = re.compile(r"\._(\d+)_(\d+)_")
_SUBPIECE_TYPE_BY_SIZE = {1: "char", 2: "short", 4: "int", 8: "__int64"}


def _subpiece_operand_start(c: str, dot: int) -> int:
	"""Index where the postfix operand ending just before `dot` begins.

	Scans left over an identifier / member chain (`a.b`, `a->b`), balanced
	`(...)`/`[...]` groups, so the whole accessed value is captured — not just its
	rightmost token."""
	i = dot
	while i > 0:
		ch = c[i - 1]
		if ch in ")]":
			open_ch = "(" if ch == ")" else "["
			depth, j = 1, i - 2
			while j >= 0 and depth:
				if c[j] == ch:
					depth += 1
				elif c[j] == open_ch:
					depth -= 1
				j -= 1
			i = j + 1
		elif ch.isalnum() or ch == "_":
			j = i - 1
			while j >= 0 and (c[j].isalnum() or c[j] == "_"):
				j -= 1
			i = j + 1
		elif ch == ".":
			i -= 1
		elif ch == ">" and i >= 2 and c[i - 2] == "-":
			i -= 2
		else:
			break
	return i


def _pseudo_c_subpiece_rewrite(c: str) -> str:
	"""Rewrite Ghidra's `EXPR._<offset>_<size>_` sub-range accesses to a sized,
	offset deref: `(*(T *)((char *)&(EXPR) + offset))`.

	Ghidra emits these to read part of a wider value; MSVC parses `._0_1_` as a
	member access on a non-struct (C2224). Size picks the element type (1→char,
	2→short, 4→int, 8→__int64; odd sizes fall back to int). Safe by construction:
	a draft containing a subpiece never compiles as-is, so a rewrite can't regress
	a working baseline."""
	out: list[str] = []
	last = 0
	for m in _SUBPIECE_PATTERN.finditer(c):
		start = _subpiece_operand_start(c, m.start())
		operand = c[start : m.start()]
		if start < last or not operand.strip():
			continue  # overlaps a prior rewrite or has no operand to anchor — skip
		typ = _SUBPIECE_TYPE_BY_SIZE.get(int(m.group(2)), "int")
		out.append(c[last:start])
		out.append(f"(*({typ} *)((char *)&({operand}) + {int(m.group(1))}))")
		last = m.end()
	out.append(c[last:])
	return "".join(out)


def _pseudo_c_struct_instance_rewrite(c: str, struct_names: tuple[str, ...]) -> str:
	"""Rewrite Ghidra's `<Type>_<addr>` struct instances to typed absolute derefs.

	Ghidra names a recognized struct instance at a fixed address as
	`XBE_FILE_HEADER_00010000`. Xbox images load at a fixed base, so that is an
	absolute reference carrying no reloc; `(*(XBE_FILE_HEADER *)0x00010000)`
	emits the same baked disp32 and lets `.member` resolve against the harvested
	layout. `&inst` collapses to a plain typed pointer cast.

	Driven entirely by the harvested type names, so it stays binary-agnostic;
	with no names it is a no-op. Names are tried longest-first so a longer type
	is never clipped to a shorter prefix.
	"""
	if not struct_names:
		return c
	alt = "|".join(re.escape(n) for n in sorted(struct_names, key=len, reverse=True))
	addr_of = re.compile(r"&\s*(" + alt + r")_([0-9a-fA-F]{8})\b")
	value = re.compile(r"\b(" + alt + r")_([0-9a-fA-F]{8})\b")
	c = addr_of.sub(lambda m: f"(({m.group(1)} *)0x{m.group(2)})", c)
	c = value.sub(lambda m: f"(*({m.group(1)} *)0x{m.group(2)})", c)
	return c


def _pseudo_c_stdcall_target_rewrite(c: str, name: str) -> str:
	"""Pin the target's definition to `int __stdcall <name>` to match ctx.h.

	Ghidra emits the definition with no convention keyword and often a `void`
	return, while ctx.h forward-declares a stdcall target as
	`int __stdcall <name>(...)`. Left as-is the two collide (MSVC C2373 on the
	modifier, C2371 on the return type) and attempt 0 never compiles. Only the
	definition header; the `<name>(...)` occurrence immediately followed by
	`{`; is rewritten; call sites (which end in `;`) are left untouched.
	"""
	pattern = re.compile(
		r"(?m)^[A-Za-z_][\w \t\*]*?\b" + re.escape(name) + r"(\s*\([^;{}]*\))(?=\s*\{)"
	)
	return pattern.sub(lambda m: f"int __stdcall {name}{m.group(1)}", c)


def _count_top_level_args(args: str) -> int:
	"""Number of comma-separated arguments at paren/bracket depth 0."""
	if not args.strip():
		return 0
	depth = 0
	count = 1
	for ch in args:
		if ch in "([{":
			depth += 1
		elif ch in ")]}":
			depth -= 1
		elif ch == "," and depth == 0:
			count += 1
	return count


def _pad_call_args(c: str, name: str, arity: int) -> str:
	"""Pad every `name(...)` call shorter than `arity` with trailing `0` args.

	Balance-scans for the matching close paren so nested calls are spanned
	correctly. Calls with `>= arity` args are left untouched.
	"""
	token = re.compile(r"\b" + re.escape(name) + r"\s*\(")
	out: list[str] = []
	i = 0
	while True:
		m = token.search(c, i)
		if m is None:
			out.append(c[i:])
			break
		out.append(c[i : m.end()])
		depth = 1
		j = m.end()
		while j < len(c) and depth:
			if c[j] == "(":
				depth += 1
			elif c[j] == ")":
				depth -= 1
				if depth == 0:
					break
			j += 1
		args = c[m.end() : j]
		n = _count_top_level_args(args)
		if n < arity:
			pad = ", ".join(["0"] * (arity - n))
			args = pad if n == 0 else f"{args.rstrip()}, {pad}"
		out.append(args)
		out.append(c[j : j + 1])
		i = j + 1
	return "".join(out)


def _pseudo_c_pad_stdcall_calls(c: str, callee_arities: dict[str, int]) -> str:
	for name, arity in callee_arities.items():
		if arity > 0:
			c = _pad_call_args(c, name, arity)
	return c


def ghidra_pseudo_c_normalize(
	c: str,
	*,
	struct_names: tuple[str, ...] = (),
	stdcall_target: str | None = None,
	callee_arities: dict[str, int] | None = None,
) -> str:
	"""Best-effort rewrite of Ghidra's pseudo-C into something MSVC will parse.

	Handles the common placeholder types, Ghidra's FUN_xxxxxxxx → our
	fn_XXXXXXXX naming, DAT_xxxxxxxx globals → absolute-address derefs, harvested
	`<Type>_<addr>` struct instances → typed absolute derefs, and the C99
	true/false literals. Leaves LAB_ labels alone (valid local goto targets).

	When `stdcall_target` is set (the post-rename target name), the target's
	definition header is pinned to `int __stdcall` so it agrees with ctx.h.
	`callee_arities` ({name: arg count}) pads under-count call sites so strict
	`@N` stdcall callee prototypes are satisfied.
	"""
	c = _PSEUDO_C_TYPE_PATTERN.sub(lambda m: _PSEUDO_C_TYPE_MAP[m.group(1)], c)
	c = _PSEUDO_C_FUN_PATTERN.sub(lambda m: f"fn_{m.group(1).upper()}", c)
	c = c.replace("XAPILIB::", "")  # C++ namespace prefix doesn't parse as C
	# MSVC 7.1 in C mode rejects __thiscall on a free-function decl; drop it so
	# the warm-start compiles (the agent restores the convention if it matters).
	c = _PSEUDO_C_THISCALL_PATTERN.sub("", c)
	if stdcall_target:
		c = _pseudo_c_stdcall_target_rewrite(c, stdcall_target)
	if callee_arities:
		c = _pseudo_c_pad_stdcall_calls(c, callee_arities)
	c = _pseudo_c_struct_instance_rewrite(c, struct_names)
	c = _pseudo_c_dat_rewrite(c)
	c = _pseudo_c_subpiece_rewrite(c)
	c = _PSEUDO_C_BOOL_LITERAL_PATTERN.sub(lambda m: "1" if m.group(1) == "true" else "0", c)
	return c


_STRUCT_TYPEDEF_NAME_PATTERN = re.compile(r"^\}\s*([A-Za-z_]\w*)\s*;", re.MULTILINE)


def ghidra_struct_names(header: str) -> tuple[str, ...]:
	"""Names of the typedef'd composites in a harvested struct header, in order.

	Parses the `} NAME;` closer of each `typedef struct/union { ... } NAME;`
	block emitted by DumpStructs.java.
	"""
	return tuple(_STRUCT_TYPEDEF_NAME_PATTERN.findall(header))


_PSEUDO_C_WARNING_LINE_RE = re.compile(
	r"^/\* WARNING: Globals starting with '_'[^\n]*\n",
	re.MULTILINE,
)


def ghidra_pseudo_c_normalize_for_prompt(c: str) -> str:
	"""Light cleanup suitable for the LLM system prompt.

	Renames FUN_xxxxxxxx → fn_XXXXXXXX so callees match ctx.h's declared
	names. Strips XAPILIB:: (C++ namespace doesn't parse as C). Drops the
	noisy "Globals starting with '_'" warning Ghidra emits.

	Keeps `undefined4`/`byte`/etc. unchanged; those are the LLM's signal
	that Ghidra was uncertain about the type.
	"""
	c = _PSEUDO_C_FUN_PATTERN.sub(lambda m: f"fn_{m.group(1).upper()}", c)
	c = c.replace("XAPILIB::", "")
	c = _PSEUDO_C_WARNING_LINE_RE.sub("", c)
	return c


__all__ = [
	"AnalyzeHeadlessFn",
	"GhidraConfig",
	"GhidraError",
	"ghidra_config_from_env",
	"ghidra_decompile_function",
	"ghidra_project_ensure",
	"ghidra_structs_dump",
	"ghidra_pseudo_c_normalize",
	"ghidra_pseudo_c_normalize_for_prompt",
	"ghidra_struct_names",
]
