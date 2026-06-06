"""Whole-image byte-splice verification, and the cache the UI reads it from.

objdiff masks rel32/disp32, so "100% matched" can hide a wrong-address symbol;
recompiling each matched function, splicing it to its real VA, and byte-comparing
against the original image closes that gap.

image_splice_verify recompiles every matched function, so it's far too slow for a
page render. The CLI runs it and caches the headline numbers next to project.json
(image_verify_cache_*); the webui just displays the cached result and how stale it is.
"""

import json
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from src.core.project import FunctionEntry, Project, function_status
from src.core.workspace import FunctionWorkspace
from src.decomp.compile_tool import CompileFn, default_compile_fn
from src.formats.coff_read import CoffObject, CoffReadError, coff_object_read
from src.formats.relocs import relocs_image_va_resolver
from src.formats.xbe import ParsedXbe, XbeFormatError, xbe_function_carve
from src.verify.relink import RelinkError, relink_place


def _self_contained_source(ctx_filename: str, best_c: str) -> str:
	"""best.c carries no include; prepend its copied ctx.h so it builds alone."""
	return f'#include "{ctx_filename}"\n\n{best_c}'


def function_object_compile(
	workspace: FunctionWorkspace, build_dir: Path, fn_name: str, compile_fn: CompileFn
) -> Path | None:
	"""Write a matched function's ctx.h + self-contained best.c into `build_dir`,
	compile it, and return the `.obj` path.

	None when the workspace lacks inputs or the compile fails — callers treat that
	as an unverified function rather than raising. The caller owns `build_dir`'s
	lifecycle.
	"""
	if not workspace.best_c.is_file() or not workspace.ctx_h.is_file():
		return None
	ctx = build_dir / f"{fn_name}.ctx.h"
	ctx.write_text(workspace.ctx_h.read_text())
	src = build_dir / f"{fn_name}.c"
	src.write_text(_self_contained_source(ctx.name, workspace.best_c.read_text()))
	obj = build_dir / f"{fn_name}.obj"
	if not compile_fn(src, obj, build_dir).success or not obj.is_file():
		return None
	return obj


def _compiled_function_object(
	project: Project, fn: FunctionEntry, compile_fn: CompileFn, build_dir: Path
) -> CoffObject | None:
	"""Recompile a matched function's best.c standalone; return the parsed object.

	None when the workspace lacks inputs or the recompile fails — the verifier
	records that as an unverified function rather than raising. `build_dir` is a
	scratch dir owned by the caller and shared across functions (outputs are keyed
	by function name, so they never collide).
	"""
	workspace = FunctionWorkspace(root=project.workspace_for(fn), function_name=fn.name)
	obj = function_object_compile(workspace, build_dir, fn.name, compile_fn)
	if obj is None:
		return None
	try:
		return coff_object_read(obj.read_bytes())
	except CoffReadError:
		# A non-COFF / corrupt recompile output is an unverified function, not a
		# loop-aborting error — the verifier records it like any other miss.
		return None


@dataclass(frozen=True)
class FunctionVerify:
	"""One matched function's splice result: how many of its bytes, placed at
	its real VA, reproduce the original image. `reason` is None on a full match."""

	name: str
	va: int
	size: int
	verified_bytes: int
	reason: str | None

	@property
	def is_verified(self) -> bool:
		return self.reason is None and self.verified_bytes == self.size


@dataclass(frozen=True)
class ImageVerify:
	functions: tuple[FunctionVerify, ...]
	matched_bytes: int
	verified_bytes: int

	@property
	def verified_percent(self) -> float:
		return (self.verified_bytes / self.matched_bytes * 100.0) if self.matched_bytes else 0.0


def _byte_match_verify(fn: FunctionEntry, placed: bytes, original: bytes) -> FunctionVerify:
	"""Count how many of fn's bytes the placed bytes reproduce, as a FunctionVerify.

	A relink that produces the wrong number of bytes is a hard failure: a short
	relink must not read as a partial/near match, and a long relink whose prefix
	happens to match must not read as fully verified. Both surface as a distinct
	'size mismatch' reason with zero verified bytes.
	"""
	if len(placed) != fn.size:
		reason = f"size mismatch: relink produced {len(placed)} bytes, expected {fn.size}"
		return FunctionVerify(fn.name, fn.va, fn.size, 0, reason)
	if len(original) != fn.size:
		reason = f"size mismatch: carved {len(original)} original bytes, expected {fn.size}"
		return FunctionVerify(fn.name, fn.va, fn.size, 0, reason)

	verified = sum(1 for i in range(fn.size) if placed[i] == original[i])
	reason = None if verified == fn.size else f"{verified}/{fn.size} bytes match"
	return FunctionVerify(fn.name, fn.va, fn.size, verified, reason)


def _matched_functions(project: Project) -> list[FunctionEntry]:
	return [f for f in project.functions if function_status(project, f).state == "matched"]


def _function_splice_verify(
	project: Project,
	parsed: ParsedXbe,
	fn: FunctionEntry,
	resolve: Callable[[str], int | None],
	compile_fn: CompileFn,
	build_dir: Path,
) -> FunctionVerify:
	try:
		original = xbe_function_carve(parsed, fn.va, fn.size)
	except XbeFormatError as exc:
		return FunctionVerify(fn.name, fn.va, fn.size, 0, f"carve failed: {exc}")

	obj = _compiled_function_object(project, fn, compile_fn, build_dir)
	if obj is None:
		return FunctionVerify(fn.name, fn.va, fn.size, 0, "recompile failed or missing inputs")

	try:
		placed = relink_place(obj, fn.va, resolve)
	except RelinkError as exc:
		return FunctionVerify(fn.name, fn.va, fn.size, 0, f"relink failed: {exc}")

	return _byte_match_verify(fn, placed, original)


def _image_verify(
	project: Project,
	verify_one: Callable[[FunctionEntry], FunctionVerify],
	*,
	on_result: Callable[[FunctionVerify], None] | None = None,
) -> ImageVerify:
	"""Assemble an ImageVerify by running `verify_one` over every matched function.

	The two verifiers differ only in how they check one function; this owns the
	shared per-image tally so neither has to repeat it. `on_result`, when given,
	is called with each FunctionVerify as it lands — for live progress."""
	results: list[FunctionVerify] = []
	for fn in _matched_functions(project):
		fv = verify_one(fn)
		results.append(fv)
		if on_result is not None:
			on_result(fv)
	return ImageVerify(
		functions=tuple(results),
		matched_bytes=sum(r.size for r in results),
		verified_bytes=sum(r.verified_bytes for r in results),
	)


def image_splice_verify(
	project: Project,
	parsed: ParsedXbe,
	*,
	compile_fn: CompileFn = default_compile_fn,
	on_result: Callable[[FunctionVerify], None] | None = None,
) -> ImageVerify:
	"""Recompile every matched function, relocate it to its VA, and byte-compare
	against the original image. Returns per-function and whole-image verified
	byte counts."""
	resolve = relocs_image_va_resolver(parsed)
	with tempfile.TemporaryDirectory() as build_dir:
		return _image_verify(
			project,
			lambda fn: _function_splice_verify(
				project, parsed, fn, resolve, compile_fn, Path(build_dir)
			),
			on_result=on_result,
		)


def image_verify_cache_path(project_path: Path | str) -> Path:
	return Path(project_path).parent / "image_verify.json"


def image_verify_cache_write(project_path: Path | str, result: ImageVerify, *, when: float) -> None:
	"""Persist the headline verify numbers (not the full per-function list)."""
	image_verify_cache_path(project_path).write_text(
		json.dumps(
			{
				"verified_bytes": result.verified_bytes,
				"matched_bytes": result.matched_bytes,
				"verified_percent": result.verified_percent,
				"functions": len(result.functions),
				"functions_verified": sum(1 for f in result.functions if f.is_verified),
				"generated_at": when,
			},
			indent=2,
		)
	)


def image_verify_cache_load(project_path: Path | str) -> dict | None:
	path = image_verify_cache_path(project_path)
	if not path.is_file():
		return None
	try:
		return json.loads(path.read_text())
	except json.JSONDecodeError, OSError:
		return None
