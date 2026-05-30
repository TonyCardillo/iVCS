"""Real relink of one matched function via Link.Exe (Phase 4b).

Where the byte-splice verifier (Phase 4a) places a function with our own
relocator, this drives the *real* XDK linker as an independent oracle: recompile
the matched source, resolve its externals to fixed image addresses with an
absolute-symbol stub, pad the front of `.text` so the function lands at the exact
VA it occupies in the original image, link, and read the placed bytes back out.

Exact placement: a PE image base must be 64 KB-aligned, so `/BASE` alone can't
pin a function to an arbitrary VA. The base is rounded down to 64 KB and the
shortfall is made up with N pad bytes of `.text` ordered ahead of the function:

    function VA = image_base + text_rva + pad

`text_rva` is the linker's choice (the headers rounded up to section alignment,
0x1000 in practice); the link is verified against the real RVA read back from the
PE and re-padded once if the guess was off.
"""

import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from src.coff import (
	IMAGE_SYM_CLASS_EXTERNAL,
	coff_absolute_symbols_build,
	coff_object_build,
)
from src.coff_read import CoffObject, coff_object_read
from src.compile_tool import default_compile_fn
from src.link_tool import LinkOutput, default_link_fn
from src.pe_read import pe_image_read
from src.project import FunctionEntry, Project
from src.relocs import relocs_image_va_resolver
from src.workspace import FunctionWorkspace
from src.xbe import ParsedXbe

_IMAGE_SYM_UNDEFINED = 0
_DEFAULT_TEXT_RVA = 0x1000
_PAD_SYMBOL = "ivcs_pad"


def relink_placement(fn_va: int, text_rva: int = _DEFAULT_TEXT_RVA) -> tuple[int, int]:
	"""Return (image_base, pad) placing a function at `fn_va` given `text_rva`.

	The base is 64 KB-aligned below `fn_va`; if the low bits leave no room for the
	section RVA the base drops another 64 KB so the pad stays non-negative.
	"""
	base = fn_va & ~0xFFFF
	pad = fn_va - base - text_rva
	if pad < 0:
		base -= 0x10000
		pad = fn_va - base - text_rva
	return base, pad


@dataclass(frozen=True)
class RealRelinkResult:
	"""Outcome of relinking one function with the real linker.

	`function_bytes` is the function's machine code as the linker placed it at its
	true VA (length = fn.size), ready to byte-compare against the original image;
	`reason` is None on success and a short diagnostic otherwise.
	"""

	name: str
	va: int
	size: int
	function_bytes: bytes | None
	reason: str | None

	@property
	def ok(self) -> bool:
		return self.reason is None and self.function_bytes is not None


def _external_names(obj: CoffObject, *, defined: bool) -> list[str]:
	"""External symbol names that are defined in (a section of) this object, or
	undefined (to be resolved elsewhere)."""
	out = []
	for sym in obj.symbols:
		if sym.storage_class != IMAGE_SYM_CLASS_EXTERNAL:
			continue
		is_defined = sym.section_number >= 1
		if is_defined == defined:
			out.append(sym.name)
	return out


CompileFn = Callable[[Path, Path, Path], object]
LinkFn = Callable[..., LinkOutput]


def function_real_relink(
	project: Project,
	parsed: ParsedXbe,
	fn: FunctionEntry,
	*,
	compile_fn: CompileFn = default_compile_fn,
	link_fn: LinkFn = default_link_fn,
	resolve: Callable[[str], int | None] | None = None,
) -> RealRelinkResult:
	"""Recompile, relink at the function's true VA via Link.Exe, return placed bytes."""
	workspace = FunctionWorkspace(root=project.workspace_for(fn), function_name=fn.name)
	if not workspace.best_c.is_file() or not workspace.ctx_h.is_file():
		return RealRelinkResult(fn.name, fn.va, fn.size, None, "missing best.c/ctx.h")
	if resolve is None:
		resolve = relocs_image_va_resolver(parsed)

	build = Path(tempfile.mkdtemp())
	try:
		fobj = _recompile(workspace, build, fn, compile_fn)
		if fobj is None:
			return RealRelinkResult(fn.name, fn.va, fn.size, None, "recompile failed")
		obj = coff_object_read(fobj.read_bytes())

		retain = _external_names(obj, defined=True)
		if not retain:
			return RealRelinkResult(fn.name, fn.va, fn.size, None, "no function symbol to retain")

		stub: dict[str, int] = {}
		for name in _external_names(obj, defined=False):
			va = resolve(name)
			if va is None:
				reason = f"unresolved external {name!r}"
				return RealRelinkResult(fn.name, fn.va, fn.size, None, reason)
			stub[name] = va

		return _link_place_extract(build, fobj, fn, retain, stub, link_fn)
	finally:
		shutil.rmtree(build, ignore_errors=True)


def _recompile(
	workspace: FunctionWorkspace, build: Path, fn: FunctionEntry, compile_fn: CompileFn
) -> Path | None:
	ctx = build / f"{fn.name}.ctx.h"
	ctx.write_text(workspace.ctx_h.read_text())
	src = build / f"{fn.name}.c"
	src.write_text(f'#include "{ctx.name}"\n\n{workspace.best_c.read_text()}')
	fobj = build / f"{fn.name}.obj"
	if not compile_fn(src, fobj, build).success or not fobj.is_file():
		return None
	return fobj


def _link_place_extract(
	build: Path,
	fobj: Path,
	fn: FunctionEntry,
	retain: list[str],
	stub: dict[str, int],
	link_fn: LinkFn,
) -> RealRelinkResult:
	"""Link [pad, function, stub] so the function lands at fn.va, and extract it.

	One link is done at the assumed text RVA; if the function landed off-target
	the actual RVA (read back from the PE) drives a single re-pad and relink.

	MS Link treats an absolute-symbol value as an RVA and adds the image base, so
	each external's stub value is encoded as `target_va - base` (mod 2^32); the
	linker's `base + (target_va - base)` then lands exactly on `target_va`.
	"""
	includes = tuple(f"/INCLUDE:{name}" for name in (_PAD_SYMBOL, *retain))

	text_rva = _DEFAULT_TEXT_RVA
	last_reason = "link failed"
	for _ in range(2):
		base, pad = relink_placement(fn.va, text_rva)
		if pad < 0:
			return RealRelinkResult(fn.name, fn.va, fn.size, None, "cannot place (pad < 0)")

		pad_obj = build / "ivcs_pad.obj"
		pad_obj.write_bytes(coff_object_build(b"\x90" * pad, _PAD_SYMBOL, relocations=[]))
		objs = [pad_obj, fobj]
		if stub:
			stub_obj = build / "ivcs_stub.obj"
			rebased = {name: (va - base) & 0xFFFFFFFF for name, va in stub.items()}
			stub_obj.write_bytes(coff_absolute_symbols_build(rebased))
			objs.append(stub_obj)
		out = build / "relinked.dll"
		out.unlink(missing_ok=True)

		link_out = link_fn(objs, out, base_address=base, extra_flags=("/OPT:NOREF", *includes))
		if not link_out.success or not out.is_file():
			last_reason = "link failed"
			break

		text = _text_section(out)
		if text is None:
			last_reason = "no .text in linked image"
			break

		landed_va = text.virtual_address + pad
		if landed_va == fn.va:
			return RealRelinkResult(
				fn.name, fn.va, fn.size, text.raw[pad : pad + fn.size], None
			)
		# The guessed RVA was off; correct it from the real layout and retry once.
		text_rva = text.virtual_address - base
		last_reason = f"placed at {landed_va:#x}, expected {fn.va:#x}"

	return RealRelinkResult(fn.name, fn.va, fn.size, None, last_reason)


def _text_section(pe_path: Path):
	pe = pe_image_read(pe_path.read_bytes())
	for section in pe.sections:
		if section.name == ".text":
			return section
	return None
