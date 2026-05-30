"""Source-tree integrator: turn matched per-function C into a buildable,
segment-organized tree and report whole-project coverage.

The matching loop works one function at a time, leaving a `best.c` in each
scratch workspace. This module is the layer that makes those matches compound:
it groups the project's functions under the XBE section (segment) they belong
to, commits matched sources into a version-controlled tree, and reports how
much of each segment is done.

splat's segment map, but derived from the XBE — the section headers are
authoritative, so nothing is hand-authored or duplicated into config.

Phase 1 (here): the segment model — grouping, gaps, overlaps, source paths.
"""

import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from src.coff_read import CoffObject, coff_object_read
from src.compile_tool import CompileOutput, default_compile_fn
from src.link_tool import default_link_fn
from src.project import FunctionEntry, Project, function_status
from src.relink import RelinkError, relink_place
from src.relink_image import LinkFn, function_real_relink
from src.relocs import relocs_image_va_resolver
from src.workspace import FunctionWorkspace
from src.xbe import ParsedXbe, XbeFormatError, xbe_function_carve, xbe_section_containing_va

CompileFn = Callable[[Path, Path, Path], CompileOutput]
"""(c_source, out_obj, workspace_root) -> CompileOutput. Injected for testing."""


@dataclass(frozen=True)
class Segment:
	"""One XBE section plus the project functions that live in it (va-sorted)."""

	section: str
	virtual_address: int
	virtual_size: int
	is_executable: bool
	functions: tuple[FunctionEntry, ...]


@dataclass(frozen=True)
class SegmentGap:
	"""A byte range within a segment that no function claims."""

	virtual_address: int
	size: int


@dataclass(frozen=True)
class SegmentOverlap:
	"""Two functions whose byte ranges intersect — an enumeration bug."""

	first: FunctionEntry
	second: FunctionEntry
	overlap_bytes: int


def project_segments(project: Project, parsed: ParsedXbe) -> tuple[Segment, ...]:
	"""Group the project's functions under the section that contains each.

	One Segment per section holding at least one function, in section order;
	functions within a segment are sorted by virtual address. A function whose
	VA falls in no section is skipped here (it surfaces as a byte discrepancy in
	coverage rather than being silently folded into the wrong segment).

	Keyed by section virtual address, not name: real XBEs reuse section names
	(Halo 2 has four `BINKYUY2` sections), so name-keying would conflate them.
	"""
	by_va: dict[int, list[FunctionEntry]] = {}
	for fn in project.functions:
		section = xbe_section_containing_va(parsed, fn.va)
		if section is not None:
			by_va.setdefault(section.virtual_address, []).append(fn)

	segments: list[Segment] = []
	for section in parsed.sections:
		fns = by_va.get(section.virtual_address)
		if not fns:
			continue
		segments.append(
			Segment(
				section=section.name,
				virtual_address=section.virtual_address,
				virtual_size=section.virtual_size,
				is_executable=section.is_executable,
				functions=tuple(sorted(fns, key=lambda f: f.va)),
			)
		)
	return tuple(segments)


def segment_gaps(segment: Segment) -> tuple[SegmentGap, ...]:
	"""Byte ranges in the segment not covered by any function.

	A gap is emitted before the first function, between consecutive functions,
	and after the last up to the segment's virtual end. Overlapping functions
	never produce a negative gap (the cursor only moves forward); report those
	with `segment_overlaps`.
	"""
	gaps: list[SegmentGap] = []
	cursor = segment.virtual_address
	end = segment.virtual_address + segment.virtual_size
	for fn in segment.functions:
		if fn.va > cursor:
			gaps.append(SegmentGap(cursor, fn.va - cursor))
		cursor = max(cursor, fn.va + fn.size)
	if cursor < end:
		gaps.append(SegmentGap(cursor, end - cursor))
	return tuple(gaps)


def segment_overlaps(segment: Segment) -> tuple[SegmentOverlap, ...]:
	"""Functions whose byte ranges intersect, walking va-sorted order.

	Each function is compared against the furthest end seen so far (not just its
	immediate predecessor), so a function nested inside a larger earlier one is
	still caught.
	"""
	overlaps: list[SegmentOverlap] = []
	max_end = segment.virtual_address
	holder: FunctionEntry | None = None
	for fn in segment.functions:
		if holder is not None and fn.va < max_end:
			overlaps.append(SegmentOverlap(holder, fn, max_end - fn.va))
		if fn.va + fn.size > max_end:
			max_end = fn.va + fn.size
			holder = fn
	return tuple(overlaps)


def _safe_dirname(section_name: str) -> str:
	"""Section name as a directory: strip the leading dot so `.text` isn't a
	hidden directory."""
	return section_name.lstrip(".") or "section"


def function_source_path(project: Project, parsed: ParsedXbe, fn: FunctionEntry) -> Path:
	"""Where fn's committed source belongs: `<src_root>/<section>/<name>.c`.

	A function outside any section is routed to an `_orphan` directory rather
	than guessed into a segment.
	"""
	section = xbe_section_containing_va(parsed, fn.va)
	section_dir = _safe_dirname(section.name) if section is not None else "_orphan"
	return project.src_root / section_dir / f"{fn.name}.c"


def _self_contained_source(ctx_filename: str, best_c: str) -> str:
	"""best.c carries no include; prepend its copied ctx.h so it builds alone."""
	return f'#include "{ctx_filename}"\n\n{best_c}'


@dataclass(frozen=True)
class CommitResult:
	"""Outcome of committing one function's source into the tree.

	`skipped_reason` is set when nothing was written (not matched, missing
	inputs); otherwise the source was committed and `compiled` reports whether
	it still builds standalone (a False here is a ctx-drift warning, not a skip).
	"""

	path: Path
	compiled: bool
	skipped_reason: str | None


def integrate_commit(
	project: Project,
	parsed: ParsedXbe,
	fn: FunctionEntry,
	*,
	compile_fn: CompileFn = default_compile_fn,
	force: bool = False,
) -> CommitResult:
	"""Promote a matched function's `best.c` into the source tree.

	Writes a self-contained `<name>.c` (`#include "<name>.ctx.h"` + the body,
	since `best.c` carries no include) alongside a copied `<name>.ctx.h`, then
	recompiles it to confirm it still builds outside its workspace. Only matched
	functions are committed unless `force=True`. Idempotent — re-committing
	overwrites.
	"""
	dest = function_source_path(project, parsed, fn)
	status = function_status(project, fn)
	if status.state != "matched" and not force:
		return CommitResult(dest, False, f"not matched (state={status.state}); pass force=True")

	workspace = FunctionWorkspace(root=project.workspace_for(fn), function_name=fn.name)
	if not workspace.best_c.is_file():
		return CommitResult(dest, False, "no best.c in workspace")
	if not workspace.ctx_h.is_file():
		return CommitResult(dest, False, "no ctx.h in workspace")

	dest.parent.mkdir(parents=True, exist_ok=True)
	ctx_dest = dest.with_name(f"{fn.name}.ctx.h")
	ctx_dest.write_text(workspace.ctx_h.read_text())
	dest.write_text(_self_contained_source(ctx_dest.name, workspace.best_c.read_text()))

	obj_dir = Path(tempfile.mkdtemp())
	try:
		compiled = bool(compile_fn(dest, obj_dir / f"{fn.name}.obj", dest.parent).success)
	finally:
		shutil.rmtree(obj_dir, ignore_errors=True)
	return CommitResult(dest, compiled, None)


@dataclass(frozen=True)
class SegmentCoverage:
	"""How much of one segment's enumerated code is matched / committed.

	`function_bytes` is the total size of the functions in the segment (the code
	we're trying to match); `matched_bytes`/`partial_bytes` are subsets of it.
	`committed` counts functions whose source is present in the tree.
	"""

	segment: Segment
	matched_bytes: int
	partial_bytes: int
	function_bytes: int
	committed: int
	gaps: tuple[SegmentGap, ...]
	overlaps: tuple[SegmentOverlap, ...]

	@property
	def matched_percent(self) -> float:
		return (self.matched_bytes / self.function_bytes * 100.0) if self.function_bytes else 0.0


def project_coverage(project: Project, parsed: ParsedXbe) -> tuple[SegmentCoverage, ...]:
	"""Per-segment matched/partial/committed coverage, with gaps and overlaps.

	Joins each segment's tiling with the matched-state classification from
	`function_status` — the splat-style "X% of this segment is done" view.
	"""
	coverage: list[SegmentCoverage] = []
	for segment in project_segments(project, parsed):
		matched = partial = committed = 0
		for fn in segment.functions:
			state = function_status(project, fn).state
			if state == "matched":
				matched += fn.size
			elif state == "partial":
				partial += fn.size
			if function_source_path(project, parsed, fn).is_file():
				committed += 1
		coverage.append(
			SegmentCoverage(
				segment=segment,
				matched_bytes=matched,
				partial_bytes=partial,
				function_bytes=sum(f.size for f in segment.functions),
				committed=committed,
				gaps=segment_gaps(segment),
				overlaps=segment_overlaps(segment),
			)
		)
	return tuple(coverage)


# --- Phase 4a: whole-image byte-splice verification -------------------------
#
# The per-function objdiff is relocation-aware: it masks the rel32/disp32 fields
# so a function can read "100% matched" even if a symbol resolves to the wrong
# address. Splice verification closes that gap — recompile the matched source,
# relocate it to the VA the function actually occupies, and byte-compare against
# the original image. A whole-image "verified %" is a stronger claim than the
# sum of per-function match percents.

def _compiled_function_object(
	project: Project, fn: FunctionEntry, compile_fn: CompileFn
) -> CoffObject | None:
	"""Recompile a matched function's best.c standalone; return the parsed object.

	None when the workspace lacks inputs or the recompile fails — the verifier
	records that as an unverified function rather than raising.
	"""
	workspace = FunctionWorkspace(root=project.workspace_for(fn), function_name=fn.name)
	if not workspace.best_c.is_file() or not workspace.ctx_h.is_file():
		return None

	build_dir = Path(tempfile.mkdtemp())
	try:
		ctx = build_dir / f"{fn.name}.ctx.h"
		ctx.write_text(workspace.ctx_h.read_text())
		src = build_dir / f"{fn.name}.c"
		src.write_text(_self_contained_source(ctx.name, workspace.best_c.read_text()))
		obj = build_dir / f"{fn.name}.obj"
		if not compile_fn(src, obj, build_dir).success or not obj.is_file():
			return None
		return coff_object_read(obj.read_bytes())
	finally:
		shutil.rmtree(build_dir, ignore_errors=True)


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
	"""Count how many of fn's bytes the placed bytes reproduce, as a FunctionVerify."""
	verified = sum(1 for i in range(fn.size) if i < len(placed) and placed[i] == original[i])
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
) -> FunctionVerify:
	try:
		original = xbe_function_carve(parsed, fn.va, fn.size)
	except XbeFormatError as exc:
		return FunctionVerify(fn.name, fn.va, fn.size, 0, f"carve failed: {exc}")

	obj = _compiled_function_object(project, fn, compile_fn)
	if obj is None:
		return FunctionVerify(fn.name, fn.va, fn.size, 0, "recompile failed or missing inputs")

	try:
		placed = relink_place(obj, fn.va, resolve)
	except RelinkError as exc:
		return FunctionVerify(fn.name, fn.va, fn.size, 0, f"relink failed: {exc}")

	return _byte_match_verify(fn, placed, original)


def image_splice_verify(
	project: Project,
	parsed: ParsedXbe,
	*,
	compile_fn: CompileFn = default_compile_fn,
) -> ImageVerify:
	"""Recompile every matched function, relocate it to its VA, and byte-compare
	against the original image. Returns per-function and whole-image verified
	byte counts."""
	resolve = relocs_image_va_resolver(parsed)
	results = [
		_function_splice_verify(project, parsed, fn, resolve, compile_fn)
		for fn in _matched_functions(project)
	]
	return ImageVerify(
		functions=tuple(results),
		matched_bytes=sum(r.size for r in results),
		verified_bytes=sum(r.verified_bytes for r in results),
	)


# --- Phase 4b: real relink verification (Link.Exe) --------------------------
#
# An independent oracle for the same claim: instead of our own relocator, drive
# the real XDK linker over each matched function (placed at its true VA with an
# absolute-symbol stub for its externals) and byte-compare the linker's output
# against the original image. Agreement with the splice verifier is strong
# evidence; disagreement points at a relocation our own placement got wrong.


def image_real_relink_verify(
	project: Project,
	parsed: ParsedXbe,
	*,
	compile_fn: CompileFn = default_compile_fn,
	link_fn: LinkFn = default_link_fn,
) -> ImageVerify:
	"""Relink every matched function with Link.Exe at its true VA and byte-compare
	against the original image."""
	results: list[FunctionVerify] = []
	for fn in _matched_functions(project):
		relinked = function_real_relink(
			project, parsed, fn, compile_fn=compile_fn, link_fn=link_fn
		)
		if not relinked.ok:
			results.append(FunctionVerify(fn.name, fn.va, fn.size, 0, relinked.reason))
			continue
		try:
			original = xbe_function_carve(parsed, fn.va, fn.size)
		except XbeFormatError as exc:
			results.append(FunctionVerify(fn.name, fn.va, fn.size, 0, f"carve failed: {exc}"))
			continue
		results.append(_byte_match_verify(fn, relinked.function_bytes, original))
	return ImageVerify(
		functions=tuple(results),
		matched_bytes=sum(r.size for r in results),
		verified_bytes=sum(r.verified_bytes for r in results),
	)
