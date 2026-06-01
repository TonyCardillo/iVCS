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

import json
import shutil
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from src.coff_read import CoffObject, coff_object_read
from src.compile_tool import CompileOutput, default_compile_fn
from src.link_tool import default_link_fn
from src.project import FunctionEntry, FunctionStatus, Project, function_status
from src.relink import RelinkError, relink_place
from src.relink_image import LinkFn, function_object_compile, function_real_relink
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


_COMMON_HEADER_DIR = "include"
_COMMON_HEADER_NAME = "ivcs_common.h"


def _split_ctx_preamble(ctx_text: str) -> tuple[str, str]:
	"""Split a workspace ctx.h into (shared preamble, per-function tail).

	The preamble is the leading run of scalar `typedef ...;` lines the launcher
	emits identically for every function (BYTE, ULONG, HANDLE, ...). Everything
	from the first section comment on (the `/* Target */`, `/* xboxkrnl imports */`,
	`/* Callees */`, `/* Ghidra ... */` blocks) is function-specific. Extracting
	the preamble lets every committed source share one `include/ivcs_common.h`
	instead of carrying its own copy of ~25 identical typedefs.
	"""
	lines = ctx_text.splitlines()
	cut = 0
	for line in lines:
		stripped = line.strip()
		if stripped == "" or (stripped.startswith("typedef ") and stripped.endswith(";")):
			cut += 1
		else:
			break
	return "\n".join(lines[:cut]).strip(), "\n".join(lines[cut:]).strip()


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

	Writes `<name>.c` that includes the shared `include/ivcs_common.h` (the typedef
	preamble every function shares) plus, when the function needs them, a slim
	`<name>.ctx.h` carrying only its own target/kernel/callee/struct decls. Then
	recompiles it to confirm it still builds outside its workspace. Only matched
	functions are committed unless `force=True`. Idempotent — re-committing
	overwrites, and drops a now-unneeded per-function header.
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
	common, tail = _split_ctx_preamble(workspace.ctx_h.read_text())

	# Shared preamble lives once per project; sources include it.
	common_dir = project.src_root / _COMMON_HEADER_DIR
	common_dir.mkdir(parents=True, exist_ok=True)
	common_body = f"#pragma once\n\n{common}\n" if common else "#pragma once\n"
	(common_dir / _COMMON_HEADER_NAME).write_text(common_body)

	includes = [f'#include "../{_COMMON_HEADER_DIR}/{_COMMON_HEADER_NAME}"']
	ctx_dest = dest.with_name(f"{fn.name}.ctx.h")
	if tail:
		ctx_dest.write_text(tail + "\n")
		includes.append(f'#include "{ctx_dest.name}"')
	else:
		ctx_dest.unlink(missing_ok=True)  # idempotent: drop a stale per-fn header
	dest.write_text("\n".join(includes) + f"\n\n{workspace.best_c.read_text()}")

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
	sdk_bytes: int = 0  # SDK-identified functions in this segment, excluded from target
	sdk_count: int = 0

	@property
	def game_bytes(self) -> int:
		"""The real target in this segment: function bytes that aren't SDK code."""
		return self.function_bytes - self.sdk_bytes

	@property
	def matched_percent(self) -> float:
		return (self.matched_bytes / self.game_bytes * 100.0) if self.game_bytes else 0.0


def project_coverage(
	project: Project, parsed: ParsedXbe, *, sdk_vas: frozenset[int] = frozenset()
) -> tuple[SegmentCoverage, ...]:
	"""Per-segment matched/partial/committed coverage, with gaps and overlaps.

	Joins each segment's tiling with the matched-state classification from
	`function_status` — the splat-style "X% of this segment is done" view. Functions
	whose VA is in `sdk_vas` are counted as SDK and excluded from the match target.
	"""
	coverage: list[SegmentCoverage] = []
	for segment in project_segments(project, parsed):
		matched = partial = committed = sdk_bytes = sdk_count = 0
		for fn in segment.functions:
			if fn.va in sdk_vas:
				sdk_bytes += fn.size
				sdk_count += 1
				continue
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
				sdk_bytes=sdk_bytes,
				sdk_count=sdk_count,
			)
		)
	return tuple(coverage)


# --- Phase 4a: whole-image byte-splice verification -------------------------
# objdiff masks rel32/disp32, so "100% matched" can hide a wrong-address symbol;
# splicing each function to its real VA and byte-comparing closes that gap.


def _compiled_function_object(
	project: Project, fn: FunctionEntry, compile_fn: CompileFn
) -> CoffObject | None:
	"""Recompile a matched function's best.c standalone; return the parsed object.

	None when the workspace lacks inputs or the recompile fails — the verifier
	records that as an unverified function rather than raising.
	"""
	workspace = FunctionWorkspace(root=project.workspace_for(fn), function_name=fn.name)
	build_dir = Path(tempfile.mkdtemp())
	try:
		obj = function_object_compile(workspace, build_dir, fn.name, compile_fn)
		return coff_object_read(obj.read_bytes()) if obj is not None else None
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
	return _image_verify(
		project,
		lambda fn: _function_splice_verify(project, parsed, fn, resolve, compile_fn),
		on_result=on_result,
	)


# --- Phase 4b: real relink verification (Link.Exe) --------------------------
# Independent oracle: the real XDK linker, not our relocator. Disagreement with
# Phase 4a points at a relocation our own placement got wrong.


def _function_real_relink_verify(
	project: Project,
	parsed: ParsedXbe,
	fn: FunctionEntry,
	compile_fn: CompileFn,
	link_fn: LinkFn,
) -> FunctionVerify:
	relinked = function_real_relink(project, parsed, fn, compile_fn=compile_fn, link_fn=link_fn)
	if not relinked.ok:
		return FunctionVerify(fn.name, fn.va, fn.size, 0, relinked.reason)
	try:
		original = xbe_function_carve(parsed, fn.va, fn.size)
	except XbeFormatError as exc:
		return FunctionVerify(fn.name, fn.va, fn.size, 0, f"carve failed: {exc}")
	return _byte_match_verify(fn, relinked.function_bytes, original)


def image_real_relink_verify(
	project: Project,
	parsed: ParsedXbe,
	*,
	compile_fn: CompileFn = default_compile_fn,
	link_fn: LinkFn = default_link_fn,
	on_result: Callable[[FunctionVerify], None] | None = None,
) -> ImageVerify:
	"""Relink every matched function with Link.Exe at its true VA and byte-compare
	against the original image."""
	return _image_verify(
		project,
		lambda fn: _function_real_relink_verify(project, parsed, fn, compile_fn, link_fn),
		on_result=on_result,
	)


# --- Whole-image byte coverage (code AND data) ------------------------------
#
# project_coverage answers "% of enumerated code matched" per segment. This
# answers the wider, honest question: of every byte in the image — code,
# data, padding — how much is reconstructed from source vs. still carried
# verbatim from the original. Data sections (no enumerated functions) show up
# explicitly as all-gap, instead of being invisible.


@dataclass(frozen=True)
class SectionCoverage:
	name: str
	virtual_address: int
	virtual_size: int
	is_executable: bool
	matched_bytes: int
	partial_bytes: int
	sdk_bytes: int
	enumerated_bytes: int  # total bytes of enumerated functions in this section

	@property
	def gap_bytes(self) -> int:
		"""Bytes not covered by any enumerated function: padding, jump tables,
		data, and un-enumerated code. For a pure data section this is the whole
		section — carried verbatim, not reconstructed from source."""
		return max(0, self.virtual_size - self.enumerated_bytes)


@dataclass(frozen=True)
class ImageCoverage:
	sections: tuple[SectionCoverage, ...]

	@property
	def total_bytes(self) -> int:
		return sum(s.virtual_size for s in self.sections)

	@property
	def matched_bytes(self) -> int:
		return sum(s.matched_bytes for s in self.sections)

	@property
	def partial_bytes(self) -> int:
		return sum(s.partial_bytes for s in self.sections)

	@property
	def sdk_bytes(self) -> int:
		return sum(s.sdk_bytes for s in self.sections)

	@property
	def enumerated_bytes(self) -> int:
		return sum(s.enumerated_bytes for s in self.sections)

	@property
	def gap_bytes(self) -> int:
		return sum(s.gap_bytes for s in self.sections)

	@property
	def todo_code_bytes(self) -> int:
		"""Enumerated code that's neither matched, partial, nor SDK — functions
		we've identified but not yet decompiled. The real remaining code work,
		distinct from data/assets (which live in gap_bytes, carried verbatim)."""
		return max(
			0, self.enumerated_bytes - self.matched_bytes - self.partial_bytes - self.sdk_bytes
		)

	@property
	def from_source_percent(self) -> float:
		"""Matched (reconstructed-from-source) bytes over the whole image."""
		return (self.matched_bytes / self.total_bytes * 100.0) if self.total_bytes else 0.0


def image_coverage(
	statuses: Sequence[FunctionStatus],
	parsed: ParsedXbe,
	*,
	sdk_vas: frozenset[int] = frozenset(),
) -> ImageCoverage:
	"""Whole-binary byte coverage across every section, code and data alike.

	Takes precomputed FunctionStatus (from project_aggregate) so it adds no disk
	reads — fit for an always-on UI. Each function's bytes are tallied under the
	section that contains its VA; every section's remaining bytes become gap.
	"""
	by_section: dict[int, list[FunctionStatus]] = {}
	for status in statuses:
		section = xbe_section_containing_va(parsed, status.va)
		if section is not None:
			by_section.setdefault(section.virtual_address, []).append(status)

	sections: list[SectionCoverage] = []
	for section in parsed.sections:
		group = by_section.get(section.virtual_address, [])
		matched = partial = sdk = enumerated = 0
		for st in group:
			enumerated += st.size
			if st.va in sdk_vas:
				sdk += st.size
			elif st.state == "matched":
				matched += st.size
			elif st.state == "partial":
				partial += st.size
		sections.append(
			SectionCoverage(
				name=section.name,
				virtual_address=section.virtual_address,
				virtual_size=section.virtual_size,
				is_executable=section.is_executable,
				matched_bytes=matched,
				partial_bytes=partial,
				sdk_bytes=sdk,
				enumerated_bytes=enumerated,
			)
		)
	return ImageCoverage(tuple(sections))


# --- Verify-result cache (UI reads what the CLI computes) --------------------
#
# image_splice_verify / image_real_relink_verify recompile every matched
# function, so they're far too slow for a page render. The CLI runs them and
# caches the headline numbers next to project.json; the webui just displays the
# cached result (and how stale it is).


def image_verify_cache_path(project_path: Path | str) -> Path:
	return Path(project_path).parent / "image_verify.json"


def image_verify_cache_write(
	project_path: Path | str, result: ImageVerify, *, method: str, when: float
) -> None:
	"""Persist the headline verify numbers (not the full per-function list)."""
	image_verify_cache_path(project_path).write_text(
		json.dumps(
			{
				"method": method,
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
	except (json.JSONDecodeError, OSError):
		return None
