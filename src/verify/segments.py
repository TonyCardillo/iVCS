"""Segment model: group a project's functions under the XBE section they live
in, and route each function's committed source to a stable path.

splat's segment map, but derived from the XBE — the section headers are
authoritative, so nothing is hand-authored or duplicated into config. This is
the base layer the commit and coverage stages build on.
"""

from dataclasses import dataclass
from pathlib import Path

from src.core.project import FunctionEntry, Project
from src.formats.xbe import ParsedXbe, xbe_section_containing_va


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
