"""Coverage reporting: how much of the image is reconstructed from source.

Two views over the same segment model:
  - project_coverage — per-segment "X% of this segment's enumerated code is
    matched", the splat-style progress view (gaps and overlaps included).
  - image_coverage — the wider, honest question: of every byte in the image
    (code, data, padding), how much is matched vs. carried verbatim. Data
    sections show up explicitly as all-gap instead of being invisible.
"""

from collections.abc import Sequence
from dataclasses import dataclass

from src.core.project import FunctionStatus, Project, function_status
from src.formats.xbe import ParsedXbe, xbe_section_containing_va
from src.verify.segments import (
	Segment,
	SegmentGap,
	SegmentOverlap,
	function_source_path,
	project_segments,
	segment_gaps,
	segment_overlaps,
)


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
