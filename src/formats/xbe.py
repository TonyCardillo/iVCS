"""XBE (Xbox Executable) loader.

Parses the XBE header and section table, carves function bytes by virtual
address, and decodes the XOR-scrambled entry point and kernel-thunk
addresses for all three build flavors (retail, debug, Chihiro).

Reference: Cxbx-Reloaded's src/common/xbe/Xbe.h.
"""

import struct
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import capstone

XBE_MAGIC = b"XBEH"
HEADER_SIZE = 0x178
SECTION_HEADER_SIZE = 0x38

SECTION_FLAG_WRITABLE = 0x00000001
SECTION_FLAG_PRELOAD = 0x00000002
SECTION_FLAG_EXECUTABLE = 0x00000004
SECTION_FLAG_INSERTED_FILE = 0x00000008
SECTION_FLAG_HEAD_PAGE_RO = 0x00000010
SECTION_FLAG_TAIL_PAGE_RO = 0x00000020

# EP and KT use different keys, paired by build flavor. Verified against
# Cxbx-Reloaded and Halo 2 retail default.xbe (entry=0x002D0AEE, thunk=0x00411520).
XBE_EP_KEY_RETAIL = 0xA8FC57AB
XBE_EP_KEY_DEBUG = 0x94859D4B
XBE_EP_KEY_CHIHIRO = 0x40B5C16E
XBE_KT_KEY_RETAIL = 0x5B6D40B6
XBE_KT_KEY_DEBUG = 0xEFB1F152
XBE_KT_KEY_CHIHIRO = 0x2290059D


class XbeFormatError(ValueError):
	"""The byte stream is not a valid XBE."""


@dataclass(frozen=True)
class XbeHeader:
	base_address: int
	size_of_headers: int
	size_of_image: int
	size_of_image_header: int
	section_count: int
	section_headers_address: int
	entry_point_xor: int
	kernel_thunk_address_xor: int


@dataclass(frozen=True)
class XbeSection:
	name: str
	flags: int
	virtual_address: int
	virtual_size: int
	raw_address: int
	raw_size: int

	@property
	def is_executable(self) -> bool:
		return bool(self.flags & SECTION_FLAG_EXECUTABLE)

	@property
	def is_writable(self) -> bool:
		return bool(self.flags & SECTION_FLAG_WRITABLE)


@dataclass(frozen=True)
class ParsedXbe:
	header: XbeHeader
	sections: tuple[XbeSection, ...] = field(default_factory=tuple)
	data: bytes = b""


@dataclass(frozen=True)
class XbeBuildFlavor:
	name: str
	ep_key: int
	kt_key: int


XBE_BUILD_FLAVORS: tuple[XbeBuildFlavor, ...] = (
	XbeBuildFlavor("retail", XBE_EP_KEY_RETAIL, XBE_KT_KEY_RETAIL),
	XbeBuildFlavor("debug", XBE_EP_KEY_DEBUG, XBE_KT_KEY_DEBUG),
	XbeBuildFlavor("chihiro", XBE_EP_KEY_CHIHIRO, XBE_KT_KEY_CHIHIRO),
)


def is_xbe_magic_valid(data: bytes) -> bool:
	return len(data) >= 4 and data[:4] == XBE_MAGIC


def xbe_parse(data: bytes) -> ParsedXbe:
	if not is_xbe_magic_valid(data):
		raise XbeFormatError(f"bad magic (expected {XBE_MAGIC!r}, got {data[:4]!r})")
	if len(data) < HEADER_SIZE:
		raise XbeFormatError(f"header truncated (need {HEADER_SIZE} bytes, got {len(data)})")

	header = _xbe_header_parse(data)
	sections = _xbe_sections_parse(data, header)
	return ParsedXbe(header=header, sections=sections, data=data)


def xbe_section_find(parsed: ParsedXbe, name: str) -> XbeSection | None:
	for section in parsed.sections:
		if section.name == name:
			return section
	return None


def xbe_section_read(parsed: ParsedXbe, section: XbeSection) -> bytes:
	start = section.raw_address
	end = start + section.raw_size
	if end > len(parsed.data):
		raise XbeFormatError(
			f"section {section.name!r} truncated "
			f"(needs bytes [{start:#x}..{end:#x}], file is {len(parsed.data):#x} bytes)"
		)
	return parsed.data[start:end]


def xbe_section_containing_va(parsed: ParsedXbe, virtual_address: int) -> XbeSection | None:
	for section in parsed.sections:
		start = section.virtual_address
		if start <= virtual_address < start + section.virtual_size:
			return section
	return None


def xbe_function_carve(parsed: ParsedXbe, virtual_address: int, size: int) -> bytes:
	if size <= 0:
		raise ValueError(f"size must be positive, got {size}")

	section = xbe_section_containing_va(parsed, virtual_address)
	if section is None:
		raise XbeFormatError(f"no section contains virtual address {virtual_address:#x}")
	if not section.is_executable:
		raise XbeFormatError(
			f"section {section.name!r} containing {virtual_address:#x} is not executable "
			f"(flags={section.flags:#x})"
		)

	# virtual_size can exceed raw_size (BSS zero-fill tail); carving past raw bytes
	# reads non-code zeros.
	offset = virtual_address - section.virtual_address
	if offset + size > section.raw_size:
		raise XbeFormatError(
			f"function at {virtual_address:#x} (size {size}) extends past raw bytes of "
			f"section {section.name!r} (raw_size={section.raw_size})"
		)

	file_start = section.raw_address + offset
	return parsed.data[file_start : file_start + size]


@lru_cache(maxsize=128)
def _build_flavor_detect(base: int, end: int, encoded: int) -> XbeBuildFlavor:
	"""Keyed on the three header ints the flavor depends on (not the multi-MB
	image) so detection is memoized across the entry-point and kernel-thunk
	getters rather than rescanning the flavor table for each."""
	for flavor in XBE_BUILD_FLAVORS:
		if base <= encoded ^ flavor.ep_key < end:
			return flavor
	raise XbeFormatError(
		f"entry point {encoded:#x} does not decode to a VA inside "
		f"[{base:#x}..{end:#x}) with any known build flavor"
	)


def xbe_build_flavor_detect(parsed: ParsedXbe) -> XbeBuildFlavor:
	header = parsed.header
	return _build_flavor_detect(
		header.base_address, header.base_address + header.size_of_image, header.entry_point_xor
	)


def xbe_entry_point_get(parsed: ParsedXbe) -> int:
	return parsed.header.entry_point_xor ^ xbe_build_flavor_detect(parsed).ep_key


def xbe_kernel_thunk_address_get(parsed: ParsedXbe) -> int:
	return parsed.header.kernel_thunk_address_xor ^ xbe_build_flavor_detect(parsed).kt_key


def xbe_load(path: Path | str) -> ParsedXbe:
	return xbe_parse(Path(path).read_bytes())


# Function enumeration ──────────────────────────────────────────────────────
# MSVC inter-function alignment padding; a `ret` followed by one marks a boundary.
FUNCTION_PADDING_BYTES = frozenset({0xCC, 0x90})

# Past this, capstone is almost certainly scanning into data, not code; under-count instead.
MAX_FUNCTION_SIZE = 16384


@dataclass(frozen=True)
class XbeFunction:
	name: str
	va: int
	size: int


def xbe_functions_enumerate(parsed: ParsedXbe) -> tuple[XbeFunction, ...]:
	"""Linear-sweep every executable section, emitting (name, va, size) per
	detected function. Names follow `fn_VVVVVVVV` (8 hex digits uppercase).

	Two-pass per section. First, disassemble the whole section and record every
	direct `call` target that lands within it; each is a guaranteed function
	start. Second, walk the instruction stream and split functions at three
	signals, so that endings other than `ret` (tail-call `jmp`, `noreturn` calls)
	don't merge the following function in. The signals:

	1. a `ret` closes the function iff the byte after it is padding (0xCC/0x90),
	the section ends, the next instruction is a recognized MSVC /O2 prologue, or
	its VA is a call target;
	2. reaching a call-target VA mid-function closes the previous function; a
	directly-called entry cannot lie inside another function;
	3. an `int3` run that leads into a prologue or call-target closes the current
	function (int3 is never intra-function padding under /O2, unlike `nop`).
	"""
	md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
	md.detail = False
	found: list[XbeFunction] = []

	for section in parsed.sections:
		if not section.is_executable:
			continue
		body = xbe_section_read(parsed, section)
		n = section.raw_size
		section_va = section.virtual_address

		instrs = _disassemble_with_resync(md, body, section_va)
		call_targets = _collect_call_targets(instrs, section_va, section_va + n)

		fn_start_off: int | None = None
		for i, (addr, size, mnem, _op) in enumerate(instrs):
			offset = addr - section_va
			end_off = offset + size

			# A directly-called entry can't lie inside another function: it closes the previous one.
			if fn_start_off is not None and offset > fn_start_off and addr in call_targets:
				_maybe_emit(found, section_va, fn_start_off, offset)
				fn_start_off = offset

			if fn_start_off is None:
				if mnem in ("int3", "nop"):
					continue
				fn_start_off = offset

			# int3 run closes functions whose body ended in a tail-jmp/noreturn, not a `ret`.
			if (
				mnem == "int3"
				and offset > fn_start_off
				and _int3_run_is_boundary(instrs, i, call_targets)
			):
				_maybe_emit(found, section_va, fn_start_off, offset)
				fn_start_off = None
				continue

			if mnem == "ret" or mnem.startswith("retf"):
				next_va = section_va + end_off
				is_boundary = (
					end_off >= n
					or body[end_off] in FUNCTION_PADDING_BYTES
					or next_va in call_targets
					or _next_instr_is_prologue(instrs, i + 1)
				)
				if is_boundary:
					_maybe_emit(found, section_va, fn_start_off, end_off)
					fn_start_off = None

	return tuple(found)


def _maybe_emit(found: list[XbeFunction], section_va: int, start_off: int, end_off: int) -> None:
	fn_size = end_off - start_off
	if 1 <= fn_size <= MAX_FUNCTION_SIZE:
		fn_va = section_va + start_off
		found.append(XbeFunction(name=f"fn_{fn_va:08X}", va=fn_va, size=fn_size))


def _collect_call_targets(
	instrs: list[tuple[int, int, str, str]],
	section_va: int,
	section_end_va: int,
) -> set[int]:
	"""VAs of direct `call <imm>` targets that land inside [section_va, section_end_va)."""
	targets: set[int] = set()
	for _, _, mnem, op in instrs:
		if mnem != "call" or not op.startswith("0x"):
			continue
		try:
			tgt = int(op, 16)
		except ValueError:
			continue
		if section_va <= tgt < section_end_va:
			targets.add(tgt)
	return targets


_PUSH_PROLOGUE_REGS = frozenset({"ebp", "esi", "edi", "ebx"})


def _looks_like_prologue(mnem: str, op: str) -> bool:
	"""Is this single instruction a recognized MSVC /O2 function prologue?"""
	if mnem == "push" and op in _PUSH_PROLOGUE_REGS:
		return True
	if mnem == "sub" and op.startswith("esp,"):
		return True
	if mnem == "mov" and op == "edi, edi":
		return True
	return mnem == "enter"


def _next_instr_is_prologue(instrs: list[tuple[int, int, str, str]], idx: int) -> bool:
	"""Does the next non-padding instruction at/after `idx` look like a prologue?"""
	while idx < len(instrs):
		_, _, mnem, op = instrs[idx]
		if mnem in ("int3", "nop"):
			idx += 1
			continue
		return _looks_like_prologue(mnem, op)
	return False


def _int3_run_is_boundary(
	instrs: list[tuple[int, int, str, str]], idx: int, call_targets: set[int]
) -> bool:
	"""True if the `int3` run at `idx` marks a function boundary.

	This is what lets an `int3` run close a function whose body ended in a
	tail-call `jmp` or a `noreturn` call rather than a `ret`. A run of two or more
	int3 is reliable inter-function padding (you never `__debugbreak` twice, and
	intra-function alignment uses `nop`). A lone int3 is ambiguous, so it counts
	only when the following non-padding instruction is itself a new-function
	start; a directly-called entry or a recognized prologue; or the section ends.
	"""
	run = 0
	j = idx
	while j < len(instrs) and instrs[j][2] == "int3":
		run += 1
		j += 1
	if run >= 2:
		return True

	while j < len(instrs) and instrs[j][2] in ("int3", "nop"):
		j += 1
	if j >= len(instrs):
		return True
	addr, _size, mnem, op = instrs[j]
	return addr in call_targets or _looks_like_prologue(mnem, op)


def _disassemble_with_resync(
	md: capstone.Cs, body: bytes, base_va: int
) -> list[tuple[int, int, str, str]]:
	"""Linear disasm of `body`, advancing 1 byte past any capstone desync."""
	n = len(body)
	instrs: list[tuple[int, int, str, str]] = []
	offset = 0
	while offset < n:
		batch = list(md.disasm_lite(body[offset:], base_va + offset))
		if not batch:
			offset += 1
			continue
		instrs.extend(batch)
		last_addr, last_size, _, _ = batch[-1]
		offset = (last_addr + last_size) - base_va
		if offset < n:
			offset += 1
	return instrs


def _xbe_header_parse(data: bytes) -> XbeHeader:
	base_address = struct.unpack_from("<I", data, 0x104)[0]
	size_of_headers = struct.unpack_from("<I", data, 0x108)[0]
	size_of_image = struct.unpack_from("<I", data, 0x10C)[0]
	size_of_image_header = struct.unpack_from("<I", data, 0x110)[0]
	section_count = struct.unpack_from("<I", data, 0x11C)[0]
	section_headers_address = struct.unpack_from("<I", data, 0x120)[0]
	entry_point_xor = struct.unpack_from("<I", data, 0x128)[0]
	kernel_thunk_address_xor = struct.unpack_from("<I", data, 0x158)[0]

	return XbeHeader(
		base_address=base_address,
		size_of_headers=size_of_headers,
		size_of_image=size_of_image,
		size_of_image_header=size_of_image_header,
		section_count=section_count,
		section_headers_address=section_headers_address,
		entry_point_xor=entry_point_xor,
		kernel_thunk_address_xor=kernel_thunk_address_xor,
	)


def _xbe_sections_parse(data: bytes, header: XbeHeader) -> tuple[XbeSection, ...]:
	if header.section_count == 0:
		return ()

	table_offset = header.section_headers_address - header.base_address
	table_end = table_offset + SECTION_HEADER_SIZE * header.section_count
	if table_end > len(data):
		raise XbeFormatError(
			f"section table truncated "
			f"(needs bytes [{table_offset:#x}..{table_end:#x}], file is {len(data):#x} bytes)"
		)

	sections = []
	for i in range(header.section_count):
		entry_offset = table_offset + SECTION_HEADER_SIZE * i
		flags = struct.unpack_from("<I", data, entry_offset + 0x00)[0]
		virtual_address = struct.unpack_from("<I", data, entry_offset + 0x04)[0]
		virtual_size = struct.unpack_from("<I", data, entry_offset + 0x08)[0]
		raw_address = struct.unpack_from("<I", data, entry_offset + 0x0C)[0]
		raw_size = struct.unpack_from("<I", data, entry_offset + 0x10)[0]
		section_name_address = struct.unpack_from("<I", data, entry_offset + 0x14)[0]

		name = _xbe_section_name_read(data, header, section_name_address)
		sections.append(
			XbeSection(
				name=name,
				flags=flags,
				virtual_address=virtual_address,
				virtual_size=virtual_size,
				raw_address=raw_address,
				raw_size=raw_size,
			)
		)

	return tuple(sections)


def _xbe_section_name_read(data: bytes, header: XbeHeader, virtual_address: int) -> str:
	file_offset = virtual_address - header.base_address
	if file_offset < 0 or file_offset >= len(data):
		return ""

	end = data.find(b"\x00", file_offset)
	if end == -1 or end - file_offset > 64:
		return ""

	return data[file_offset:end].decode("ascii", errors="replace")
