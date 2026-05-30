"""Place one compiled function's bytes at a virtual address — a one-function linker.

Reads a parsed compiled object (`coff_read`), resolves each relocation's target
symbol to a virtual address, and patches the field so the bytes are correct *at
the VA the function actually occupies in the image*. This is what lets the
whole-image splice verifier byte-compare compiled output against the original:
the per-function objdiff is relocation-aware and masks these fields, so they are
exactly the bytes that must be reconstructed to catch a wrong target address.

Symbol resolution:
  - A symbol defined in this object (section_number >= 1) sits at
    `placement_va + value` — the function symbol itself and `.text`-relative
    local branches. These are placement-relative and need no external lookup.
  - An external symbol (section_number 0) is handed to the caller's `resolve`,
    which decodes the target VA from the synthesized name (`_fn_<va>`,
    `_data_<va>`, `__imp__<export>`).

Patch math (A = signed addend already in the field, P = placement_va + offset):
  - REL32: field = (S + A) - (P + 4)
  - DIR32: field = (S + A)
"""

import struct
from collections.abc import Callable

from src.coff import IMAGE_REL_I386_DIR32, IMAGE_REL_I386_REL32
from src.coff_read import CoffObject

SymbolVaResolve = Callable[[str], int | None]
"""(symbol_name) -> target virtual address, or None if it cannot be resolved."""


class RelinkError(ValueError):
	pass


def relink_place(obj: CoffObject, placement_va: int, resolve: SymbolVaResolve) -> bytes:
	"""Return the `.text` bytes patched to be correct at `placement_va`."""
	section = obj.text_section()
	if section is None:
		raise RelinkError("object has no .text section")

	buf = bytearray(section.raw)
	for reloc in section.relocations:
		symbol = obj.symbol_at(reloc.symbol_index)
		addend = struct.unpack_from("<i", buf, reloc.offset)[0]

		if symbol.section_number >= 1:
			target = placement_va + symbol.value
		else:
			resolved = resolve(symbol.name)
			if resolved is None:
				raise RelinkError(f"cannot resolve external symbol {symbol.name!r}")
			target = resolved

		if reloc.type == IMAGE_REL_I386_REL32:
			value = (target + addend) - (placement_va + reloc.offset + 4)
		elif reloc.type == IMAGE_REL_I386_DIR32:
			value = target + addend
		else:
			raise RelinkError(f"unsupported relocation type {reloc.type:#x}")

		struct.pack_into("<I", buf, reloc.offset, value & 0xFFFFFFFF)

	return bytes(buf)
