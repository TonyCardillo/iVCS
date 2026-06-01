"""Place one compiled function's bytes at a virtual address; a one-function linker.

Patches each relocation field so the bytes are correct at the VA the function
occupies, reconstructing exactly the fields objdiff masks; so the splice
verifier catches a wrong target address.

Symbol resolution: defined symbols (section_number >= 1) sit at
`placement_va + value`; externals (section_number 0) go to the caller's `resolve`,
which decodes the VA from the synthesized name (`_fn_<va>`, `_data_<va>`,
`__imp__<export>`).

Patch math (A = addend in the field, P = placement_va + offset):
  - REL32: field = (S + A) - (P + 4)
  - DIR32: field = (S + A)
"""

import struct
from collections.abc import Callable

from src.formats.coff import IMAGE_REL_I386_DIR32, IMAGE_REL_I386_REL32
from src.formats.coff_read import CoffObject

SymbolVaResolve = Callable[[str], int | None]
"""(symbol_name) -> target virtual address, or None if it cannot be resolved."""


class RelinkError(ValueError):
	pass


_RELOC_FIELD_SIZE = 4  # every REL32/DIR32 field we patch is a 4-byte little-endian word


def relink_place(obj: CoffObject, placement_va: int, resolve: SymbolVaResolve) -> bytes:
	"""Return the `.text` bytes patched to be correct at `placement_va`."""
	section = obj.text_section()
	if section is None:
		raise RelinkError("object has no .text section")

	buf = bytearray(section.raw)
	for reloc in section.relocations:
		if reloc.offset < 0 or reloc.offset + _RELOC_FIELD_SIZE > len(buf):
			raise RelinkError(
				f"relocation field at offset {reloc.offset} runs past .text ({len(buf)} bytes)"
			)
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
