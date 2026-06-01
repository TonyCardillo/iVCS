"""XBE→target.obj: carve bytes, resolve relocations, synthesize a COFF object.

Returns bytes; the caller decides where they land (usually
`FunctionWorkspace.target_obj`).
"""

from src.formats.coff import coff_object_build
from src.formats.relocs import relocs_resolve
from src.formats.xbe import ParsedXbe, xbe_function_carve


def carver_target_obj_build(
	parsed: ParsedXbe,
	function_virtual_address: int,
	function_size: int,
	function_name: str,
) -> bytes:
	carved = xbe_function_carve(parsed, function_virtual_address, function_size)
	resolved = relocs_resolve(carved, function_virtual_address, parsed)
	return coff_object_build(carved, function_name, relocations=resolved)
