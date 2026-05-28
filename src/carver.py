"""End-to-end XBE→target.obj orchestration.

Thin glue that chains the three slices: carve the function bytes, discover
and resolve relocations, synthesize a COFF object. The result is bytes; the
caller decides where it lands (typically `FunctionWorkspace.target_obj`).
"""

from src.coff import coff_object_build
from src.relocs import relocs_resolve
from src.xbe import ParsedXbe, xbe_function_carve


def carver_target_obj_build(
	parsed: ParsedXbe,
	function_virtual_address: int,
	function_size: int,
	function_name: str,
) -> bytes:
	carved = xbe_function_carve(parsed, function_virtual_address, function_size)
	resolved = relocs_resolve(carved, function_virtual_address, parsed)
	return coff_object_build(carved, function_name, relocations=resolved)
