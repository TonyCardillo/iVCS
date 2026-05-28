#!/usr/bin/env python3
"""End-to-end sanity check of the XBE carver against a real Halo 2 default.xbe.

Exercises xbe_parse + xbe_entry_point_get + xbe_kernel_thunk_address_get +
relocs_discover/resolve + coff_object_build on real bytes. Not a unit test
— emits human-readable diagnostics so we can eyeball whether the API holds
up on a 4.6 MB game binary, and round-trips the synthesized target.obj
through objdiff-cli.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from src.coff import coff_object_build  # noqa: E402
from src.relocs import relocs_resolve  # noqa: E402
from src.xbe import (  # noqa: E402
	xbe_build_flavor_detect,
	xbe_entry_point_get,
	xbe_function_carve,
	xbe_kernel_thunk_address_get,
	xbe_load,
	xbe_section_containing_va,
)

OBJDIFF_CLI = REPO_ROOT / "recon/objdiff-smoke/objdiff-cli"

XBE_PATH = Path("/tmp/halo2_default.xbe")
THUNK_PEEK_COUNT = 12
ENTRY_CARVE_SIZE = 128


def main() -> int:
	parsed = xbe_load(XBE_PATH)
	h = parsed.header

	print(f"=== XBE file: {XBE_PATH} ({XBE_PATH.stat().st_size} bytes) ===")
	print(f"base_address       = {h.base_address:#010x}")
	print(f"size_of_image      = {h.size_of_image:#010x}")
	print(f"size_of_headers    = {h.size_of_headers:#010x}")
	print(f"section_count      = {h.section_count}")
	print(f"section_headers_va = {h.section_headers_address:#010x}")
	print()

	print("=== Sections ===")
	for s in parsed.sections:
		flags = []
		if s.is_executable:
			flags.append("X")
		if s.is_writable:
			flags.append("W")
		print(
			f"  {s.name:<12} va={s.virtual_address:#010x} "
			f"vsize={s.virtual_size:#010x} raw={s.raw_address:#010x} "
			f"rsize={s.raw_size:#010x} [{','.join(flags) or '-'}]"
		)
	print()

	flavor = xbe_build_flavor_detect(parsed)
	entry_va = xbe_entry_point_get(parsed)
	thunk_va = xbe_kernel_thunk_address_get(parsed)
	print(f"=== XOR-decoded addresses (build flavor: {flavor.name}) ===")
	print(f"  ep_key            = {flavor.ep_key:#010x}")
	print(f"  kt_key            = {flavor.kt_key:#010x}")
	print(f"  entry_point       = {entry_va:#010x}")
	print(f"  kernel_thunk_addr = {thunk_va:#010x}")
	print()

	print(f"=== First {THUNK_PEEK_COUNT} kernel thunk slots ===")
	thunk_section = xbe_section_containing_va(parsed, thunk_va)
	if thunk_section is None:
		print(f"  ERROR: thunk VA {thunk_va:#010x} not in any section")
	else:
		print(f"  thunk section: {thunk_section.name}")
		_thunk_table_print(parsed, thunk_va, THUNK_PEEK_COUNT)
	print()

	print(f"=== Carving {ENTRY_CARVE_SIZE} bytes at entry point {entry_va:#010x} ===")
	carved = xbe_function_carve(parsed, entry_va, ENTRY_CARVE_SIZE)
	print(f"  carved {len(carved)} bytes, first 16: {carved[:16].hex()}")
	print()

	print("=== Resolved relocations in entry-point region ===")
	resolved = relocs_resolve(carved, entry_va, parsed)
	if not resolved:
		print("  (none — entry-point region has no REL32 externals in first 128 bytes)")
	for r in resolved:
		print(
			f"  +{r.site.imm_offset:#06x} {r.site.kind.value} → "
			f"{r.site.target_va:#010x}  {r.symbol_name}"
		)
	print()

	print(f"=== Building target.obj for entry-point function (size={ENTRY_CARVE_SIZE}) ===")
	obj_bytes = coff_object_build(carved, "_entry_point", relocations=resolved)
	print(f"  synthesized {len(obj_bytes)}-byte COFF object")

	if OBJDIFF_CLI.is_file():
		with tempfile.TemporaryDirectory() as td:
			target = Path(td) / "target.obj"
			target.write_bytes(obj_bytes)
			cmd = [
				str(OBJDIFF_CLI),
				"diff",
				"-1",
				str(target),
				"-2",
				str(target),
				"--format",
				"json",
				"-o",
				"-",
			]
			result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
			if result.returncode != 0:
				print(f"  objdiff-cli FAILED rc={result.returncode}: {result.stderr.strip()}")
			else:
				objdiff_doc = json.loads(result.stdout)
				fn_names = [
					s["name"]
					for s in objdiff_doc.get("left", {}).get("symbols", [])
					if s.get("kind") == "SYMBOL_FUNCTION"
				]
				print(f"  objdiff parsed OK; function symbols on left side: {fn_names}")
				assert "_entry_point" in fn_names, "synthesized .obj missing function symbol"
	else:
		print(f"  (skipped objdiff round-trip — CLI not at {OBJDIFF_CLI})")
	print()

	print("=== Scanning .text for an FF 15 site that hits the kernel thunk table ===")
	text_section = next((s for s in parsed.sections if s.name == ".text"), None)
	if text_section is None:
		print("  no .text section?!")
	else:
		site = _find_first_ff15_into_thunk_table(parsed, text_section, thunk_va)
		if site is None:
			print("  none found in .text (unexpected for a kernel-using game)")
		else:
			call_va, thunk_slot_va, ordinal, name = site
			print(f"  found call at va={call_va:#010x} → thunk slot {thunk_slot_va:#010x}")
			print(f"  ordinal {ordinal} = {name}")
			CARVE = 32
			carve_start = call_va & ~0xF
			carved2 = xbe_function_carve(parsed, carve_start, CARVE)
			resolved2 = relocs_resolve(carved2, carve_start, parsed)
			print(f"  resolved relocations in this {CARVE}-byte window:")
			for r in resolved2:
				print(
					f"    +{r.site.imm_offset:#06x} {r.site.kind.value} → "
					f"{r.site.target_va:#010x}  {r.symbol_name}"
				)
			assert any(r.symbol_name.startswith("__imp__") for r in resolved2), (
				"expected an __imp__ symbol in the resolved set"
			)
	print()

	print(
		f"=== Summary === entry resolved={len(resolved)} sites, "
		f"target.obj built ({len(obj_bytes)} bytes)"
	)
	return 0


def _find_first_ff15_into_thunk_table(parsed, text_section, thunk_va: int):
	import struct as _struct

	from src.xboxkrnl import xboxkrnl_name_get

	text_bytes = parsed.data[
		text_section.raw_address : text_section.raw_address + text_section.raw_size
	]
	base_va = text_section.virtual_address
	thunk_end = thunk_va + 4096  # generous upper bound for the table
	i = 0
	while i < len(text_bytes) - 6:
		if text_bytes[i] == 0xFF and text_bytes[i + 1] == 0x15:
			disp = _struct.unpack_from("<I", text_bytes, i + 2)[0]
			if thunk_va <= disp < thunk_end and (disp - thunk_va) % 4 == 0:
				call_va = base_va + i
				slot_off = text_section.raw_address  # unused; need the .rdata raw addr
				# Read the ordinal from the .rdata thunk slot
				rdata_sec = xbe_section_containing_va(parsed, disp)
				file_off = rdata_sec.raw_address + (disp - rdata_sec.virtual_address)
				raw = _struct.unpack_from("<I", parsed.data, file_off)[0]
				if raw == 0:
					i += 1
					continue
				ordinal = raw & 0x7FFFFFFF
				name = xboxkrnl_name_get(ordinal) or "(unknown)"
				return call_va, disp, ordinal, name
		i += 1
	return None


def _thunk_table_print(parsed, thunk_va: int, max_slots: int) -> None:
	import struct

	from src.xboxkrnl import xboxkrnl_name_get

	section = xbe_section_containing_va(parsed, thunk_va)
	file_offset = section.raw_address + (thunk_va - section.virtual_address)
	for i in range(max_slots):
		slot_va = thunk_va + i * 4
		slot_off = file_offset + i * 4
		if slot_off + 4 > len(parsed.data):
			print(f"  [{i:2d}] {slot_va:#010x}  <out of file>")
			break
		raw = struct.unpack_from("<I", parsed.data, slot_off)[0]
		if raw == 0:
			print(f"  [{i:2d}] {slot_va:#010x}  0x00000000  <terminator>")
			break
		ordinal = raw & 0x7FFFFFFF
		name = xboxkrnl_name_get(ordinal) or "(unknown)"
		flag = "ORD" if raw & 0x80000000 else "RVA"
		print(f"  [{i:2d}] {slot_va:#010x}  {raw:#010x}  {flag} ord={ordinal:>3}  {name}")


if __name__ == "__main__":
	raise SystemExit(main())
