#!/usr/bin/env python3
"""Identify a project's SDK functions by matching them against the XDK libraries.

Usage:
    python scripts/libmatch.py path/to/project.json LIB.lib [LIB2.lib ...]
                                                            [--min-size N] [--show N]

Fingerprints every function in the given XDK static libraries and matches the
project's functions against them (on relocation-invariant opcode/operand-shape
hashes, so the linker's address patching doesn't matter). Reports how much of the
image is recognized SDK code — named, and excludable from the real decomp target.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from src.fingerprint import project_fingerprints  # noqa: E402
from src.libmatch import (  # noqa: E402
	library_signatures,
	match_fingerprints,
	sdk_manifest_write,
	signature_index,
)
from src.project import project_load  # noqa: E402
from src.xbe import xbe_load  # noqa: E402


def main() -> int:
	parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
	parser.add_argument("project", type=Path, help="Path to project.json")
	parser.add_argument("libs", type=Path, nargs="+", help="XDK .lib archives to match against")
	parser.add_argument("--min-size", type=int, default=16, help="Skip functions below N bytes")
	parser.add_argument("--show", type=int, default=20, help="How many named matches to print")
	parser.add_argument(
		"--save",
		action="store_true",
		help="Write confident matches to sdk.json next to project.json "
		"(consumed by the coverage report and web UI)",
	)
	args = parser.parse_args()

	if not args.project.is_file():
		print(f"ERROR: {args.project} not found", file=sys.stderr)
		return 1

	signatures = []
	for lib in args.libs:
		if not lib.is_file():
			print(f"ERROR: {lib} not found", file=sys.stderr)
			return 1
		sigs = library_signatures(lib.read_bytes())
		signatures.extend(sigs)
		print(f"  {lib.name:<16} {len(sigs):>6,} function signatures", file=sys.stderr)
	index = signature_index(signatures)

	project = project_load(args.project)
	parsed = xbe_load(project.xbe_path)
	fingerprints = project_fingerprints(project, parsed)
	matches = match_fingerprints(fingerprints, index, min_size=args.min_size)

	confident = [m for m in matches if m.is_confident]
	exact = [m for m in confident if m.confidence == "exact"]
	total = len(fingerprints)
	print(
		f"{project.name}: {len(matches):,}/{total:,} functions match the SDK "
		f"({len(confident):,} confidently named, {len(exact):,} exact); "
		f"{len(signatures):,} library signatures from {len(args.libs)} lib(s)"
	)
	for m in confident[: args.show]:
		print(f"  {m.confidence:<8} {m.va:#010x}  {m.size:>5} B  {m.names[0]}")
	ambiguous = len(matches) - len(confident)
	if ambiguous:
		print(f"  ... and {ambiguous:,} ambiguous (skeleton shared by several library functions)")

	if args.save:
		sdk_path = args.project.parent / "sdk.json"
		written = sdk_manifest_write(sdk_path, matches)
		print(f"wrote {written:,} confident SDK identifications to {sdk_path}", file=sys.stderr)
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
