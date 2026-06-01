"""`libmatch` subcommand: identify SDK functions by matching XDK libraries.

Fingerprints every function in the given XDK static libraries and matches the
project's functions against them on relocation-invariant hashes, so the linker's
address patching doesn't matter. Reports how much of the image is recognized SDK
code — named, and excludable from the real decomp target. `--save` writes the
confident matches to sdk.json (consumed by the coverage report and web UI).
"""

from __future__ import annotations

import sys
from pathlib import Path

from src.analysis.fingerprint import project_fingerprints
from src.analysis.libmatch import (
	library_signatures,
	match_fingerprints,
	sdk_manifest_write,
	signature_index,
)
from src.core.project import project_load
from src.formats.xbe import xbe_load


def add_parser(subparsers) -> None:
	parser = subparsers.add_parser("libmatch", help="Name SDK functions via XDK library signatures")
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
	parser.set_defaults(func=_run)


def _run(args) -> int:
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
