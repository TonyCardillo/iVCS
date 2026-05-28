#!/usr/bin/env python3
"""Enumerate functions in an XBE and emit a project.json manifest.

Usage:
    python scripts/enumerate.py path/to/default.xbe [options]
    python scripts/enumerate.py /tmp/halo2_default.xbe \\
        --name halo2-retail \\
        --workspace-root ./functions \\
        --output halo2.project.json

Prints a one-line summary (function count, total bytes, section breakdown)
to stderr; writes the manifest JSON to --output (default: stdout).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from src.xbe import (  # noqa: E402
	xbe_functions_enumerate,
	xbe_load,
	xbe_section_containing_va,
)


def main() -> int:
	parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
	parser.add_argument("xbe_path", type=Path, help="Path to the .xbe file")
	parser.add_argument(
		"--name",
		default=None,
		help="Project name (default: xbe basename without extension)",
	)
	parser.add_argument(
		"--workspace-root",
		default="./functions",
		help="workspace_root entry for the manifest (default: ./functions)",
	)
	parser.add_argument(
		"--output",
		type=Path,
		default=None,
		help="Write manifest to this path instead of stdout",
	)
	parser.add_argument(
		"--limit",
		type=int,
		default=None,
		help="Only emit the first N functions (useful for sampling)",
	)
	parser.add_argument(
		"--min-size",
		type=int,
		default=1,
		help="Skip functions smaller than this many bytes (default: 1)",
	)
	args = parser.parse_args()

	if not args.xbe_path.is_file():
		print(f"ERROR: {args.xbe_path} not found", file=sys.stderr)
		return 1

	parsed = xbe_load(args.xbe_path)
	functions = xbe_functions_enumerate(parsed)
	if args.min_size > 1:
		functions = tuple(f for f in functions if f.size >= args.min_size)

	section_counts: Counter[str] = Counter()
	section_bytes: Counter[str] = Counter()
	total_bytes = 0
	for fn in functions:
		section = xbe_section_containing_va(parsed, fn.va)
		section_name = section.name if section else "?"
		section_counts[section_name] += 1
		section_bytes[section_name] += fn.size
		total_bytes += fn.size

	sizes = sorted(f.size for f in functions)
	print(
		f"enumerated {len(functions)} functions, {total_bytes:,} bytes "
		f"(min={sizes[0] if sizes else 0}, "
		f"median={sizes[len(sizes) // 2] if sizes else 0}, "
		f"max={sizes[-1] if sizes else 0})",
		file=sys.stderr,
	)
	for section_name in section_counts:
		print(
			f"  {section_name:<12} {section_counts[section_name]:>6} fns  "
			f"{section_bytes[section_name]:>12,} bytes",
			file=sys.stderr,
		)

	if args.limit is not None:
		functions = functions[: args.limit]
		print(f"  (limited to first {args.limit})", file=sys.stderr)

	project_name = args.name or args.xbe_path.stem
	manifest = {
		"name": project_name,
		"xbe_path": str(args.xbe_path.resolve()),
		"workspace_root": args.workspace_root,
		"functions": [
			{"name": fn.name, "va": f"0x{fn.va:08X}", "size": fn.size} for fn in functions
		],
	}
	serialized = json.dumps(manifest, indent=2) + "\n"

	if args.output is None:
		sys.stdout.write(serialized)
	else:
		args.output.write_text(serialized)
		print(f"wrote {args.output}", file=sys.stderr)

	return 0


if __name__ == "__main__":
	raise SystemExit(main())
