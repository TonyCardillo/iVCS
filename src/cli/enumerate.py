"""`enumerate` subcommand: XBE → project.json manifest.

Prints a one-line summary (function count, total bytes, section breakdown) to
stderr; writes the manifest JSON to --output (default: stdout). The manifest
shape is built by `project_manifest_build`; everything here is presentation.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from src.cli._common import path_exists_or_error
from src.core.project import project_manifest_build
from src.formats.xbe import (
	xbe_functions_enumerate,
	xbe_load,
	xbe_section_containing_va,
)


def add_parser(subparsers) -> argparse.ArgumentParser:
	parser = subparsers.add_parser(
		"enumerate", help="Enumerate an XBE's functions into a project.json manifest"
	)
	parser.add_argument("xbe_path", type=Path, help="Path to the .xbe file")
	parser.add_argument(
		"--name", default=None, help="Project name (default: xbe basename without extension)"
	)
	parser.add_argument(
		"--workspace-root",
		default="./functions",
		help="workspace_root entry for the manifest (default: ./functions)",
	)
	parser.add_argument(
		"--output", "-o", type=Path, default=None, help="Write manifest here instead of stdout"
	)
	parser.add_argument(
		"--limit", type=int, default=None, help="Only emit the first N functions (for sampling)"
	)
	parser.add_argument(
		"--min-size", type=int, default=1, help="Skip functions smaller than N bytes (default: 1)"
	)
	parser.set_defaults(func=_run)
	return parser


def _run(args) -> int:
	if not path_exists_or_error(args.xbe_path):
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

	manifest = project_manifest_build(
		parsed,
		name=args.name or args.xbe_path.stem,
		xbe_path=args.xbe_path,
		workspace_root=args.workspace_root,
		functions=functions,
	)
	serialized = json.dumps(manifest, indent=2) + "\n"

	if args.output is None:
		sys.stdout.write(serialized)
	else:
		args.output.write_text(serialized)
		print(f"wrote {args.output}", file=sys.stderr)

	return 0
