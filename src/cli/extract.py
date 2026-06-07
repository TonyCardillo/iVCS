"""`extract` subcommand: list or pull files out of an Xbox disc image (XISO).

With no `--file`, prints the image's root directory. With `--file NAME`, streams
that file out to `--output` (default: the filename in the current directory) —
the usual job being to recover a project's `default.xbe` from its game disc.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from src.cli._common import path_exists_or_error
from src.formats.xiso import (
	XisoFormatError,
	xiso_image_file_extract,
	xiso_image_root_list,
)


def add_parser(subparsers) -> argparse.ArgumentParser:
	parser = subparsers.add_parser(
		"extract", help="List or extract files from an Xbox disc image (XISO)"
	)
	parser.add_argument("image", type=Path, help="Path to the .iso / .xiso.iso disc image")
	parser.add_argument(
		"--file", default=None, help="Root file to extract (omit to list the image instead)"
	)
	parser.add_argument(
		"--output", "-o", type=Path, default=None, help="Destination path (default: ./<file>)"
	)
	parser.set_defaults(func=_run)
	return parser


def _run(args) -> int:
	if not path_exists_or_error(args.image):
		return 1
	try:
		if args.file is None:
			return _list(args.image)
		return _extract(args.image, args.file, args.output)
	except XisoFormatError as e:
		print(f"ERROR: {e}", file=sys.stderr)
		return 1


def _list(image: Path) -> int:
	entries = sorted(xiso_image_root_list(image), key=lambda e: e.name.lower())
	print(f"{image.name}: {len(entries)} root entries", file=sys.stderr)
	for entry in entries:
		kind = "DIR " if entry.is_directory else "    "
		print(f"  {kind} {entry.size:>12,}  {entry.name}")
	return 0


def _extract(image: Path, name: str, output: Path | None) -> int:
	dest = output if output is not None else Path(name)
	written = xiso_image_file_extract(image, name, dest)
	print(f"wrote {dest} ({written:,} bytes)", file=sys.stderr)
	return 0
