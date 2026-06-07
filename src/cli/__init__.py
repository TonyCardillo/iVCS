"""Unified command-line frontend: `python -m src <command>`.

The real verbs live in the library packages (core/formats/decomp/verify/
analysis/drivers); each module here is a thin frontend that parses args, calls
one feature, and prints. Subcommands register themselves via `add_parser`, so
adding a command is local to its module.

    python -m src extract    "Halo 2.xiso.iso" --file default.xbe -o game.xbe
    python -m src enumerate game.xbe --name halo2 -o projects/halo2/project.json
    python -m src report    projects/halo2/project.json
    python -m src commit    projects/halo2/project.json [--function NAME]
    python -m src verify     projects/halo2/project.json
    python -m src cluster    projects/halo2/project.json [--by exact|opcode|equiv]
    python -m src similar    projects/halo2/project.json --function NAME
    python -m src libmatch   projects/halo2/project.json LIB.lib [LIB2.lib ...]
    python -m src batch       projects/halo2/project.json [--dry-run]
"""

from __future__ import annotations

import argparse

from src.cli import batch, extract, index, integrate, libmatch
from src.cli import enumerate as enumerate_cmd


def build_parser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(prog="python -m src", description=__doc__.splitlines()[0])
	subparsers = parser.add_subparsers(dest="command", required=True)
	for module in (extract, enumerate_cmd, integrate, index, libmatch, batch):
		module.add_parser(subparsers)
	return parser


def main(argv: list[str] | None = None) -> int:
	args = build_parser().parse_args(argv)
	return args.func(args)
