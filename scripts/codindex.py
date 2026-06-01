#!/usr/bin/env python3
"""Structural code index over a project: cluster duplicates, find similar functions.

Usage:
    python scripts/codindex.py cluster path/to/project.json [--by exact|opcode|equiv]
                                                            [--min-size N] [--top N]
    python scripts/codindex.py similar path/to/project.json --function NAME
                                                            [--threshold F] [--top N]

A coddog-style index (github.com/ethteck/coddog), ported to x86. `cluster` groups
functions that share a hash — one decompilation can cover a whole cluster.
`similar` ranks the functions most structurally similar to a given one (few-shot
retrieval for the agent loop). No LLM/embedding model required.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from src.analysis.fingerprint import (  # noqa: E402
	fingerprint_clusters,
	fingerprints_similar_to,
	project_fingerprints,
)
from src.core.project import project_load  # noqa: E402
from src.formats.xbe import xbe_load  # noqa: E402


def _cluster(project, parsed, *, by: str, min_size: int, top: int) -> int:
	fps = project_fingerprints(project, parsed)
	clusters = fingerprint_clusters(fps, by=by, min_size=min_size)

	redundant = sum(c.size - 1 for c in clusters)
	pct = (redundant / len(fps) * 100.0) if fps else 0.0
	print(
		f"{project.name}: {len(fps):,} functions, {len(clusters):,} {by}-clusters "
		f"(≥{min_size}); {redundant:,} redundant ({pct:.1f}%) — covered by one match each"
	)
	for c in clusters[:top]:
		example = c.members[0]
		print(
			f"  x{c.size:<4} {example.name} @ {example.va:#010x}  "
			f"({example.size} B)  +{c.size - 1} more"
		)
	return 0


def _similar(project, parsed, *, function: str, threshold: float, top: int) -> int:
	fps = project_fingerprints(project, parsed)
	query = next((fp for fp in fps if fp.name == function), None)
	if query is None:
		print(f"ERROR: no function named {function!r} in project", file=sys.stderr)
		return 1

	ranked = fingerprints_similar_to(query, fps, threshold=threshold, top_k=top)
	print(f"{function} @ {query.va:#010x} ({query.size} B): {len(ranked)} similar ≥{threshold:.2f}")
	for fp, score in ranked:
		print(f"  {score * 100:6.2f}%  {fp.name} @ {fp.va:#010x}  ({fp.size} B)")
	return 0


def main() -> int:
	parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
	parser.add_argument("command", choices=("cluster", "similar"))
	parser.add_argument("project", type=Path, help="Path to project.json")
	parser.add_argument(
		"--by", choices=("exact", "opcode", "equiv"), default="opcode", help="Cluster key"
	)
	parser.add_argument("--min-size", type=int, default=2, help="Smallest cluster to report")
	parser.add_argument("--function", default=None, help="Query function for `similar`")
	parser.add_argument("--threshold", type=float, default=0.5, help="Min similarity for `similar`")
	parser.add_argument("--top", type=int, default=25, help="How many rows to print")
	args = parser.parse_args()

	if not args.project.is_file():
		print(f"ERROR: {args.project} not found", file=sys.stderr)
		return 1

	project = project_load(args.project)
	parsed = xbe_load(project.xbe_path)

	if args.command == "cluster":
		return _cluster(project, parsed, by=args.by, min_size=args.min_size, top=args.top)
	if args.function is None:
		print("ERROR: `similar` requires --function NAME", file=sys.stderr)
		return 1
	return _similar(
		project, parsed, function=args.function, threshold=args.threshold, top=args.top
	)


if __name__ == "__main__":
	raise SystemExit(main())
