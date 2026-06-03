"""`cluster` / `similar` subcommands: a coddog-style structural index over x86.

`cluster` groups functions that share a hash — one decompilation can cover a
whole cluster. `similar` ranks the functions most structurally similar to a
given one (few-shot retrieval for the agent loop). No LLM/embedding required;
the index logic lives in src.analysis.fingerprint.
"""

from __future__ import annotations

import sys
from pathlib import Path

from src.analysis.fingerprint import (
	fingerprint_clusters,
	fingerprints_similar_to,
	project_fingerprints,
)
from src.cli._common import project_xbe_load


def add_parser(subparsers) -> None:
	cluster = subparsers.add_parser("cluster", help="Group functions sharing a structural hash")
	cluster.add_argument("project", type=Path, help="Path to project.json")
	cluster.add_argument(
		"--by", choices=("exact", "opcode", "equiv"), default="opcode", help="Cluster key"
	)
	cluster.add_argument("--min-size", type=int, default=2, help="Smallest cluster to report")
	cluster.add_argument("--top", type=int, default=25, help="How many rows to print")
	cluster.set_defaults(func=_run_cluster)

	similar = subparsers.add_parser("similar", help="Rank functions similar to a given one")
	similar.add_argument("project", type=Path, help="Path to project.json")
	similar.add_argument("--function", default=None, help="Query function (required)")
	similar.add_argument("--threshold", type=float, default=0.5, help="Min similarity to report")
	similar.add_argument("--top", type=int, default=25, help="How many rows to print")
	similar.set_defaults(func=_run_similar)


def _run_cluster(args) -> int:
	loaded = project_xbe_load(args.project)
	if loaded is None:
		return 1
	project, parsed = loaded
	return _cluster(project, parsed, by=args.by, min_size=args.min_size, top=args.top)


def _run_similar(args) -> int:
	if args.function is None:
		print("ERROR: `similar` requires --function NAME", file=sys.stderr)
		return 1
	loaded = project_xbe_load(args.project)
	if loaded is None:
		return 1
	project, parsed = loaded
	return _similar(project, parsed, function=args.function, threshold=args.threshold, top=args.top)


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
