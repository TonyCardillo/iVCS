#!/usr/bin/env python3
"""Integrate matched functions into the project source tree, and report coverage.

Usage:
    python scripts/integrate.py report path/to/project.json
    python scripts/integrate.py commit path/to/project.json [--function NAME]
                                                             [--force] [--no-compile]

`report` prints per-segment matched / committed coverage (the splat-style
progress view). `commit` promotes matched functions' best.c into
<src_root>/<section>/<name>.c — all matched functions, or one named via
--function (with --force to commit a partial).
"""

from __future__ import annotations

import argparse
import sys
import types
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from src.integrator import (  # noqa: E402
	integrate_commit,
	project_coverage,
)
from src.project import function_status, project_load  # noqa: E402
from src.xbe import xbe_load  # noqa: E402


def _report(project, parsed) -> int:
	coverage = project_coverage(project, parsed)
	matched = sum(c.matched_bytes for c in coverage)
	total = sum(c.function_bytes for c in coverage)
	committed = sum(c.committed for c in coverage)
	fns = sum(len(c.segment.functions) for c in coverage)
	pct = (matched / total * 100.0) if total else 0.0
	print(
		f"{project.name}: {matched:,}/{total:,} matched bytes ({pct:.1f}%), "
		f"{committed}/{fns} functions committed"
	)
	for c in coverage:
		warn = f"  !! {len(c.overlaps)} overlap(s)" if c.overlaps else ""
		print(
			f"  {c.segment.section:<12} {c.matched_percent:5.1f}%  "
			f"{c.matched_bytes:>10,}/{c.function_bytes:<10,} B  "
			f"committed {c.committed:>4}/{len(c.segment.functions):<4}  "
			f"gaps {len(c.gaps)}{warn}"
		)
	return 0


def _commit(project, parsed, *, function: str | None, force: bool, no_compile: bool) -> int:
	compile_fn = (lambda c, o, w: types.SimpleNamespace(success=True)) if no_compile else None
	kwargs = {"force": force}
	if compile_fn is not None:
		kwargs["compile_fn"] = compile_fn

	if function is not None:
		targets = [f for f in project.functions if f.name == function]
		if not targets:
			print(f"ERROR: no function named {function!r} in project", file=sys.stderr)
			return 1
	else:
		targets = [f for f in project.functions if function_status(project, f).state == "matched"]

	committed = skipped = failed = 0
	for fn in targets:
		res = integrate_commit(project, parsed, fn, **kwargs)
		if res.skipped_reason is not None:
			skipped += 1
			print(f"  skip  {fn.name}: {res.skipped_reason}", file=sys.stderr)
		elif not res.compiled and not no_compile:
			failed += 1
			print(f"  WARN  {fn.name}: committed but failed to recompile", file=sys.stderr)
		else:
			committed += 1
	tail = " (compile skipped)" if no_compile else f", {failed} recompile-failed"
	print(f"committed {committed}, skipped {skipped}{tail}", file=sys.stderr)
	return 0


def main() -> int:
	parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
	parser.add_argument("command", choices=("report", "commit"))
	parser.add_argument("project", type=Path, help="Path to project.json")
	parser.add_argument("--function", default=None, help="Commit only this function")
	parser.add_argument("--force", action="store_true", help="Commit even if not matched")
	parser.add_argument(
		"--no-compile", action="store_true", help="Skip the standalone recompile gate"
	)
	args = parser.parse_args()

	if not args.project.is_file():
		print(f"ERROR: {args.project} not found", file=sys.stderr)
		return 1

	project = project_load(args.project)
	parsed = xbe_load(project.xbe_path)

	if args.command == "report":
		return _report(project, parsed)
	return _commit(
		project, parsed, function=args.function, force=args.force, no_compile=args.no_compile
	)


if __name__ == "__main__":
	raise SystemExit(main())
