"""`report` / `commit` / `verify` subcommands.

`report` prints per-segment matched / committed coverage. `commit` promotes
matched functions' best.c into <src_root>/<section>/<name>.c. `verify` recompiles
each matched function, relocates it with our own relocator, and byte-compares
against the original image (needs Wine + the toolchain). The verbs live in
src.verify (commit / coverage / splice_verify); this module is argument plumbing
+ printing.
"""

from __future__ import annotations

import sys
import tempfile
import time
import types
from pathlib import Path

from src.cli._common import project_xbe_load
from src.core.project import function_status, project_sdk_vas
from src.verify.commit import integrate_commit
from src.verify.coverage import project_coverage
from src.verify.splice_verify import image_splice_verify, image_verify_cache_write


def add_parser(subparsers) -> None:
	report = subparsers.add_parser("report", help="Per-segment matched/committed coverage")
	report.add_argument("project", type=Path, help="Path to project.json")
	report.set_defaults(func=_run_report)

	commit = subparsers.add_parser("commit", help="Promote matched best.c into the source tree")
	commit.add_argument("project", type=Path, help="Path to project.json")
	commit.add_argument("--function", default=None, help="Commit only this function")
	commit.add_argument("--force", action="store_true", help="Commit even if not matched")
	commit.add_argument("--no-compile", action="store_true", help="Skip the standalone recompile")
	commit.set_defaults(func=_run_commit)

	verify = subparsers.add_parser("verify", help="Byte-splice verify matched functions")
	verify.add_argument("project", type=Path, help="Path to project.json")
	verify.set_defaults(func=_run_verify)


def _run_report(args) -> int:
	loaded = project_xbe_load(args.project)
	if loaded is None:
		return 1
	project, parsed = loaded
	return _report(project, parsed, project_sdk_vas(args.project))


def _run_commit(args) -> int:
	loaded = project_xbe_load(args.project)
	if loaded is None:
		return 1
	project, parsed = loaded
	return _commit(
		project, parsed, function=args.function, force=args.force, no_compile=args.no_compile
	)


def _run_verify(args) -> int:
	loaded = project_xbe_load(args.project)
	if loaded is None:
		return 1
	project, parsed = loaded
	result = image_splice_verify(project, parsed)
	image_verify_cache_write(args.project, result, when=time.time())
	return _print_verify(project, result, "splice-verified")


def _report(project, parsed, sdk_vas: frozenset[int]) -> int:
	coverage = project_coverage(project, parsed, sdk_vas=sdk_vas)
	matched = sum(c.matched_bytes for c in coverage)
	game = sum(c.game_bytes for c in coverage)
	sdk_bytes = sum(c.sdk_bytes for c in coverage)
	sdk_count = sum(c.sdk_count for c in coverage)
	committed = sum(c.committed for c in coverage)
	pct = (matched / game * 100.0) if game else 0.0
	print(
		f"{project.name}: {matched:,}/{game:,} game bytes matched ({pct:.1f}%), "
		f"{committed} committed"
	)
	if sdk_vas:
		print(
			f"  SDK identified: {sdk_count:,} functions / {sdk_bytes:,} bytes "
			f"(linked from the XDK, excluded from the target)"
		)
	for c in coverage:
		warn = f"  !! {len(c.overlaps)} overlap(s)" if c.overlaps else ""
		sdk = f"  sdk {c.sdk_count}" if c.sdk_count else ""
		print(
			f"  {c.segment.section:<12} {c.matched_percent:5.1f}%  "
			f"{c.matched_bytes:>10,}/{c.game_bytes:<10,} B  "
			f"committed {c.committed:>4}/{len(c.segment.functions):<4}  "
			f"gaps {len(c.gaps)}{sdk}{warn}"
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
	with tempfile.TemporaryDirectory() as build_dir:
		for fn in targets:
			res = integrate_commit(project, parsed, fn, build_dir=Path(build_dir), **kwargs)
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


def _print_verify(project, result, kind: str) -> int:
	pct = result.verified_percent
	print(
		f"{project.name}: {result.verified_bytes:,}/{result.matched_bytes:,} "
		f"matched bytes {kind} against the original image ({pct:.1f}%)"
	)
	for fv in result.functions:
		mark = "ok  " if fv.is_verified else "FAIL"
		detail = "" if fv.reason is None else f"  ({fv.reason})"
		print(f"  {mark} {fv.name} @ {fv.va:#010x}  {fv.size:>6,} B{detail}")
	return 0
