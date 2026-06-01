#!/usr/bin/env python3
"""Integrate matched functions into the project source tree, and report coverage.

Usage:
    python scripts/integrate.py report path/to/project.json
    python scripts/integrate.py commit path/to/project.json [--function NAME]
                                                             [--force] [--no-compile]
    python scripts/integrate.py verify path/to/project.json
    python scripts/integrate.py relink path/to/project.json

`report` prints per-segment matched / committed coverage (the splat-style
progress view). `commit` promotes matched functions' best.c into
<src_root>/<section>/<name>.c — all matched functions, or one named via
--function (with --force to commit a partial). `verify` recompiles each matched
function, relocates it to its real VA with our own relocator, and byte-compares
against the original image. `relink` does the same but drives the real XDK
Link.Exe as an independent oracle. Both report a whole-image verified-matched %
and need Wine + the toolchain.
"""

from __future__ import annotations

import argparse
import sys
import time
import types
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from src.analysis.libmatch import sdk_manifest_load  # noqa: E402
from src.core.project import function_status, project_load  # noqa: E402
from src.formats.xbe import xbe_load  # noqa: E402
from src.verify.integrator import (  # noqa: E402
	image_real_relink_verify,
	image_splice_verify,
	image_verify_cache_write,
	integrate_commit,
	project_coverage,
)


def _sdk_vas_for(project_path: Path) -> frozenset[int]:
	"""Load the SDK manifest sitting next to project.json, if any (see
	scripts/libmatch.py --save). Empty when absent → coverage is unchanged."""
	sdk_path = project_path.parent / "sdk.json"
	return frozenset(sdk_manifest_load(sdk_path)) if sdk_path.is_file() else frozenset()


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


def _verify(project, parsed, project_path: Path) -> int:
	result = image_splice_verify(project, parsed)
	image_verify_cache_write(project_path, result, method="splice", when=time.time())
	return _print_verify(project, result, "splice-verified")


def _relink(project, parsed, project_path: Path) -> int:
	result = image_real_relink_verify(project, parsed)
	image_verify_cache_write(project_path, result, method="relink", when=time.time())
	return _print_verify(project, result, "relink-verified")


def main() -> int:
	parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
	parser.add_argument("command", choices=("report", "commit", "verify", "relink"))
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
		return _report(project, parsed, _sdk_vas_for(args.project))
	if args.command == "verify":
		return _verify(project, parsed, args.project)
	if args.command == "relink":
		return _relink(project, parsed, args.project)
	return _commit(
		project, parsed, function=args.function, force=args.force, no_compile=args.no_compile
	)


if __name__ == "__main__":
	raise SystemExit(main())
