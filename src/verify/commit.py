"""Commit a matched function's `best.c` into a buildable, segment-organized
source tree.

The matching loop leaves a `best.c` in each scratch workspace; this promotes the
matched ones into `<src_root>/<section>/<name>.c`, factoring the typedef preamble
every function shares into one `include/ivcs_common.h`, and recompiles each to
confirm it still builds outside its workspace.
"""

import tempfile
from dataclasses import dataclass
from pathlib import Path

from src.core.project import FunctionEntry, Project, function_status
from src.core.workspace import FunctionWorkspace
from src.decomp.compile_tool import CompileFn, default_compile_fn
from src.formats.xbe import ParsedXbe
from src.verify.segments import function_source_path

_COMMON_HEADER_DIR = "include"
_COMMON_HEADER_NAME = "ivcs_common.h"


def _split_ctx_preamble(ctx_text: str) -> tuple[str, str]:
	"""Split a workspace ctx.h into (shared preamble, per-function tail).

	The preamble is the leading run of scalar `typedef ...;` lines the launcher
	emits identically for every function (BYTE, ULONG, HANDLE, ...). Everything
	from the first section comment on (the `/* Target */`, `/* xboxkrnl imports */`,
	`/* Callees */`, `/* Ghidra ... */` blocks) is function-specific. Extracting
	the preamble lets every committed source share one `include/ivcs_common.h`
	instead of carrying its own copy of ~25 identical typedefs.
	"""
	lines = ctx_text.splitlines()
	cut = 0
	for line in lines:
		stripped = line.strip()
		if stripped == "" or (stripped.startswith("typedef ") and stripped.endswith(";")):
			cut += 1
		else:
			break
	return "\n".join(lines[:cut]).strip(), "\n".join(lines[cut:]).strip()


@dataclass(frozen=True)
class CommitResult:
	"""Outcome of committing one function's source into the tree.

	`skipped_reason` is set when nothing was written (not matched, missing
	inputs); otherwise the source was committed and `compiled` reports whether
	it still builds standalone (a False here is a ctx-drift warning, not a skip).
	"""

	path: Path
	compiled: bool
	skipped_reason: str | None


def integrate_commit(
	project: Project,
	parsed: ParsedXbe,
	fn: FunctionEntry,
	*,
	compile_fn: CompileFn = default_compile_fn,
	force: bool = False,
	build_dir: Path | None = None,
) -> CommitResult:
	"""Promote a matched function's `best.c` into the source tree.

	Writes `<name>.c` that includes the shared `include/ivcs_common.h` (the typedef
	preamble every function shares) plus, when the function needs them, a slim
	`<name>.ctx.h` carrying only its own target/kernel/callee/struct decls. Then
	recompiles it to confirm it still builds outside its workspace. Only matched
	functions are committed unless `force=True`. Idempotent — re-committing
	overwrites, and drops a now-unneeded per-function header.

	A function whose typedef preamble diverges from an already-written shared
	header carries its own full ctx instead, so it never clobbers (or breaks)
	sources committed by other functions.
	"""
	dest = function_source_path(project, parsed, fn)
	status = function_status(project, fn)
	if status.state != "matched" and not force:
		return CommitResult(dest, False, f"not matched (state={status.state}); pass force=True")

	workspace = FunctionWorkspace(root=project.workspace_for(fn), function_name=fn.name)
	if not workspace.best_c.is_file():
		return CommitResult(dest, False, "no best.c in workspace")
	if not workspace.ctx_h.is_file():
		return CommitResult(dest, False, "no ctx.h in workspace")

	dest.parent.mkdir(parents=True, exist_ok=True)
	common, tail = _split_ctx_preamble(workspace.ctx_h.read_text())

	# The shared preamble lives once per project; sources include it. But it is one
	# file shared by every committed function, so overwriting it with a different
	# preamble would silently break sources already committed against the old
	# content. The first committer owns it; a function whose preamble diverges
	# self-contains (carries its own full ctx) rather than clobber the shared header.
	common_dir = project.src_root / _COMMON_HEADER_DIR
	common_dir.mkdir(parents=True, exist_ok=True)
	common_path = common_dir / _COMMON_HEADER_NAME
	common_body = f"#pragma once\n\n{common}\n" if common else "#pragma once\n"
	use_shared = not common_path.is_file() or common_path.read_text() == common_body
	if use_shared:
		common_path.write_text(common_body)

	includes: list[str] = []
	ctx_dest = dest.with_name(f"{fn.name}.ctx.h")
	if use_shared:
		includes.append(f'#include "../{_COMMON_HEADER_DIR}/{_COMMON_HEADER_NAME}"')
		per_function_ctx = tail  # shared typedefs come from the common header
	else:
		per_function_ctx = workspace.ctx_h.read_text().strip()  # diverged: full ctx, self-contained

	if per_function_ctx:
		ctx_dest.write_text(per_function_ctx + "\n")
		includes.append(f'#include "{ctx_dest.name}"')
	else:
		ctx_dest.unlink(missing_ok=True)  # idempotent: drop a stale per-fn header
	dest.write_text("\n".join(includes) + f"\n\n{workspace.best_c.read_text()}")

	# A caller committing many functions passes a shared build_dir (outputs are
	# keyed by function name, so they never collide); a lone call gets its own.
	if build_dir is not None:
		compiled = bool(compile_fn(dest, build_dir / f"{fn.name}.obj", dest.parent).success)
	else:
		with tempfile.TemporaryDirectory() as d:
			compiled = bool(compile_fn(dest, Path(d) / f"{fn.name}.obj", dest.parent).success)
	return CommitResult(dest, compiled, None)
