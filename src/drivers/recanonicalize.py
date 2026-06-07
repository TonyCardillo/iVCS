"""One-off repair: re-canonicalize stale cached baseline objects.

A cached `history/0000.obj` can carry a defined-function symbol name that no
longer matches its `target.obj` — most often a stdcall `@N` decoration that
drifted (Ghidra's parameter guess vs the binary's real `ret N`). objdiff pairs
symbols by exact name, so a stale name leaves the baseline unpaired and scored
`None`: a phantom "no-match"/"failed" in a sweep.

`ghidra_only_run` now canonicalizes before every diff, so fresh sweeps are
immune. This pass repairs baselines already on disk WITHOUT re-running Ghidra
or the compiler — it only re-diffs the cached object against `target.obj`, so
previously mis-scored functions flip to their true match% in `result.json`.

The authoritative canonical name is `target.obj`'s defined symbol: that object
is always rebuilt fresh from the binary, so it never carries a stale decoration.
"""

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from src.core.workspace import FunctionWorkspace
from src.decomp.agent_loop import ghidra_only_run
from src.decomp.compile_tool import CompileOutput, DiffFn, default_diff_fn
from src.formats.coff import IMAGE_SYM_CLASS_EXTERNAL, IMAGE_SYM_TYPE_FUNCTION
from src.formats.coff_read import CoffReadError, coff_object_read


@dataclass(frozen=True)
class RecanonOutcome:
	name: str
	old_symbol: str
	new_symbol: str
	match_percent: float | None


@dataclass(frozen=True)
class RecanonSummary:
	scanned: int
	repaired: int
	outcomes: tuple[RecanonOutcome, ...]


def _compile_must_not_run(_c: Path, _o: Path, _r: Path) -> CompileOutput:
	"""A cached 0000.obj must already exist, so the baseline compile is skipped.
	Reaching here means the precondition (cached obj present) was violated."""
	raise AssertionError("baseline recompile attempted during recanonicalize repair")


def coff_defined_function_symbol(obj: bytes) -> str | None:
	"""The lone EXTERNAL, section-defined, function-typed symbol name; else None.

	Returns None when the object is unreadable or the defined function can't be
	uniquely identified (zero or several candidates) — the same uniqueness rule
	`coff_defined_function_rename` uses, so a name we can't pin we also don't act
	on."""
	try:
		co = coff_object_read(obj)
	except CoffReadError:
		return None
	names = [
		s.name
		for s in co.symbols
		if s.storage_class == IMAGE_SYM_CLASS_EXTERNAL
		and s.section_number > 0
		and s.type == IMAGE_SYM_TYPE_FUNCTION
	]
	return names[0] if len(names) == 1 else None


def baseline_recanonicalize_one(
	root: Path, *, diff_fn: DiffFn = default_diff_fn
) -> RecanonOutcome | None:
	"""Repair one workspace's cached baseline, or return None if nothing to do.

	A no-op (returns None) unless a cached baseline (`target.obj`, `history/
	0000.c`, `history/0000.obj`) exists, both objects expose a uniquely-named
	defined function, and those names disagree. When they disagree, re-runs the
	ghidra-only baseline (compile is skipped — the obj is cached — so it only
	canonicalizes the symbol and re-diffs), refreshing `result.json` with the
	now-paired match%."""
	target_obj = root / "target.obj"
	paths_c = root / "history" / "0000.c"
	obj = root / "history" / "0000.obj"
	if not (target_obj.is_file() and paths_c.is_file() and obj.is_file()):
		return None

	target_sym = coff_defined_function_symbol(target_obj.read_bytes())
	base_sym = coff_defined_function_symbol(obj.read_bytes())
	if target_sym is None or base_sym is None or target_sym == base_sym:
		return None

	workspace = FunctionWorkspace(root=root, function_name=target_sym)
	result = ghidra_only_run(
		workspace=workspace, compile_fn=_compile_must_not_run, diff_fn=diff_fn
	)
	return RecanonOutcome(
		name=root.name,
		old_symbol=base_sym,
		new_symbol=target_sym,
		match_percent=result.best_match_percent,
	)


def project_baselines_recanonicalize(
	workspace_root: Path,
	*,
	diff_fn: DiffFn = default_diff_fn,
	log: Callable[[RecanonOutcome], None] = lambda _o: None,
) -> RecanonSummary:
	"""Walk every function workspace under `workspace_root`, repairing stale
	baselines. Each repair is handed to `log` as it lands."""
	scanned = 0
	outcomes: list[RecanonOutcome] = []
	for root in sorted(p for p in workspace_root.iterdir() if p.is_dir()):
		scanned += 1
		outcome = baseline_recanonicalize_one(root, diff_fn=diff_fn)
		if outcome is not None:
			outcomes.append(outcome)
			log(outcome)
	return RecanonSummary(scanned=scanned, repaired=len(outcomes), outcomes=tuple(outcomes))
