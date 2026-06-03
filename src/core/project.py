"""Project manifest + aggregator for whole-game decomp progress.

A project.json file declares the target XBE and the list of functions
that constitute the project for progress-tracking purposes. The
aggregator walks the per-function workspaces and computes how much of
the project is matched, partial, or untouched. Workspace path for a
function is `workspace_root / function.name` by convention.
"""

import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from src.formats.xbe import ParsedXbe, XbeFunction, xbe_functions_enumerate


@dataclass(frozen=True)
class FunctionEntry:
	name: str
	va: int
	size: int


@dataclass(frozen=True)
class Project:
	name: str
	xbe_path: Path
	workspace_root: Path
	functions: tuple[FunctionEntry, ...]
	src_root: Path = Path("src_tree")

	def workspace_for(self, fn: FunctionEntry) -> Path:
		return self.workspace_root / fn.name


@dataclass(frozen=True)
class FunctionStatus:
	name: str
	va: int
	size: int
	state: str  # "matched" | "partial" | "untouched"
	best_match_percent: float | None
	iterations: int
	workspace_path: Path
	termination_reason: str | None
	model: str | None = None


@dataclass(frozen=True)
class ProjectStats:
	total_functions: int
	matched_functions: int
	partial_functions: int
	untouched_functions: int
	total_bytes: int
	matched_bytes: int
	partial_bytes: int
	function_statuses: tuple[FunctionStatus, ...]
	sdk_functions: int = 0  # identified as XDK library code, excluded from the target
	sdk_bytes: int = 0

	@property
	def matched_function_percent(self) -> float:
		return (
			(self.matched_functions / self.total_functions * 100.0) if self.total_functions else 0.0
		)

	@property
	def matched_byte_percent(self) -> float:
		return (self.matched_bytes / self.total_bytes * 100.0) if self.total_bytes else 0.0

	@property
	def game_functions(self) -> int:
		"""The real decomp target: enumerated functions that aren't SDK library code."""
		return self.total_functions - self.sdk_functions

	@property
	def game_bytes(self) -> int:
		return self.total_bytes - self.sdk_bytes

	@property
	def game_matched_byte_percent(self) -> float:
		"""Matched share of the *game* target — the honest progress number, since
		SDK code is linked from the XDK, not decompiled."""
		return (self.matched_bytes / self.game_bytes * 100.0) if self.game_bytes else 0.0


def project_load(path: Path | str) -> Project:
	path = Path(path)
	raw = json.loads(path.read_text())
	base = path.parent

	functions: list[FunctionEntry] = []
	seen_names: set[str] = set()
	for entry in raw.get("functions", []):
		name = entry["name"]
		if name in seen_names:
			raise ValueError(f"duplicate function name in project: {name!r}")
		seen_names.add(name)
		va = _parse_int(entry["va"])
		size = _parse_int(entry["size"])
		if size <= 0:
			raise ValueError(f"function {name!r} has non-positive size {size}")
		functions.append(FunctionEntry(name=name, va=va, size=size))

	xbe_raw = Path(raw["xbe_path"])
	xbe_path = xbe_raw if xbe_raw.is_absolute() else (base / xbe_raw).resolve()

	ws_raw = Path(raw.get("workspace_root", "./functions"))
	workspace_root = ws_raw if ws_raw.is_absolute() else (base / ws_raw).resolve()

	src_raw = Path(raw.get("src_root", "./src_tree"))
	src_root = src_raw if src_raw.is_absolute() else (base / src_raw).resolve()

	return Project(
		name=raw["name"],
		xbe_path=xbe_path,
		workspace_root=workspace_root,
		functions=tuple(functions),
		src_root=src_root,
	)


def project_manifest_build(
	parsed: ParsedXbe,
	*,
	name: str,
	xbe_path: Path,
	workspace_root: str = "./functions",
	functions: Sequence[XbeFunction] | None = None,
) -> dict:
	"""Build the project.json manifest dict for an enumerated XBE.

	The inverse of `project_load`: emits the on-disk schema it consumes, with
	`va` as an `"0xXXXXXXXX"` string. When `functions` is None the whole image is
	enumerated via `xbe_functions_enumerate`; pass a pre-filtered/limited sequence
	to scope the manifest. Pure: writing the dict is the caller's job.
	"""
	if functions is None:
		functions = xbe_functions_enumerate(parsed)
	return {
		"name": name,
		"xbe_path": str(xbe_path.resolve()),
		"workspace_root": workspace_root,
		"functions": [
			{"name": fn.name, "va": f"0x{fn.va:08X}", "size": fn.size} for fn in functions
		],
	}


def project_sdk_vas(project_path: Path | str) -> frozenset[int]:
	"""VAs identified as XDK library code, from `sdk.json` next to project.json.

	Written by the `libmatch --save` pass; consumed by the coverage report, the
	batch queue, and the web UI to exclude SDK functions from the decomp target.
	Empty when the manifest is absent. The libmatch import is deferred to call
	time so `core` carries no import-time dependency on `analysis`.
	"""
	from src.analysis.libmatch import sdk_manifest_load

	sdk_path = Path(project_path).parent / "sdk.json"
	return frozenset(sdk_manifest_load(sdk_path)) if sdk_path.is_file() else frozenset()


def function_status(project: Project, fn: FunctionEntry) -> FunctionStatus:
	"""Classify one function from its workspace `result.json`, reconciled against
	the attempt history when the summary looks clobbered.

	matched   = success flag set, or best_match_percent >= 100
	partial   = some positive match, or any function that has been iterated on
	untouched = never iterated and no recorded match

	result.json is a clobberable summary: a weak re-run can overwrite it with
	`best_match_percent: null` even though `history/` (including the Ghidra
	warm-start baseline) and `best.c` still hold a real match. When it records no
	positive best, recover the true best and attempt count from the on-disk diffs
	(`history_best_read`).

	Invariant: a function with iterations > 0 has been worked on, so it is never
	reported as untouched — even when every attempt failed to produce a match.
	"""
	ws_path = project.workspace_for(fn)
	result = json_load_or_none(ws_path / "result.json") or {}

	raw_best = result.get("best_match_percent")
	best = float(raw_best) if isinstance(raw_best, (int, float)) else None
	success = bool(result.get("success"))
	iterations = int(result.get("iterations") or 0)
	reason = result.get("termination_reason")
	model = result.get("model")
	model = model if isinstance(model, str) else None

	# A None/zero summary best may just mean the summary was clobbered or the
	# baseline's score was never folded in — trust the history diffs instead.
	if not success and (best is None or best <= 0.0):
		from src.decomp.history import history_best_read

		# result.json records the canonical symbol the diffs are keyed by (the
		# mangled `_fn_<va>@N`); fall back to fn.name for pre-this-field runs.
		recovered_name = result.get("function_name")
		recovered_name = recovered_name if isinstance(recovered_name, str) else fn.name
		recovered = history_best_read(ws_path / "history", recovered_name)
		if recovered.match_percent is not None and recovered.match_percent > 0.0:
			best = recovered.match_percent
			model = model or recovered.model
		iterations = max(iterations, recovered.attempts)

	if success or (best is not None and best >= 100.0):
		state = "matched"
	elif (best is not None and best > 0.0) or iterations > 0:
		state = "partial"
	else:
		state = "untouched"

	return FunctionStatus(
		name=fn.name,
		va=fn.va,
		size=fn.size,
		state=state,
		best_match_percent=best,
		iterations=iterations,
		workspace_path=ws_path,
		termination_reason=reason if isinstance(reason, str) else None,
		model=model,
	)


def project_aggregate(project: Project, *, sdk_vas: frozenset[int] = frozenset()) -> ProjectStats:
	"""Aggregate per-function match state into project stats.

	Functions whose VA is in `sdk_vas` (identified as XDK library code) are tallied
	separately and excluded from the matched/partial/untouched target counts — they
	are linked from the XDK, not decompiled, so they shouldn't inflate progress.
	With an empty `sdk_vas` the result is unchanged.
	"""
	statuses: list[FunctionStatus] = []
	matched_fns = partial_fns = untouched_fns = 0
	matched_bytes = partial_bytes = 0
	sdk_fns = sdk_bytes = 0
	total_bytes = sum(f.size for f in project.functions)

	for fn in project.functions:
		status = function_status(project, fn)
		statuses.append(status)
		if fn.va in sdk_vas:
			sdk_fns += 1
			sdk_bytes += fn.size
			continue
		if status.state == "matched":
			matched_fns += 1
			matched_bytes += fn.size
		elif status.state == "partial":
			partial_fns += 1
			partial_bytes += fn.size
		else:
			untouched_fns += 1

	return ProjectStats(
		total_functions=len(project.functions),
		matched_functions=matched_fns,
		partial_functions=partial_fns,
		untouched_functions=untouched_fns,
		total_bytes=total_bytes,
		matched_bytes=matched_bytes,
		partial_bytes=partial_bytes,
		function_statuses=tuple(statuses),
		sdk_functions=sdk_fns,
		sdk_bytes=sdk_bytes,
	)


@dataclass(frozen=True)
class ModelStat:
	"""Per-model leaderboard row: how a single model performed across the
	functions whose best.c it owns."""

	model: str
	functions: int  # functions this model currently leads (owns best.c)
	matched: int  # of those, fully matched (100%)
	partial: int  # of those, partial (>0, <100)
	avg_best_percent: float  # mean best match% across this model's functions


def model_stats(statuses: Sequence[FunctionStatus]) -> list[ModelStat]:
	"""Group function statuses by the model that owns each best.c.

	Functions with no recorded model (never run) are skipped. Each model is
	credited only for functions where its attempt produced the standing best.c
	(see agent_loop's best-tracking). Rows are sorted by matched desc, then
	functions desc, then model name — the winningest model first.
	"""
	buckets: dict[str, list[FunctionStatus]] = {}
	for s in statuses:
		if not s.model:
			continue
		buckets.setdefault(s.model, []).append(s)

	rows = [
		ModelStat(
			model=model,
			functions=len(group),
			matched=sum(1 for s in group if s.state == "matched"),
			partial=sum(1 for s in group if s.state == "partial"),
			avg_best_percent=sum((s.best_match_percent or 0.0) for s in group) / len(group),
		)
		for model, group in buckets.items()
	]
	rows.sort(key=lambda m: (-m.matched, -m.functions, m.model))
	return rows


@dataclass(frozen=True)
class ModelAttemptStat:
	"""Per-model effort row: how hard a model worked, not just what it won.

	Derived from the per-attempt `.model` sidecars rather than the final
	result.json, so it exposes the cost/quality tradeoff the per-function
	leaderboard hides."""

	model: str
	attempts: int  # tool calls / compiles tagged with this model
	improved: int  # of those, the ones that raised the running best in their function
	matched: int  # of those, the ones that reached 100%

	@property
	def improve_rate(self) -> float:
		"""Share of this model's attempts that moved the needle — its efficiency."""
		return (self.improved / self.attempts * 100.0) if self.attempts else 0.0


def model_attempt_stats(
	workspace_attempts: Sequence[Sequence[tuple[int, str | None, float | None]]],
) -> list[ModelAttemptStat]:
	"""Aggregate per-attempt effort by model across a project.

	`workspace_attempts` is one entry per function: a sequence of
	`(attempt_number, model, match_percent)` triples (any order). Within each
	function the attempts are walked in attempt-number order tracking the running
	best match%; an attempt "improved" when its match% strictly beats every
	lower-numbered attempt (a compile failure / None counts as 0%, never an
	improvement). Attempts with no model are skipped. Rows sort by matched desc,
	improved desc, then model.
	"""
	attempts: dict[str, int] = {}
	improved: dict[str, int] = {}
	matched: dict[str, int] = {}

	for fn_attempts in workspace_attempts:
		running_best = 0.0
		for _n, model, mp in sorted(fn_attempts, key=lambda t: t[0]):
			pct = mp if isinstance(mp, (int, float)) else 0.0
			if model:
				attempts[model] = attempts.get(model, 0) + 1
				if pct > running_best:
					improved[model] = improved.get(model, 0) + 1
				if pct >= 100.0:
					matched[model] = matched.get(model, 0) + 1
			if pct > running_best:
				running_best = pct

	rows = [
		ModelAttemptStat(
			model=model,
			attempts=count,
			improved=improved.get(model, 0),
			matched=matched.get(model, 0),
		)
		for model, count in attempts.items()
	]
	rows.sort(key=lambda m: (-m.matched, -m.improved, m.model))
	return rows


def _parse_int(value) -> int:
	if isinstance(value, str):
		return int(value, 0)  # supports "0x..." and decimal
	return int(value)


def json_load_or_none(path: Path) -> dict | None:
	if not path.is_file():
		return None
	try:
		return json.loads(path.read_text())
	except (json.JSONDecodeError, OSError):
		return None
