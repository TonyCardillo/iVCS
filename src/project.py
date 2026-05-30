"""Project manifest + aggregator for whole-game decomp progress.

A project.json file declares the target XBE and the list of functions
that constitute the project for progress-tracking purposes. The
aggregator walks the per-function workspaces and computes how much of
the project is matched, partial, or untouched. Workspace path for a
function is `workspace_root / function.name` by convention.
"""

import json
from dataclasses import dataclass
from pathlib import Path


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


def function_status(project: Project, fn: FunctionEntry) -> FunctionStatus:
	"""Classify one function from its workspace `result.json`.

	matched   = success flag set, or best_match_percent >= 100
	partial   = some positive match but not complete
	untouched = no result, or zero/None match
	"""
	ws_path = project.workspace_for(fn)
	result = json_load_or_none(ws_path / "result.json")
	if result is None:
		return FunctionStatus(
			name=fn.name,
			va=fn.va,
			size=fn.size,
			state="untouched",
			best_match_percent=None,
			iterations=0,
			workspace_path=ws_path,
			termination_reason=None,
		)

	best = result.get("best_match_percent")
	success = bool(result.get("success"))
	if success or (isinstance(best, (int, float)) and best >= 100.0):
		state = "matched"
	elif isinstance(best, (int, float)) and best > 0.0:
		state = "partial"
	else:
		state = "untouched"

	reason = result.get("termination_reason")
	model = result.get("model")
	return FunctionStatus(
		name=fn.name,
		va=fn.va,
		size=fn.size,
		state=state,
		best_match_percent=float(best) if isinstance(best, (int, float)) else None,
		iterations=int(result.get("iterations") or 0),
		workspace_path=ws_path,
		termination_reason=reason if isinstance(reason, str) else None,
		model=model if isinstance(model, str) else None,
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
