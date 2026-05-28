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

	@property
	def matched_function_percent(self) -> float:
		return (
			(self.matched_functions / self.total_functions * 100.0) if self.total_functions else 0.0
		)

	@property
	def matched_byte_percent(self) -> float:
		return (self.matched_bytes / self.total_bytes * 100.0) if self.total_bytes else 0.0


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

	return Project(
		name=raw["name"],
		xbe_path=xbe_path,
		workspace_root=workspace_root,
		functions=tuple(functions),
	)


def project_aggregate(project: Project) -> ProjectStats:
	statuses: list[FunctionStatus] = []
	matched_fns = partial_fns = untouched_fns = 0
	matched_bytes = partial_bytes = 0
	total_bytes = sum(f.size for f in project.functions)

	for fn in project.functions:
		ws_path = project.workspace_for(fn)
		result = _load_json_or_none(ws_path / "result.json")

		if result is None:
			statuses.append(
				FunctionStatus(
					name=fn.name,
					va=fn.va,
					size=fn.size,
					state="untouched",
					best_match_percent=None,
					iterations=0,
					workspace_path=ws_path,
					termination_reason=None,
				)
			)
			untouched_fns += 1
			continue

		best = result.get("best_match_percent")
		iters = int(result.get("iterations") or 0)
		success = bool(result.get("success"))
		reason = result.get("termination_reason")
		model = result.get("model")

		if success or (isinstance(best, (int, float)) and best >= 100.0):
			state = "matched"
			matched_fns += 1
			matched_bytes += fn.size
		elif isinstance(best, (int, float)) and best > 0.0:
			state = "partial"
			partial_fns += 1
			partial_bytes += fn.size
		else:
			state = "untouched"
			untouched_fns += 1

		statuses.append(
			FunctionStatus(
				name=fn.name,
				va=fn.va,
				size=fn.size,
				state=state,
				best_match_percent=float(best) if isinstance(best, (int, float)) else None,
				iterations=iters,
				workspace_path=ws_path,
				termination_reason=reason if isinstance(reason, str) else None,
				model=model if isinstance(model, str) else None,
			)
		)

	return ProjectStats(
		total_functions=len(project.functions),
		matched_functions=matched_fns,
		partial_functions=partial_fns,
		untouched_functions=untouched_fns,
		total_bytes=total_bytes,
		matched_bytes=matched_bytes,
		partial_bytes=partial_bytes,
		function_statuses=tuple(statuses),
	)


def _parse_int(value) -> int:
	if isinstance(value, str):
		return int(value, 0)  # supports "0x..." and decimal
	return int(value)


def _load_json_or_none(path: Path) -> dict | None:
	if not path.is_file():
		return None
	try:
		return json.loads(path.read_text())
	except (json.JSONDecodeError, OSError):
		return None
