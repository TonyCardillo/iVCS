"""Shared process-global state: the job/sweep/verify registries and the XBE
parse cache. One owner so every view, worker, and the handler see the same
mutable dicts and locks."""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from pathlib import Path

from src.drivers.launcher import JobInfo
from src.formats.xbe import (
	ParsedXbe,
	xbe_load,
)

_PARSE_CACHE_LOCK = threading.Lock()

_PARSE_CACHE: dict[str, ParsedXbe] = {}


def xbe_cached_load(path: str) -> ParsedXbe:
	with _PARSE_CACHE_LOCK:
		if path not in _PARSE_CACHE:
			_PARSE_CACHE[path] = xbe_load(path)
		return _PARSE_CACHE[path]


_JOBS_LOCK = threading.Lock()

_JOBS: dict[Path, JobInfo] = {}

_MAX_CONCURRENT_JOBS = int(os.environ.get("IVCS_MAX_CONCURRENT_JOBS", "2"))


def _job_for(workspace_path: Path) -> JobInfo | None:
	with _JOBS_LOCK:
		return _JOBS.get(workspace_path.resolve())


def _active_jobs() -> list[JobInfo]:
	with _JOBS_LOCK:
		return [j for j in _JOBS.values() if j.is_active()]


def _register_job(job: JobInfo) -> None:
	with _JOBS_LOCK:
		_JOBS[job.workspace_path.resolve()] = job


def _unregister_job(workspace_path: Path) -> None:
	with _JOBS_LOCK:
		_JOBS.pop(workspace_path.resolve(), None)


class JobsAtCapacity(Exception):
	"""Raised when launching would exceed IVCS_MAX_CONCURRENT_JOBS."""


def job_admit(job: JobInfo) -> None:
	"""Atomically reserve a slot for `job`: under one lock, enforce the per-workspace
	and concurrency-cap guards and register it. Raises (leaving the registry
	untouched) if a job already runs for this workspace or the cap is reached.

	Spawning the worker happens only after this returns, so collapsing the
	check and the register into one critical section stops two concurrent submits
	from both passing the guard and racing on one workspace's files."""
	key = job.workspace_path.resolve()
	with _JOBS_LOCK:
		existing = _JOBS.get(key)
		if existing is not None and existing.is_active():
			raise RuntimeError(f"already running for this workspace (state={existing.state})")
		if sum(1 for j in _JOBS.values() if j.is_active()) >= _MAX_CONCURRENT_JOBS:
			raise JobsAtCapacity(f"{_MAX_CONCURRENT_JOBS} concurrent jobs already running")
		_JOBS[key] = job


@dataclass
class SweepState:
	"""Live, mutable handle for a project-wide Ghidra baseline sweep.

	One worker thread walks the queue and mutates this in place, so the progress
	page can read counts/current/state by reference. Like JobInfo, it dies on a
	server restart (the sweep just stops; banked baselines survive on disk)."""

	project_path: str
	project_name: str
	total: int
	state: str = "running"  # running | done | stopped | error
	done: int = 0
	matched: int = 0
	partial: int = 0
	failed: int = 0
	current: str | None = None
	started_at: float = 0.0
	error: str | None = None
	stop_requested: bool = False

	def is_active(self) -> bool:
		return self.state == "running"


_SWEEPS_LOCK = threading.Lock()

_SWEEPS: dict[str, SweepState] = {}  # keyed by project manifest path


def _sweep_for(project_path_str: str) -> SweepState | None:
	with _SWEEPS_LOCK:
		return _SWEEPS.get(project_path_str)


def _register_sweep(sweep: SweepState) -> None:
	with _SWEEPS_LOCK:
		_SWEEPS[sweep.project_path] = sweep


def sweep_register_if_idle(sweep: SweepState) -> SweepState:
	"""Atomically register `sweep` unless an active sweep already owns its project.

	Returns whichever sweep holds the slot: `sweep` if it won the race, else the
	live incumbent. Callers spawn the worker thread only when they get their own
	back, so concurrent launches for one project yield a single worker."""
	with _SWEEPS_LOCK:
		existing = _SWEEPS.get(sweep.project_path)
		if existing is not None and existing.is_active():
			return existing
		_SWEEPS[sweep.project_path] = sweep
		return sweep


def _active_workspace_paths() -> set[Path]:
	"""Resolved workspace dirs with a live per-function job — the sweep skips
	these so it never races another writer on the same function's files."""
	with _JOBS_LOCK:
		return {p for p, j in _JOBS.items() if j.is_active()}


@dataclass
class VerifyState:
	"""Live handle for a whole-image byte-splice verify run. Like the sweep, one
	worker thread mutates it in place and it dies on a server restart (the cache
	it writes on completion survives)."""

	project_path: str
	total: int
	state: str = "running"  # running | done | error
	done: int = 0
	current: str | None = None
	started_at: float = 0.0
	error: str | None = None

	def is_active(self) -> bool:
		return self.state == "running"


_VERIFIES_LOCK = threading.Lock()

_VERIFIES: dict[str, VerifyState] = {}  # keyed by project manifest path


def _verify_for(project_path_str: str) -> VerifyState | None:
	with _VERIFIES_LOCK:
		return _VERIFIES.get(project_path_str)


def _register_verify(verify: VerifyState) -> None:
	with _VERIFIES_LOCK:
		_VERIFIES[verify.project_path] = verify


def verify_register_if_idle(verify: VerifyState) -> VerifyState:
	"""Atomically register `verify` unless an active verify already owns its project.

	Returns whichever verify holds the slot: `verify` if it won, else the live
	incumbent — the caller spawns a worker only for its own."""
	with _VERIFIES_LOCK:
		existing = _VERIFIES.get(verify.project_path)
		if existing is not None and existing.is_active():
			return existing
		_VERIFIES[verify.project_path] = verify
		return verify
