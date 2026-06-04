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


class JobsAtCapacity(Exception):
	"""Raised when launching would exceed IVCS_MAX_CONCURRENT_JOBS."""


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
