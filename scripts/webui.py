#!/usr/bin/env python3
"""iVCS Web UI — a thin visual surface over the XBE loader, carver, and decomp workspace.

Stdlib-only. Run:  python scripts/webui.py [--port 8765]
Then open:        http://127.0.0.1:8765/
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import subprocess
import sys
import threading
import time
import traceback
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# Without this, a UI-launched decomp run dies with FileNotFoundError on first diff.
_BUNDLED_OBJDIFF = REPO_ROOT / "recon" / "objdiff-smoke" / "objdiff-cli"
if "IVCS_OBJDIFF_CLI" not in os.environ and _BUNDLED_OBJDIFF.is_file():
	os.environ["IVCS_OBJDIFF_CLI"] = str(_BUNDLED_OBJDIFF)


from src.integrator import (  # noqa: E402
	image_coverage,
	image_real_relink_verify,
	image_splice_verify,
	image_verify_cache_load,
	image_verify_cache_write,
)
from src.launcher import JobInfo, ghidra_sweep_attempt_one, launch_decomp_job  # noqa: E402
from src.libmatch import sdk_manifest_load  # noqa: E402
from src.notes import notes_load, notes_save  # noqa: E402
from src.objdiff import DiffKind, objdiff_parse  # noqa: E402
from src.project import (  # noqa: E402
	Project,
	ProjectStats,
	json_load_or_none,
	model_attempt_stats,
	model_stats,
	project_aggregate,
	project_load,
)
from src.strings_xref import (  # noqa: E402
	autoname_resolve,
	function_autoname_label,
	function_string_refs,
	string_label_sanitize,
)
from src.sweep import SweepOutcome, sweep_queue, sweep_run  # noqa: E402
from src.symbols import symbol_map_load, symbol_rename  # noqa: E402
from src.xbe import (  # noqa: E402
	ParsedXbe,
	XbeFormatError,
	xbe_load,
)

# ── XBE parse cache ─────────────────────────────────────────────────────────
_PARSE_CACHE: dict[str, ParsedXbe] = {}


def xbe_cached_load(path: str) -> ParsedXbe:
	if path not in _PARSE_CACHE:
		_PARSE_CACHE[path] = xbe_load(path)
	return _PARSE_CACHE[path]


# ── Decomp job registry (in-memory, lives for the server's lifetime) ────────
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


# ── Ghidra sweep registry (project-wide baseline pass, one per project) ─────
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


# ── Image-verify registry (relink oracle over all matched functions) ────────
@dataclass
class VerifyState:
	"""Live handle for a whole-image relink-verify run. Like the sweep, one
	worker thread mutates it in place and it dies on a server restart (the cache
	it writes on completion survives)."""

	project_path: str
	method: str  # "splice" (own relocator) | "relink" (real Link.Exe)
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


# ── Styling ─────────────────────────────────────────────────────────────────
CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
:root {
  --bg: #0a0e14;
  --bg-soft: #0f141c;
  --bg-row: #11161f;
  --fg: #b4c4d4;
  --fg-dim: #6b7c8c;
  --fg-faint: #3a4654;
  --line: rgba(180, 196, 212, 0.14);
  --line-strong: rgba(95, 215, 255, 0.35);
  --cyan: #5fd7ff;
  --amber: #ffb454;
  --green: #95e6cb;
  --red: #ff7a7a;
  --violet: #c792ea;
}
html, body {
  background: var(--bg);
  color: var(--fg);
  font-family: 'JetBrains Mono', 'SF Mono', 'IBM Plex Mono', Menlo, monospace;
  font-size: 13px;
  line-height: 1.5;
  min-height: 100vh;
}
body {
  background-image:
    linear-gradient(rgba(95, 215, 255, 0.02) 1px, transparent 1px),
    linear-gradient(90deg, rgba(95, 215, 255, 0.02) 1px, transparent 1px);
  background-size: 24px 24px;
}
a { color: var(--cyan); text-decoration: none; }
a:hover { text-shadow: 0 0 6px rgba(95, 215, 255, 0.55); }
header {
  border-bottom: 1px solid var(--line);
  padding: 12px 24px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: var(--bg-soft);
}
header .brand {
  color: var(--cyan);
  letter-spacing: 0.3em;
  font-size: 13px;
}
header .brand .dot {
  color: var(--amber);
  display: inline-block;
  animation: pulse 2.4s ease-in-out infinite;
}
@keyframes pulse {
  0%, 100% { opacity: 0.4; }
  50%      { opacity: 1.0; }
}
header nav a {
  margin-left: 24px;
  color: var(--fg-dim);
  letter-spacing: 0.15em;
  text-transform: uppercase;
  font-size: 11px;
}
header nav a:hover { color: var(--cyan); }
main { padding: 24px; max-width: 1400px; margin: 0 auto; }
.crumbs {
  color: var(--fg-faint);
  font-size: 11px;
  margin-bottom: 18px;
  letter-spacing: 0.12em;
  text-transform: uppercase;
}
.crumbs a { color: var(--fg-dim); }
.crumbs .sep { padding: 0 8px; color: var(--fg-faint); }

.panel {
  border: 1px solid var(--line);
  background: var(--bg-soft);
  margin-bottom: 18px;
  position: relative;
}
.panel::before, .panel::after {
  content: '';
  position: absolute;
  width: 8px;
  height: 8px;
  border: 1px solid var(--cyan);
}
.panel::before { top: -1px; left: -1px; border-right: none; border-bottom: none; }
.panel::after  { bottom: -1px; right: -1px; border-left: none; border-top: none; }

.panel-head {
  padding: 8px 16px;
  border-bottom: 1px solid var(--line);
  letter-spacing: 0.22em;
  color: var(--cyan);
  font-size: 11px;
  text-transform: uppercase;
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.panel-head .meta { color: var(--fg-dim); letter-spacing: 0.1em; }
.panel-body { padding: 14px 16px; }

.kv { display: grid; grid-template-columns: 220px 1fr; row-gap: 6px; column-gap: 16px; }
.kv .k { color: var(--fg-dim); text-transform: uppercase; font-size: 11px; letter-spacing: 0.15em; }
.kv .v { color: var(--fg); }
.kv .v.cyan  { color: var(--cyan); }
.kv .v.amber { color: var(--amber); }
.kv .v.green { color: var(--green); }

table { width: 100%; border-collapse: collapse; }
th, td {
  text-align: left;
  padding: 6px 12px;
  border-bottom: 1px solid var(--line);
  font-size: 13px;
}
th {
  color: var(--fg-dim);
  text-transform: uppercase;
  font-size: 10px;
  letter-spacing: 0.18em;
  border-bottom: 1px solid var(--line-strong);
}
tr:hover td { background: var(--bg-row); }
td.num { color: var(--cyan); }
td.size { color: var(--green); }

form.inline { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
input[type="text"], input[type="number"] {
  background: var(--bg);
  color: var(--fg);
  border: 1px solid var(--line);
  padding: 6px 10px;
  font-family: inherit;
  font-size: 13px;
  min-width: 240px;
}
input:focus { outline: none; border-color: var(--cyan); box-shadow: 0 0 0 1px var(--cyan); }
button {
  background: transparent;
  color: var(--cyan);
  border: 1px solid var(--cyan);
  padding: 6px 16px;
  font-family: inherit;
  font-size: 11px;
  letter-spacing: 0.2em;
  text-transform: uppercase;
  cursor: pointer;
}
button:hover { background: rgba(95, 215, 255, 0.08); box-shadow: 0 0 12px rgba(95, 215, 255, 0.2); }

pre.code {
  background: var(--bg);
  border: 1px solid var(--line);
  padding: 12px 14px;
  overflow-x: auto;
  font-size: 12px;
  line-height: 1.7;
  white-space: pre;
}
.error {
  border: 1px solid var(--red);
  color: var(--red);
  padding: 10px 14px;
  background: rgba(255, 122, 122, 0.06);
  margin-bottom: 14px;
}
.error::before { content: '⚠ '; margin-right: 6px; color: var(--red); }

.muted { color: var(--fg-dim); }
.center { text-align: center; }
.tight { letter-spacing: 0.18em; text-transform: uppercase; font-size: 10px; }

.grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }
@media (max-width: 900px) { .grid-2 { grid-template-columns: 1fr; } }

.ascii-logo {
  color: var(--cyan);
  font-size: 11px;
  line-height: 1.2;
  letter-spacing: 0;
  white-space: pre;
  margin-bottom: 18px;
  opacity: 0.85;
}

.badge {
  display: inline-block;
  padding: 2px 8px;
  border: 1px solid var(--line);
  font-size: 10px;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  color: var(--fg-dim);
}
.badge.matched  { color: var(--green); border-color: rgba(149, 230, 203, 0.45); }
.badge.partial  { color: var(--amber); border-color: rgba(255, 180, 84, 0.45); }
.badge.failed   { color: var(--red);   border-color: rgba(255, 122, 122, 0.45); }
.badge.pending  { color: var(--cyan);  border-color: rgba(95, 215, 255, 0.45); }

.kind-NONE         { color: var(--fg-faint); }
.kind-INSERT       { color: var(--green); }
.kind-DELETE       { color: var(--red); }
.kind-REPLACE      { color: var(--violet); }
.kind-OP_MISMATCH  { color: var(--amber); }
.kind-ARG_MISMATCH { color: var(--cyan); }

.progress {
  position: relative;
  border: 1px solid var(--line);
  height: 14px;
  background: var(--bg);
  margin: 6px 0;
}
.progress > .fill {
  position: absolute; top: 0; bottom: 0; left: 0;
  background: linear-gradient(90deg, rgba(95,215,255,0.18), rgba(149,230,203,0.35));
  border-right: 1px solid var(--green);
}
.progress > .label {
  position: absolute; inset: 0;
  display: flex; align-items: center; justify-content: center;
  font-size: 10px; letter-spacing: 0.2em; color: var(--fg);
}

.spark {
  display: block;
  width: 100%;
  height: 56px;
  border: 1px solid var(--line);
  background: var(--bg);
  margin-top: 8px;
}

.attempt-row {
  display: grid;
  grid-template-columns: 48px 1fr 130px 110px 110px;
  gap: 12px;
  align-items: center;
  padding: 6px 8px;
  border-bottom: 1px solid var(--line);
}
.attempt-row:hover { background: var(--bg-row); }
.attempt-row .n { color: var(--fg-dim); }
.attempt-row .attempt-model {
  font-size: 10px;
  letter-spacing: 0.04em;
  color: var(--cyan);
  text-align: right;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.attempt-row .mp { text-align: right; color: var(--green); }
.attempt-row .mp.zero { color: var(--fg-faint); }
.attempt-row .status { text-align: right; }
.attempt-row a.openrow {
  color: var(--fg);
  letter-spacing: 0.04em;
}

.split { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }
@media (max-width: 1100px) { .split { grid-template-columns: 1fr; } }

.codedual {
  display: grid;
  grid-template-columns: 1fr 1fr;
  border: 1px solid var(--line);
  background: var(--bg);
}
.codedual > .col {
  border-right: 1px solid var(--line);
  max-height: 640px;
  overflow: auto;
}
.codedual > .col:last-child { border-right: none; }
.codedual .col-head {
  position: sticky;
  top: 0;
  background: var(--bg-soft);
  border-bottom: 1px solid var(--line);
  padding: 6px 12px;
  font-size: 10px;
  letter-spacing: 0.2em;
  text-transform: uppercase;
  color: var(--cyan);
  z-index: 1;
  display: flex;
  justify-content: space-between;
}
.codedual .col-head .sub { color: var(--fg-faint); letter-spacing: 0.12em; }
.codedual pre {
  padding: 10px 12px;
  font-size: 12px;
  line-height: 1.7;
  white-space: pre;
  background: transparent;
  border: none;
}

.asm-row {
  display: grid;
  grid-template-columns: 64px 64px 1fr;
  gap: 8px;
  padding: 0 12px;
  line-height: 1.7;
  font-size: 12px;
  white-space: pre;
}
.codedual .col.right .asm-row {
  grid-template-columns: 16px 64px 64px 1fr;
}
.asm-row .marker { color: var(--fg); text-align: center; }
.asm-row .addr   { color: var(--fg-faint); }
.asm-row .mnem   { color: var(--cyan); }
.asm-row .args   { color: var(--fg); }
.asm-row.empty   { color: var(--fg-faint); }

.asm-row.none        { /* default */ }

.asm-row.delete                                    { background: rgba(255, 122, 122, 0.06); }
.asm-row.delete .addr, .asm-row.delete .mnem,
.asm-row.delete .args, .asm-row.delete .marker     { color: var(--red); }

.asm-row.insert                                    { background: rgba(149, 230, 203, 0.06); }
.asm-row.insert .addr, .asm-row.insert .mnem,
.asm-row.insert .args, .asm-row.insert .marker     { color: var(--green); }

.asm-row.replace                                   { background: rgba(95, 215, 255, 0.06); }
.asm-row.replace .addr, .asm-row.replace .mnem,
.asm-row.replace .args, .asm-row.replace .marker   { color: var(--cyan); }

.asm-row.op_mismatch                               { background: rgba(255, 180, 84, 0.06); }
.asm-row.op_mismatch .mnem,
.asm-row.op_mismatch .marker                       { color: var(--amber); }

.asm-row.arg_mismatch                              { background: rgba(199, 146, 234, 0.06); }
.asm-row.arg_mismatch .args,
.asm-row.arg_mismatch .marker                      { color: var(--violet); }

.stacked-bar {
  display: flex;
  height: 22px;
  border: 1px solid var(--line);
  background: var(--bg);
  margin: 8px 0 4px 0;
  font-size: 10px;
  letter-spacing: 0.15em;
}
.stacked-bar > div {
  display: flex;
  align-items: center;
  justify-content: center;
  border-right: 1px solid var(--line);
  color: var(--bg);
  font-weight: 600;
  overflow: hidden;
  white-space: nowrap;
}
.stacked-bar > div:last-child { border-right: none; }
.stacked-bar .seg-matched   { background: var(--green); }
.stacked-bar .seg-partial   { background: var(--amber); }
.stacked-bar .seg-untouched { background: var(--bg-row); color: var(--fg-faint); border-right-color: var(--line-strong); }

.legend { display: flex; gap: 18px; font-size: 10px; letter-spacing: 0.15em; text-transform: uppercase; color: var(--fg-dim); margin-top: 6px; }
.legend .swatch { display: inline-block; width: 10px; height: 10px; margin-right: 6px; vertical-align: middle; border: 1px solid var(--line); }
.legend .swatch.matched   { background: var(--green); }
.legend .swatch.partial   { background: var(--amber); }
.legend .swatch.untouched { background: var(--bg-row); }

.hist {
  display: block;
  width: 100%;
  height: 160px;
  border: 1px solid var(--line);
  background: var(--bg);
  margin-top: 4px;
}

.fn-state { font-size: 10px; letter-spacing: 0.18em; text-transform: uppercase; }
.fn-state.matched   { color: var(--green); }
.fn-state.partial   { color: var(--amber); }
.fn-state.untouched { color: var(--fg-faint); }

.fn-label { color: var(--amber); }
.mono { font-family: var(--mono, monospace); }
.prov { font-size: 9px; letter-spacing: 0.12em; padding: 0 4px; border-radius: 3px; vertical-align: middle; }
.prov.user { color: var(--cyan); }
.prov.sdk  { color: var(--fg-dim); border: 1px solid var(--fg-faint); }

.rename-form, .notes-form { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; margin: 6px 0; }
.rename-form input[type=text] { width: 260px; }
.string-hints { margin: 4px 0 10px 0; }
.hint-row { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; align-items: center; }
.hint-form { display: inline; margin: 0; }
button.hint {
  background: transparent;
  border: 1px solid var(--line);
  color: var(--fg);
  font-family: inherit;
  font-size: 11px;
  padding: 3px 8px;
  cursor: pointer;
}
button.hint:hover { border-color: var(--cyan); }
span.hint { font-size: 11px; padding: 3px 8px; border: 1px dashed var(--line); }
.notes-form textarea {
  width: 100%; font-family: var(--mono, monospace); font-size: 12px;
  background: var(--bg-dim, #11151c); color: var(--fg); border: 1px solid var(--fg-faint);
  border-radius: 4px; padding: 8px; resize: vertical;
}

.pager {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
  font-size: 11px;
  letter-spacing: 0.08em;
  padding: 8px 2px;
  border-top: 1px solid var(--line);
  margin-top: 6px;
}
.pager .pages { display: flex; gap: 6px; align-items: center; }
.pager a, .pager span.pg-cur, .pager span.pg-disabled {
  display: inline-block;
  padding: 3px 9px;
  border: 1px solid var(--line);
  color: var(--fg-dim);
  text-decoration: none;
}
.pager a:hover { color: var(--cyan); border-color: var(--cyan); }
.pager span.pg-cur { color: var(--bg); background: var(--cyan); border-color: var(--cyan); }
.pager span.pg-disabled { opacity: 0.35; }
.pager span.pg-ellipsis { padding: 3px 4px; color: var(--fg-faint); border: none; }
.pager form.pg-jump { display: inline-flex; align-items: center; gap: 6px; }
.pager form.pg-jump input[type=number] {
  width: 64px;
  background: var(--bg);
  color: var(--fg);
  border: 1px solid var(--line);
  padding: 3px 6px;
  font: inherit;
}

.run-banner {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 10px 14px;
  border: 1px solid var(--line);
  background: var(--bg-soft);
  margin: 0 0 14px 0;
  font-size: 12px;
  letter-spacing: 0.06em;
}
.run-banner.running { border-color: var(--line-strong); }
.run-banner.failed  { border-color: rgba(255, 122, 122, 0.55); }
.run-banner.done    { border-color: rgba(149, 230, 203, 0.45); }
.run-banner.interrupted { border-color: var(--amber); }
.run-banner a.resume {
  margin-left: auto;
  color: var(--amber);
  border: 1px solid var(--amber);
  padding: 3px 10px;
  text-decoration: none;
}
.run-banner a.resume:hover { background: var(--amber); color: var(--bg); }
.page-actions { margin: 0 0 14px 0; }
.page-actions a {
  color: var(--cyan);
  text-decoration: none;
  font-size: 12px;
  letter-spacing: 0.06em;
}
.page-actions a:hover { color: var(--amber); }
.run-actions { margin: 0 0 14px 0; }
.btn-run {
  display: inline-block;
  padding: 6px 16px;
  border: 1px solid var(--line-strong);
  color: var(--green);
  text-decoration: none;
  font-size: 12px;
  letter-spacing: 0.08em;
}
.btn-run:hover { border-color: var(--green); background: var(--bg-soft); }
.run-banner .amber  { color: var(--amber); }
.run-banner .cyan   { color: var(--cyan); }
.run-banner .green  { color: var(--green); }
.run-banner.sweeping { border-color: rgba(95, 215, 255, 0.45); }
.run-banner .sweep-counts { letter-spacing: 0.04em; }
.run-banner form.sweep-stop { margin-left: auto; }
button.btn-run {
  background: transparent;
  cursor: pointer;
  font-family: inherit;
}
.sweep-bar {
  height: 4px;
  background: var(--bg-row);
  border: 1px solid var(--line);
  margin: 0 0 14px 0;
}
.sweep-bar-fill { height: 100%; background: var(--cyan); transition: width 0.4s ease; }

button, input[type=number], select {
  background: var(--bg);
  color: var(--fg);
  border: 1px solid var(--line);
  padding: 4px 10px;
  font: inherit;
}
button { cursor: pointer; letter-spacing: 0.1em; }
button:hover { border-color: var(--cyan); color: var(--cyan); }
button:disabled { opacity: 0.35; cursor: not-allowed; }
button:disabled:hover { border-color: var(--line); color: var(--fg); }

.proj-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
  gap: 10px;
}
.proj-card {
  display: block;
  text-decoration: none;
  color: var(--fg);
  border: 1px solid var(--line);
  background: var(--bg);
  padding: 12px 14px;
  position: relative;
}
.proj-card:hover { border-color: var(--cyan); }
.proj-card::before {
  content: '';
  position: absolute; left: -1px; top: -1px; width: 8px; height: 8px;
  border-top: 1px solid var(--cyan);
  border-left: 1px solid var(--cyan);
}
.proj-card::after {
  content: '';
  position: absolute; right: -1px; bottom: -1px; width: 8px; height: 8px;
  border-bottom: 1px solid var(--cyan);
  border-right: 1px solid var(--cyan);
}
.proj-card .proj-name { color: var(--amber); font-weight: 600; }
.proj-card .proj-meta { color: var(--cyan); font-size: 11px; margin: 2px 0 4px 0; }
.proj-card .proj-path { font-size: 10px; word-break: break-all; }

.filter-bar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 12px;
  padding: 10px 12px;
  border: 1px solid var(--line);
  background: var(--bg);
  margin: 0 0 10px 0;
  font-size: 11px;
}
.filter-bar label {
  display: flex; align-items: center; gap: 6px;
  color: var(--fg-dim);
  letter-spacing: 0.08em;
  text-transform: uppercase;
  font-size: 10px;
}
.filter-bar input[type=text] { width: 140px; }
.filter-bar input[type=number] { width: 70px; }
.filter-bar select { font-size: 11px; }
.filter-bar a.clear-filters {
  color: var(--fg-dim);
  text-decoration: none;
  padding: 4px 10px;
  border: 1px solid var(--line);
}
.filter-bar a.clear-filters:hover { color: var(--cyan); border-color: var(--cyan); }

.action-rerun { color: var(--fg-dim); margin-left: 6px; }
.action-rerun:hover { color: var(--amber); }

.rerun-notice {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 14px;
  border: 1px dashed var(--line-strong);
  background: var(--bg);
  margin: 14px 0 10px 0;
  font-size: 11px;
  letter-spacing: 0.05em;
}
.rerun-notice .amber { color: var(--amber); }
.rerun-notice .green { color: var(--green); }
.rerun-notice .cyan  { color: var(--cyan); }

.kv-checkbox {
  display: flex;
  align-items: center;
  gap: 8px;
  margin: 10px 0;
  font-size: 11px;
  color: var(--fg-dim);
}
"""


# ── HTML scaffold ───────────────────────────────────────────────────────────
def page(
	title: str,
	body: str,
	current_path: str | None,
	refresh_seconds: int | None = None,
) -> str:
	nav_html = '<a href="/">overview</a>'
	path_chip = (
		f'<span class="muted tight">[ xbe ]</span> '
		f'<span style="color: var(--amber);">{html.escape(current_path)}</span>'
		if current_path
		else ""
	)
	# Swap only <main> (no flicker, keeps scroll); server drops data-live to stop the poller.
	live_attr = f' data-live="{refresh_seconds}"' if refresh_seconds else ""
	live_script = (
		"""
<script>
(function(){
  function ms(el){ return el ? parseInt(el.getAttribute('data-live'), 10) : NaN; }
  function tick(){
    fetch(location.href).then(function(r){ return r.text(); }).then(function(t){
      var next = new DOMParser().parseFromString(t, 'text/html').querySelector('main');
      var cur = document.querySelector('main');
      if (next && cur) cur.innerHTML = next.innerHTML;
      var n = ms(next);
      if (n > 0) setTimeout(tick, n * 1000);
    }).catch(function(){ setTimeout(tick, 3000); });
  }
  var n = ms(document.querySelector('main'));
  if (n > 0) setTimeout(tick, n * 1000);
})();
</script>"""
		if refresh_seconds
		else ""
	)
	return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<title>{html.escape(title)} · iVCS</title>
<style>{CSS}</style>
</head><body>
<header>
  <div class="brand">◇ &nbsp;i&middot;V&middot;C&middot;S<span class="dot">●</span></div>
  <div>{path_chip}</div>
  <nav>{nav_html}</nav>
</header>
<main{live_attr}>{body}</main>
{live_script}
</body></html>"""


def crumbs(*items: tuple[str, str | None]) -> str:
	parts = []
	for i, (label, href) in enumerate(items):
		if i:
			parts.append('<span class="sep">/</span>')
		if href:
			parts.append(f'<a href="{href}">{html.escape(label)}</a>')
		else:
			parts.append(f"<span>{html.escape(label)}</span>")
	return f'<div class="crumbs">{"".join(parts)}</div>'


def panel(head: str, body: str, meta: str = "") -> str:
	meta_html = f'<span class="meta">{html.escape(meta)}</span>' if meta else ""
	return (
		f'<div class="panel"><div class="panel-head">'
		f"<span>{html.escape(head)}</span>{meta_html}"
		f'</div><div class="panel-body">{body}</div></div>'
	)


# ── Views ───────────────────────────────────────────────────────────────────
LOGO = """\
 ┌──────────────────────────────────────────┐
 │  ░▒▓  i V C S  ▓▒░    matching-decomp    │
 │  └─ xbe · carver · coff · agent-loop ─┘  │
 └──────────────────────────────────────────┘"""


def view_index() -> str:
	projects = _discover_projects()
	if projects:
		proj_rows = "".join(
			f'<a class="proj-card" href="/progress?path={quote(path)}">'
			f'<div class="proj-name">{html.escape(name)}</div>'
			f'<div class="proj-meta">{count:,} functions</div>'
			f'<div class="proj-path muted">{html.escape(path.replace(str(REPO_ROOT) + "/", ""))}</div>'
			f"</a>"
			for path, name, count in projects
		)
		proj_panel = panel(
			"Projects",
			f'<div class="proj-grid">{proj_rows}</div>',
			meta=f"{len(projects)} detected · click to open dashboard",
		)
	else:
		proj_panel = panel(
			"Projects",
			'<p class="muted">No projects detected. Drop a '
			'<span class="cyan">project.json</span> under <span class="cyan">projects/</span> '
			"to get started.</p>",
		)

	body = f'<div class="ascii-logo">{LOGO}</div>\n{proj_panel}'
	return page("iVCS", body, current_path=None)


# ── Decomp workspace views ──────────────────────────────────────────────────
def _path_query_suffix(current_path: str | None) -> str:
	"""`&path=<quoted>` if a project is in scope, else empty. Keeps the
	project breadcrumb resolvable as the user clicks through decomp pages."""
	return f"&path={quote(current_path)}" if current_path else ""


def _project_crumb(current_path: str | None) -> tuple[str, str | None]:
	"""Middle breadcrumb for decomp views. Falls back to a non-linked
	'workspace' label when there is no project context (e.g., direct URL
	without `?path=...`), since the old `/decomp` index page is gone."""
	if current_path:
		try:
			project = project_load(current_path)
			return (project.name, f"/progress?path={quote(current_path)}")
		except Exception:  # noqa: BLE001, S110 — malformed/missing manifest falls back gracefully
			pass
	return ("workspace", None)


def _objdiff_cli_path() -> str | None:
	explicit = os.environ.get("IVCS_OBJDIFF_CLI")
	if explicit and Path(explicit).is_file():
		return explicit
	bundled = REPO_ROOT / "recon" / "objdiff-smoke" / "objdiff-cli"
	if bundled.is_file():
		return str(bundled)
	return None


def _diff_json_is_stale(diff_path: Path, *inputs: Path) -> bool:
	"""True when the cached diff predates an input it was derived from."""
	diff_mtime = diff_path.stat().st_mtime
	return any(p.is_file() and p.stat().st_mtime > diff_mtime for p in inputs)


def _ensure_diff_json(workspace_root: Path, n: int, function_name: str | None) -> Path | None:
	"""Lazily derive `NNNN.diff.json` from target.obj + NNNN.obj.

	Regenerates when the cached diff is missing or older than either input. The
	attempt's object is symbol-canonicalized (`__fn_<va>` -> `_fn_<va>`) after it
	compiles, so a diff derived from the pre-canonicalization object shows an
	unpairable `symbol mismatch` even though the attempt matched; treating a diff
	older than its obj as stale self-heals those.
	"""
	history = workspace_root / "history"
	diff_path = history / f"{n:04d}.diff.json"
	obj_path = history / f"{n:04d}.obj"
	target = workspace_root / "target.obj"
	if not obj_path.is_file() or not target.is_file():
		return diff_path if diff_path.is_file() else None
	if diff_path.is_file() and not _diff_json_is_stale(diff_path, obj_path, target):
		return diff_path
	cli = _objdiff_cli_path()
	if cli is None:
		return diff_path if diff_path.is_file() else None
	cmd = [
		cli,
		"diff",
		"-1",
		str(target),
		"-2",
		str(obj_path),
		"--format",
		"json",
		"-o",
		str(diff_path),
	]
	if function_name:
		cmd.append(function_name)
	try:
		subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=True)
	except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
		return None
	return diff_path if diff_path.is_file() else None


def _workspace_function_name(workspace_root: Path) -> str | None:
	result = json_load_or_none(workspace_root / "result.json")
	if result and result.get("function_name"):
		return result["function_name"]
	job = _job_for(workspace_root)
	if job is not None:
		return job.function_name
	return _guess_function_name(workspace_root)


def _attempt_info(workspace_root: Path, n: int, *, derive_missing: bool = True) -> dict:
	"""Pull what's interesting about one attempt. Lazily derives diff JSON if absent."""
	stem = f"{n:04d}"
	history = workspace_root / "history"
	c_path = history / f"{stem}.c"
	obj_path = history / f"{stem}.obj"
	diff_path = history / f"{stem}.diff.json"

	if derive_missing and not diff_path.is_file():
		_ensure_diff_json(workspace_root, n, _workspace_function_name(workspace_root))

	model_path = history / f"{stem}.model"
	info = {
		"n": n,
		"c_path": c_path,
		"obj_path": obj_path,
		"diff_path": diff_path,
		"compiled": obj_path.is_file(),
		"match_percent": None,
		"function_symbol_name": None,
		"model": model_path.read_text().strip() if model_path.is_file() else None,
	}
	if diff_path.is_file():
		try:
			diff = objdiff_parse(json.loads(diff_path.read_text()))
		except (json.JSONDecodeError, OSError):
			return info
		for symbol in diff.function_symbols("left"):
			info["match_percent"] = symbol.match_percent
			info["function_symbol_name"] = symbol.name
			break
		if info["match_percent"] is None:
			for symbol in diff.function_symbols("right"):
				info["match_percent"] = symbol.match_percent
				info["function_symbol_name"] = symbol.name
				break
	return info


def _attempts_listing(workspace_root: Path, *, derive_missing: bool = True) -> list[dict]:
	history = workspace_root / "history"
	if not history.is_dir():
		return []
	numbers: list[int] = []
	for entry in history.iterdir():
		if entry.suffix != ".c":
			continue
		try:
			numbers.append(int(entry.stem))
		except ValueError:
			continue
	return [
		_attempt_info(workspace_root, n, derive_missing=derive_missing) for n in sorted(numbers)
	]


def _attempt_model_label(attempt: dict, fallback: str | None) -> str | None:
	"""Model to show for one attempt row: its own `.model` sidecar, else the
	run's recorded model — the fallback covers legacy attempts written before
	per-attempt tagging (a single-model run's attempts all share that model).
	The Ghidra baseline (#0000) carries its own badge, so it gets no chip.
	"""
	if attempt["n"] == 0:
		return None
	return attempt.get("model") or fallback


def _best_attempt(attempts: list[dict]) -> dict | None:
	"""The attempt that owns best.c: highest match%, ties broken by earliest.

	Its `model` is the AI we credit for the function's best solution — even when
	several models attacked it across runs.
	"""
	scored = [a for a in attempts if isinstance(a.get("match_percent"), (int, float))]
	if not scored:
		return None
	return max(scored, key=lambda a: (a["match_percent"], -a["n"]))


def _status_badge(result_json: dict | None) -> str:
	if result_json is None:
		return '<span class="badge pending">in progress</span>'
	reason = result_json.get("termination_reason", "?")
	success = result_json.get("success", False)
	cls = (
		"matched"
		if success
		else ("failed" if reason in ("hard_timeout", "llm_no_progress") else "partial")
	)
	return f'<span class="badge {cls}">{html.escape(reason)}</span>'


def _sparkline_svg(attempts: list[dict]) -> str:
	series = [a["match_percent"] for a in attempts]
	if not series:
		return '<div class="muted center" style="padding: 18px;">no attempts yet</div>'
	pts: list[tuple[float, float]] = []
	n = len(series)
	width = 800
	height = 56
	for i, mp in enumerate(series):
		x = (i / max(n - 1, 1)) * (width - 8) + 4
		v = mp if mp is not None else 0.0
		y = height - 4 - (v / 100.0) * (height - 12)
		pts.append((x, y))
	path = "M " + " L ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
	dots = "".join(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="2.5" fill="#5fd7ff"/>' for x, y in pts)
	grid = "".join(
		f'<line x1="0" x2="{width}" y1="{height - 4 - p / 100 * (height - 12):.1f}" '
		f'y2="{height - 4 - p / 100 * (height - 12):.1f}" '
		f'stroke="rgba(180,196,212,0.08)" stroke-width="1"/>'
		for p in (25, 50, 75, 100)
	)
	return (
		f'<svg class="spark" viewBox="0 0 {width} {height}" preserveAspectRatio="none">'
		f"{grid}"
		f'<path d="{path}" stroke="#5fd7ff" stroke-width="1.5" fill="none" opacity="0.9"/>'
		f"{dots}"
		"</svg>"
	)


def _symbol_notes_panel(root: Path, current_path: str | None) -> str:
	"""Rename box + free-text notes for the function this workspace decompiles.

	The rename is a display label only — the machine symbol stays `fn_<va>`, so
	nothing here touches the matching or relink path. Notes are keyed by the
	workspace dir, so they work even without a project path; rename needs the
	project path to locate `symbols.json`.
	"""
	va = _va_from_workspace(root)
	notes_text = notes_load(root)

	rename_form = ""
	if current_path and va is not None:
		symbols = symbol_map_load(current_path)
		label = symbols.label_for(va)
		provenance = symbols.provenance(va)
		current = (
			f'<span class="muted tight">current: <span class="amber">{html.escape(label)}</span>'
			f" · {provenance}</span>"
			if provenance != "default"
			else '<span class="muted tight">no custom name yet</span>'
		)
		rename_form = f"""
<form class="rename-form" method="post" action="/symbol/rename">
  <input type="hidden" name="path" value="{html.escape(current_path)}">
  <input type="hidden" name="va"   value="0x{va:08X}">
  <input type="hidden" name="root" value="{html.escape(str(root))}">
  <label>name <input type="text" name="label" value="{html.escape(label)}" placeholder="CPlayer__Update"></label>
  <button type="submit">rename</button>
  <span class="muted tight">blank to revert to fn_{va:08X}</span>
  {current}
</form>
"""

	notes_form = f"""
<form class="notes-form" method="post" action="/notes/save">
  <input type="hidden" name="root" value="{html.escape(str(root))}">
  <input type="hidden" name="path" value="{html.escape(current_path or "")}">
  <textarea name="notes" rows="5" placeholder="calling convention, struct layout, what this function does…">{html.escape(notes_text)}</textarea>
  <button type="submit">save notes</button>
</form>
"""
	hints = _string_hints_html(root, current_path, va)
	meta = "display label · machine symbol stays fn_<va>" if va is not None else "notes"
	return panel("Symbol &amp; notes", rename_form + hints + notes_form, meta=meta)


def _string_hints_html(root: Path, current_path: str | None, va: int | None) -> str:
	"""Naming hints from the string literals this function references.

	Each sanitizable string becomes a one-click button that adopts it as the
	display label (POST to /symbol/rename). Binary-derived and clean-room — a
	"quick start" for naming an unknown function from what it prints/asserts.
	Silent (empty) when there's no project path, no matching function, or no
	referenced strings.
	"""
	if not current_path or va is None:
		return ""
	try:
		project = project_load(current_path)
		fn = next((f for f in project.functions if f.va == va), None)
		if fn is None:
			return ""
		parsed = xbe_cached_load(str(project.xbe_path))
		refs = function_string_refs(parsed, fn.va, fn.size)
	except Exception:  # noqa: BLE001 — hints are best-effort; never break the page
		return ""
	if not refs:
		return ""

	shown, rows = refs[:12], []
	for s in shown:
		disp = html.escape(s if len(s) <= 48 else s[:45] + "…")
		label = string_label_sanitize(s)
		if label:
			rows.append(
				'<form class="hint-form" method="post" action="/symbol/rename">'
				f'<input type="hidden" name="path" value="{html.escape(current_path)}">'
				f'<input type="hidden" name="va" value="0x{va:08X}">'
				f'<input type="hidden" name="root" value="{html.escape(str(root))}">'
				f'<input type="hidden" name="label" value="{html.escape(label)}">'
				f'<button type="submit" class="hint" title="adopt: {html.escape(s)}">'
				f'{disp} → <span class="cyan">{html.escape(label)}</span></button>'
				"</form>"
			)
		else:
			rows.append(f'<span class="hint muted" title="{html.escape(s)}">{disp}</span>')
	more = f'<span class="muted tight">+{len(refs) - 12} more</span>' if len(refs) > 12 else ""
	return (
		'<div class="string-hints">'
		'<div class="muted tight">referenced strings — click to adopt as the name:</div>'
		f'<div class="hint-row">{"".join(rows)}{more}</div>'
		"</div>"
	)


def view_decomp_run(root_str: str, current_path: str | None) -> str:
	root = Path(root_str)
	if not root.is_dir():
		raise FileNotFoundError(f"workspace not a directory: {root}")

	job = _job_for(root)
	result = json_load_or_none(root / "result.json")
	attempts = _attempts_listing(root)
	best = (result or {}).get("best_match_percent")
	if best is None:
		best = max((a["match_percent"] or 0 for a in attempts), default=None)
	fn_name = (
		(result or {}).get("function_name")
		or (job.function_name if job else None)
		or _guess_function_name(root)
		or "?"
	)

	best_at = _best_attempt(attempts)
	best_model = (result or {}).get("model") or (best_at["model"] if best_at else None)
	best_model_row = ""
	if best_model:
		where = f" · #{best_at['n']:04d}" if best_at else ""
		best_model_row = (
			'  <div class="k">best by</div>         '
			f'<div class="v cyan">{html.escape(best_model)}{where}</div>\n'
		)

	header_body = f"""
<div class="kv">
  <div class="k">workspace</div>      <div class="v">{html.escape(str(root))}</div>
  <div class="k">function</div>       <div class="v amber">{html.escape(fn_name)}</div>
  <div class="k">attempts</div>       <div class="v">{len(attempts)}</div>
  <div class="k">best match</div>     <div class="v green">{(f"{best:.2f}%" if isinstance(best, (int, float)) else "—")}</div>
{best_model_row}  <div class="k">status</div>         <div class="v">{_status_badge(result)}</div>
</div>
{_progress_bar(best)}
{_sparkline_svg(attempts)}
<div class="muted tight" style="margin-top: 8px;">match % across attempts</div>
"""

	last_n = attempts[-1]["n"] if attempts else 0
	job_active = bool(job and job.is_active())

	timeline_rows = []
	for a in attempts:
		is_in_flight = job_active and a["n"] == last_n
		label, badge_cls, badge_text = _attempt_status_labels(a, is_in_flight=is_in_flight)
		if label is not None:
			mp_html = f'<span class="muted">{label}</span>'
			status_html = f'<span class="badge {badge_cls}">{badge_text}</span>'
		else:
			mp = a["match_percent"]
			cls = "" if mp > 0 else "zero"
			mp_html = f'<span class="mp {cls}">{mp:.2f}%</span>'
			status_html = (
				'<span class="badge matched">100%</span>'
				if mp == 100.0
				else '<span class="badge partial">partial</span>'
			)
		ghidra_tag = (
			'<span class="badge partial" title="Ghidra warm-start baseline">ghidra</span>'
			if a["n"] == 0
			else ""
		)
		attempt_model = _attempt_model_label(a, (result or {}).get("model"))
		model_chip = (
			f'<span class="attempt-model" title="model for this attempt">'
			f"{html.escape(attempt_model)}</span>"
			if attempt_model
			else ""
		)
		timeline_rows.append(
			f'<div class="attempt-row">'
			f'<span class="n">#{a["n"]:04d}</span>'
			f'<a class="openrow" href="/decomp/attempt?root={html.escape(str(root))}&n={a["n"]}">view source &amp; diff →</a>'
			f"{model_chip}"
			f'<span class="status">{mp_html}</span>'
			f'<span class="status">{ghidra_tag}{status_html}</span>'
			f"</div>"
		)
	timeline = (
		"".join(timeline_rows)
		or '<div class="muted center" style="padding: 18px;">no attempts on disk yet</div>'
	)

	ctx_h = (root / "ctx.h").read_text() if (root / "ctx.h").is_file() else "(missing)"
	best_c = (root / "best.c").read_text() if (root / "best.c").is_file() else "(no best.c yet)"

	banner = ""
	refresh = None
	if job:
		if job.is_active():
			refresh = 3
			elapsed = (
				int((time.time() if job.started_at else 0) - job.started_at)
				if job.started_at
				else 0
			)
			banner = (
				f'<div class="run-banner running">'
				f'<span class="badge pending">{job.state.upper()}</span>'
				f'<span>iter <span class="amber">{job.iterations_completed}</span>/{job.max_iterations}'
				f" · elapsed {elapsed}s / {int(job.hard_timeout_seconds)}s"
				f' · model <span class="cyan">{html.escape(job.model)}</span></span>'
				f'<span class="muted">auto-refreshing every 3s</span>'
				f"</div>"
			)
		elif job.state == "error":
			banner = (
				f'<div class="run-banner failed">'
				f'<span class="badge failed">ERROR</span>'
				f'<span class="muted">{html.escape(job.error or "")}</span>'
				f"</div>"
			)
		else:
			reason = job.termination_reason or "done"
			best_str = (
				f"{job.best_match_percent:.2f}%"
				if isinstance(job.best_match_percent, (int, float))
				else "—"
			)
			banner = (
				f'<div class="run-banner done">'
				f'<span class="badge matched">FINISHED</span>'
				f'<span>reason <span class="amber">{html.escape(reason)}</span>'
				f' · best <span class="green">{best_str}</span>'
				f" · iter {job.iterations_completed}/{job.max_iterations}</span>"
				f"</div>"
			)
	elif _run_interrupted(job, result, attempts):
		banner = _interrupted_banner(root, current_path)

	body = (
		crumbs(("home", "/"), _project_crumb(current_path), (root.name, None))
		+ banner
		+ _run_action_bar(root, current_path, job, has_attempts=bool(attempts))
		+ panel("Run", header_body, meta=fn_name)
		+ _symbol_notes_panel(root, current_path)
		+ panel("Attempts", timeline, meta=f"{len(attempts)} total")
		+ '<div class="split">'
		+ panel(
			"ctx.h",
			f'<pre class="code">{html.escape(ctx_h)}</pre>',
			meta="context header · prepended to every attempt",
		)
		+ panel(
			"best.c",
			f'<pre class="code">{html.escape(best_c)}</pre>',
			meta="highest-match attempt so far",
		)
		+ "</div>"
	)
	return page(
		f"decomp · {root.name}",
		body,
		current_path=current_path,
		refresh_seconds=refresh,
	)


def view_decomp_attempt(root_str: str, n: int, current_path: str | None) -> str:
	root = Path(root_str)
	if not root.is_dir():
		raise FileNotFoundError(f"workspace not a directory: {root}")

	info = _attempt_info(root, n)
	c_text = info["c_path"].read_text() if info["c_path"].is_file() else "(missing)"

	compile_error = ""
	if not info["diff_path"].is_file() and not info["compiled"]:
		stderr_path = info["c_path"].with_suffix(".stderr")
		compile_error = (
			stderr_path.read_text()
			if stderr_path.is_file()
			else "compile failed (no diff produced, no stderr captured)"
		)

	mp = info["match_percent"]
	mp_str = f"{mp:.2f}%" if isinstance(mp, (int, float)) else "—"

	head_body = f"""
<div class="kv">
  <div class="k">attempt</div>        <div class="v">#{n:04d}</div>
  <div class="k">workspace</div>      <div class="v muted">{html.escape(str(root))}</div>
  <div class="k">symbol</div>         <div class="v amber">{html.escape(info["function_symbol_name"] or "?")}</div>
  <div class="k">match</div>          <div class="v green">{mp_str}</div>
  <div class="k">compiled</div>       <div class="v">{"yes" if info["compiled"] else "no"}</div>
</div>
{_progress_bar(mp)}
"""

	sections = [
		crumbs(
			("home", "/"),
			_project_crumb(current_path),
			(
				root.name,
				f"/decomp/run?root={html.escape(str(root))}{_path_query_suffix(current_path)}",
			),
			(f"#{n:04d}", None),
		),
		panel(f"Attempt #{n:04d}", head_body),
	]
	if compile_error:
		sections.append(
			panel("Compile error", f'<pre class="code">{html.escape(compile_error)}</pre>')
		)
		sections.append(panel(f"{n:04d}.c", f'<pre class="code">{html.escape(c_text)}</pre>'))
	else:
		target_col, current_col, stats = _asm_dual_columns(
			info["diff_path"], info["function_symbol_name"]
		)
		matched, differs, target_name, current_name = stats
		sections.append(
			panel(
				"Compilation",
				(
					'<div class="codedual">'
					f'<div class="col left">'
					f'<div class="col-head"><span>target · {html.escape(target_name)}</span><span class="sub">{matched} match · {differs} diff</span></div>'
					f"{target_col}"
					"</div>"
					f'<div class="col right">'
					f'<div class="col-head"><span>current · {html.escape(current_name)}</span><span class="sub">&lt; del · &gt; ins · | repl · o op · r arg</span></div>'
					f"{current_col}"
					"</div>"
					"</div>"
				),
				meta=f"{n:04d}.obj vs target.obj",
			)
		)
		sections.append(
			panel(
				f"{n:04d}.c",
				f'<pre class="code">{_numbered_c(c_text)}</pre>',
				meta=f"{len(c_text.splitlines())} lines",
			)
		)

	nav = []
	if n > 1:
		nav.append(f'<a href="/decomp/attempt?root={html.escape(str(root))}&n={n - 1}">← prev</a>')
	nav.append(f'<a href="/decomp/run?root={html.escape(str(root))}">↑ run</a>')
	if (root / "history" / f"{n + 1:04d}.c").is_file():
		nav.append(f'<a href="/decomp/attempt?root={html.escape(str(root))}&n={n + 1}">next →</a>')
	sections.append(
		f'<p class="tight" style="display: flex; gap: 18px; padding: 4px 0;">{"  ".join(nav)}</p>'
	)

	return page(f"#{n:04d}", body="".join(sections), current_path=current_path)


_KIND_GLYPHS: dict[DiffKind, str] = {
	DiffKind.NONE: " ",
	DiffKind.DELETE: "&lt;",
	DiffKind.INSERT: "&gt;",
	DiffKind.REPLACE: "|",
	DiffKind.OP_MISMATCH: "o",
	DiffKind.ARG_MISMATCH: "r",
}


def _split_instr(formatted: str) -> tuple[str, str]:
	parts = formatted.split(None, 1)
	if not parts:
		return "", ""
	if len(parts) == 1:
		return parts[0], ""
	return parts[0], parts[1]


def _asm_dual_columns(
	diff_path: Path, function_symbol_name: str | None
) -> tuple[str, str, tuple[int, int, str, str]]:
	"""Returns (target_rows_html, current_rows_html, (matched, differs, target_name, current_name))."""
	try:
		diff = objdiff_parse(json.loads(diff_path.read_text()))
	except (json.JSONDecodeError, OSError) as e:
		err = f'<div class="error">{html.escape(str(e))}</div>'
		return err, err, (0, 0, "—", "—")

	left_syms = list(diff.function_symbols("left"))
	right_syms = list(diff.function_symbols("right"))
	left_sym = next(
		(s for s in left_syms if s.name == function_symbol_name),
		left_syms[0] if left_syms else None,
	)
	right_sym = next(
		(s for s in right_syms if s.name == function_symbol_name),
		right_syms[0] if right_syms else None,
	)

	if left_sym is None and right_sym is None:
		empty = '<div class="muted center" style="padding: 18px;">no function symbols</div>'
		return empty, empty, (0, 0, "—", "—")

	left_rows = list(left_sym.instructions) if left_sym else []
	right_rows = list(right_sym.instructions) if right_sym else []
	n = max(len(left_rows), len(right_rows))

	target_html: list[str] = []
	current_html: list[str] = []
	matched = 0
	differs = 0

	for i in range(n):
		lrow = left_rows[i] if i < len(left_rows) else None
		rrow = right_rows[i] if i < len(right_rows) else None
		kind = (
			(lrow.diff_kind if lrow else None)
			or (rrow.diff_kind if rrow else None)
			or DiffKind.NONE
		)
		cls = kind.value.removeprefix("DIFF_").lower()
		glyph = _KIND_GLYPHS.get(kind, " ")

		if kind == DiffKind.NONE:
			matched += 1
		else:
			differs += 1

		# Target column: no marker glyph.
		if lrow is not None and lrow.instruction is not None:
			addr = f"{lrow.instruction.address:x}:" if lrow.instruction.address is not None else ""
			mnem, args = _split_instr(lrow.instruction.formatted)
			target_html.append(
				f'<div class="asm-row {cls}">'
				f'<span class="addr">{addr}</span>'
				f'<span class="mnem">{html.escape(mnem)}</span>'
				f'<span class="args">{html.escape(args)}</span>'
				"</div>"
			)
		else:
			target_html.append(f'<div class="asm-row {cls} empty">&nbsp;</div>')

		# Current column: marker glyph in first column.
		if rrow is not None and rrow.instruction is not None:
			addr = f"{rrow.instruction.address:x}:" if rrow.instruction.address is not None else ""
			mnem, args = _split_instr(rrow.instruction.formatted)
			current_html.append(
				f'<div class="asm-row {cls}">'
				f'<span class="marker">{glyph}</span>'
				f'<span class="addr">{addr}</span>'
				f'<span class="mnem">{html.escape(mnem)}</span>'
				f'<span class="args">{html.escape(args)}</span>'
				"</div>"
			)
		else:
			current_html.append(
				f'<div class="asm-row {cls} empty"><span class="marker">{glyph}</span></div>'
			)

	target_name = left_sym.name if left_sym else "—"
	current_name = right_sym.name if right_sym else "—"
	return (
		"".join(target_html),
		"".join(current_html),
		(matched, differs, target_name, current_name),
	)


def _numbered_c(c_text: str) -> str:
	out = []
	for i, line in enumerate(c_text.splitlines() or [""], start=1):
		out.append(
			f'<span style="display: inline-block; width: 36px; color: var(--fg-faint); '
			f'text-align: right; padding-right: 12px;">{i}</span>{html.escape(line)}'
		)
	return "\n".join(out)


def _progress_bar(value: float | None) -> str:
	pct = value if isinstance(value, (int, float)) else 0.0
	pct = max(0.0, min(100.0, pct))
	label = f"{value:.2f}%" if isinstance(value, (int, float)) else "—"
	return (
		f'<div class="progress">'
		f'<div class="fill" style="width: {pct:.2f}%;"></div>'
		f'<div class="label">{label}</div>'
		f"</div>"
	)


def _attempt_status_labels(attempt: dict, *, is_in_flight: bool) -> tuple[str | None, str, str]:
	"""Pick (mp_label, badge_class, badge_text) for one attempt row.

	Returns (None, _, _) when match_percent is set and the caller should
	render the percentage normally. Otherwise the label distinguishes
	transient mid-iteration states (compiling/diffing) from terminal
	failures (compile failed, diff failed, symbol mismatch).
	"""
	if attempt["match_percent"] is not None:
		return None, "", ""
	if not attempt["compiled"]:
		return (
			("compiling…", "pending", "compiling")
			if is_in_flight
			else ("compile failed", "failed", "compile")
		)
	if not attempt["diff_path"].is_file():
		return (
			("diffing…", "pending", "diffing")
			if is_in_flight
			else ("diff failed", "failed", "diff")
		)
	return "symbol mismatch", "failed", "no match"


def _guess_function_name(root: Path) -> str | None:
	# Recover "fn_<va>" from a "<prefix>_fn_<va>" workspace name.
	name = root.name
	if "_fn_" in name:
		return "fn_" + name.split("_fn_", 1)[1]
	return None


def _run_interrupted(job: JobInfo | None, result: dict | None, attempts: list[dict]) -> bool:
	"""True when a run was orphaned — the model attempted at least once (#0001+ on
	disk) but there's no terminal result.json and no live job tracking it.

	This is the 'server restarted mid-run' case: the daemon thread died, so its
	in-memory JobInfo is gone and the loop never reached _finalize. The attempt
	history and best.c survive on disk, so the run is resumable.
	"""
	if job is not None or result is not None:
		return False
	return any(a["n"] >= 1 for a in attempts)


def _interrupted_banner(root: Path, current_path: str | None) -> str:
	"""Banner for an orphaned run: explain the interruption and offer a Resume
	link to the prefilled launch form. Resume reuses this workspace, so attempt
	numbering continues and best.c is preserved — no progress is thrown away."""
	va = _va_from_workspace(root)
	resume = ""
	if va is not None and current_path:
		href = f"/decomp/launch?path={quote(current_path)}&va={va:#x}"
		resume = f'<a class="resume" href="{href}">resume run →</a>'
	return (
		'<div class="run-banner interrupted">'
		'<span class="badge failed">INTERRUPTED</span>'
		'<span class="muted">run stopped mid-flight (server restarted) · '
		"attempts and best.c preserved on disk</span>"
		f"{resume}"
		"</div>"
	)


def _run_action_bar(root: Path, current_path: str | None, job, *, has_attempts: bool) -> str:
	"""A run / re-run button on the decomp page → the prefilled launch form.

	Hidden while a job is live (the banner already shows progress) or when we
	lack the project path needed to build the launch link. Labelled by history:
	`▶ run` for a fresh function, `↻ re-run` once attempts exist — re-running
	lets another model attack the same workspace.
	"""
	va = _va_from_workspace(root)
	if not current_path or va is None or (job and job.is_active()):
		return ""
	label = "↻ re-run" if has_attempts else "▶ run"
	href = f"/decomp/launch?path={quote(current_path)}&va={va:#x}"
	return f'<div class="run-actions"><a class="btn-run" href="{href}">{label}</a></div>'


def _va_from_workspace(root: Path) -> int | None:
	"""Recover a function's VA from its `fn_<hex>` workspace dir name.

	The dir is keyed by the machine name (never renamed), so the VA is decodable
	straight out of it — the same anchor the symbol map and relink oracle use.
	"""
	m = re.search(r"fn_([0-9A-Fa-f]{8})", root.name)
	return int(m.group(1), 16) if m else None


# ── Whole-game progress views ──────────────────────────────────────────────
def _discover_projects() -> list[tuple[str, str, int]]:
	"""Find project manifests under projects/ and examples/.

	Returns a list of (manifest_path_str, project_name, function_count)
	tuples. Skips manifests that fail to load. Cheap enough to redo on
	every index render — there will rarely be more than a handful.
	"""
	found: list[tuple[str, str, int]] = []
	seen: set[Path] = set()
	for root in (REPO_ROOT / "projects", REPO_ROOT / "examples"):
		if not root.is_dir():
			continue
		for manifest in sorted(root.glob("*/project.json")):
			seen.add(manifest)
		for manifest in sorted(root.glob("*.project.json")):
			seen.add(manifest)
	for manifest in sorted(seen):
		try:
			project = project_load(manifest)
			found.append((str(manifest), project.name, len(project.functions)))
		except Exception:  # noqa: BLE001, S112 — malformed manifests just get skipped
			continue
	return found


def view_progress_index(current_path: str | None) -> str:
	projects = _discover_projects()
	if projects:
		rows = "".join(
			f"<tr>"
			f'<td><a href="/progress?path={quote(path)}">{html.escape(name)}</a></td>'
			f'<td class="num">{count:,} fns</td>'
			f'<td class="muted">{html.escape(path)}</td>'
			f"</tr>"
			for path, name, count in projects
		)
		recent = panel(
			"Detected projects",
			f"<table><thead><tr><th>name</th><th>size</th><th>path</th></tr></thead>"
			f"<tbody>{rows}</tbody></table>",
			meta=f"{len(projects)} found · scans projects/ and examples/",
		)
	else:
		recent = ""

	open_form = panel(
		"Open project",
		"""
<form class="inline" action="/progress" method="get">
  <input type="text" name="path" placeholder="/path/to/project.json"{autofocus}>
  <button type="submit">Aggregate →</button>
</form>
<p class="muted" style="margin-top: 12px;">
  Point at a <span style="color: var(--cyan);">project.json</span> manifest.
  Generate one with <span style="color: var(--cyan);">scripts/enumerate.py</span>.
</p>
""".replace("{autofocus}", " autofocus" if not projects else ""),
	)
	body = crumbs(("home", "/"), ("progress", None)) + recent + open_form
	return page("progress", body, current_path=current_path)


def _sweep_section(project_path_str: str, stats: ProjectStats) -> tuple[str, bool]:
	"""Render the Ghidra-attempt-all control. Returns (panel_html, is_active).

	Active → a live progress banner + bar + stop button (the caller turns on
	auto-refresh). Idle → a launch button sized by the untouched count, plus a
	one-line summary of the previous sweep if one ran this server session.
	"""
	sweep = _sweep_for(project_path_str)
	active = sweep is not None and sweep.is_active()
	untouched = stats.untouched_functions
	path_q = quote(project_path_str)

	if active and sweep is not None:
		pct = (sweep.done / sweep.total * 100.0) if sweep.total else 100.0
		current = (
			f' · <span class="muted">at {html.escape(sweep.current)}</span>'
			if sweep.current
			else ""
		)
		body = (
			'<div class="run-banner sweeping">'
			'<span class="badge pending">SWEEPING</span>'
			f'<span class="sweep-counts">{sweep.done}/{sweep.total} · '
			f'<span class="green">{sweep.matched} matched</span> · '
			f"{sweep.partial} partial · {sweep.failed} failed</span>"
			f"{current}"
			f'<form class="inline sweep-stop" method="post" action="/sweep/stop?path={path_q}">'
			'<button type="submit">stop</button></form>'
			"</div>"
			f'<div class="sweep-bar"><div class="sweep-bar-fill" '
			f'style="width:{pct:.1f}%"></div></div>'
		)
		return panel("Ghidra sweep", body, meta=f"{pct:.0f}% · serial baseline pass"), True

	finished = ""
	if sweep is not None and not active:
		if sweep.state == "error":
			finished = (
				f'<p class="muted tight" style="margin-top:10px;">last sweep errored: '
				f"{html.escape(sweep.error or '')}</p>"
			)
		else:
			verb = "stopped" if sweep.state == "stopped" else "finished"
			finished = (
				f'<p class="muted tight" style="margin-top:10px;">last sweep {verb}: '
				f"{sweep.done}/{sweep.total} done · "
				f'<span class="green">{sweep.matched} matched</span> · '
				f"{sweep.partial} partial · {sweep.failed} failed</p>"
			)

	if untouched == 0:
		button = '<p class="muted">every function has a baseline — nothing untouched to sweep.</p>'
	else:
		button = (
			f'<form class="inline" method="post" action="/sweep/launch?path={path_q}">'
			'<button type="submit" class="btn-run">⚡ Ghidra attempt all</button>'
			f'<span class="muted" style="margin-left:10px;">{untouched:,} untouched · '
			"compiles each Ghidra warm-start, no LLM</span></form>"
		)
	return panel("Ghidra sweep", button + finished), False


def _autoname_section(project_path_str: str, named: int | None) -> str:
	"""The project-wide 'auto-name from strings' control + last-run notice.

	`named` is the count from a just-completed run (via the ?named= redirect),
	or None when the page wasn't reached from an auto-name."""
	path_q = quote(project_path_str)
	notice = ""
	if named is not None and named > 0:
		notice = (
			'<div class="run-banner done"><span class="badge matched">NAMED</span>'
			f'<span>auto-named <span class="green">{named}</span> '
			f"function{'s' if named != 1 else ''} from referenced strings</span></div>"
		)
	elif named is not None:
		notice = (
			'<div class="run-banner"><span class="badge pending">—</span>'
			'<span class="muted">no new high-confidence names found</span></div>'
		)
	button = (
		f'<form class="inline" method="post" action="/autoname?path={path_q}">'
		'<button type="submit" class="btn-run">✎ Auto-name stubs from strings</button>'
		'<span class="muted" style="margin-left:10px;">names tiny functions whose single '
		"referenced string is unambiguous · clean-room, re-runnable</span></form>"
	)
	return panel("Auto-name", notice + button)


def view_progress(
	project_path_str: str,
	current_path: str | None,
	*,
	page_n: int = 1,
	page_size: int = 100,
	filters: dict[str, str] | None = None,
	named: int | None = None,
) -> str:
	project = project_load(project_path_str)
	stats = project_aggregate(project, sdk_vas=_sdk_vas_for(project_path_str))
	symbols = symbol_map_load(project_path_str)
	filters = filters or {}

	all_statuses = list(stats.function_statuses)
	filtered = _apply_filters(all_statuses, filters, symbols)
	filtered = _apply_sort(filtered, filters.get("sort", "va"), filters.get("order", "asc"))

	total_unfiltered = stats.total_functions
	total = len(filtered)
	total_pages = max(1, (total + page_size - 1) // page_size)
	page_n = max(1, min(page_n, total_pages))
	start = (page_n - 1) * page_size
	page_slice = filtered[start : start + page_size]

	summary = _progress_summary(project, stats)
	histogram = _progress_histogram(stats)
	filter_bar = _progress_filter_bar(project_path_str, filters, page_size, total, total_unfiltered)
	table = _progress_function_table(
		page_slice,
		project_path_str,
		symbols=symbols,
		page=page_n,
		total_pages=total_pages,
		total=total,
		page_size=page_size,
		filters=filters,
	)

	sweep_html, sweep_active = _sweep_section(project_path_str, stats)

	rng = f"{start + 1}–{min(start + page_size, total)} of {total}" if total else "0 of 0"
	body = (
		crumbs(("home", "/"), ("progress", "/progress"), (project.name, None))
		+ f'<div class="page-actions"><a href="/stats?path={quote(project_path_str)}">'
		"📊 model stats →</a></div>"
		+ panel(
			"Project", summary, meta=f"{total_unfiltered} functions · {stats.total_bytes:,} bytes"
		)
		+ sweep_html
		+ _autoname_section(project_path_str, named)
		+ panel("Match distribution", histogram, meta="function count per 10% bucket")
		+ panel("Functions", filter_bar + table, meta=f"{rng} · page {page_n}/{total_pages}")
	)
	# Refresh only while the sweep is live; server drops data-live to stop the poller.
	refresh = 4 if sweep_active else None
	return page(
		f"progress · {project.name}", body, current_path=current_path, refresh_seconds=refresh
	)


def _model_stats_table(rows: list) -> str:
	"""Per-model leaderboard table. Each model is credited for the functions
	whose best.c it currently owns."""
	if not rows:
		return (
			'<div class="muted center" style="padding: 18px;">'
			"no model attributions yet — run a function to populate this</div>"
		)
	body_rows = []
	for r in rows:
		win_pct = (r.matched / r.functions * 100.0) if r.functions else 0.0
		body_rows.append(
			"<tr>"
			f'<td><span class="cyan">{html.escape(r.model)}</span></td>'
			f'<td class="num">{r.functions}</td>'
			f'<td class="num green">{r.matched}</td>'
			f'<td class="num">{r.partial}</td>'
			f'<td class="num">{win_pct:.0f}%</td>'
			f'<td class="num">{r.avg_best_percent:.2f}%</td>'
			"</tr>"
		)
	return (
		"<table>"
		"<thead><tr>"
		"<th>model</th><th>functions</th><th>matched</th><th>partial</th>"
		"<th>match rate</th><th>avg best</th>"
		"</tr></thead>"
		f"<tbody>{''.join(body_rows)}</tbody>"
		"</table>"
		'<p class="muted tight" style="margin-top: 10px;">'
		"A model is credited for a function when its attempt produced the standing "
		"best.c. Re-running with another model reassigns credit only if it beats the "
		'current best. <span class="cyan">propagated</span> = byte-identical twins '
		'auto-finished from a solved representative; <span class="cyan">ghidra</span> '
		"= matched straight from the warm-start.</p>"
	)


def _workspace_attempt_triples(root: Path) -> list[tuple[int, str | None, float | None]]:
	"""(attempt_number, model, match_percent) for one workspace's attempts.

	Reads only what's on disk (no objdiff derivation) so a whole-project scan
	stays cheap — the diff JSON already exists for any attempt that ran."""
	return [
		(a["n"], a["model"], a["match_percent"])
		for a in _attempts_listing(root, derive_missing=False)
	]


def _model_attempt_table(rows: list) -> str:
	"""Per-model effort table: attempts spent vs. attempts that moved the needle."""
	if not rows:
		return '<div class="muted center" style="padding: 18px;">no per-attempt history yet</div>'
	body_rows = [
		(
			"<tr>"
			f'<td><span class="cyan">{html.escape(r.model)}</span></td>'
			f'<td class="num">{r.attempts}</td>'
			f'<td class="num">{r.improved}</td>'
			f'<td class="num green">{r.matched}</td>'
			f'<td class="num">{r.improve_rate:.0f}%</td>'
			"</tr>"
		)
		for r in rows
	]
	return (
		"<table>"
		"<thead><tr>"
		"<th>model</th><th>attempts</th><th>improved</th><th>100% hits</th><th>improve rate</th>"
		"</tr></thead>"
		f"<tbody>{''.join(body_rows)}</tbody>"
		"</table>"
		'<p class="muted tight" style="margin-top: 10px;">'
		'Counted from the per-attempt <span class="cyan">.model</span> sidecars. '
		"<b>attempts</b> = compiles tagged to the model; <b>improved</b> = those that "
		"raised the function's running best; <b>improve rate</b> = improved ÷ attempts "
		"(efficiency — a model can win few functions cheaply or many by grinding).</p>"
	)


def _image_coverage_table(cov) -> str:
	"""Per-section whole-image byte breakdown: how much of each section (code and
	data) is reconstructed from source vs. carried verbatim as a gap."""
	rows = []
	for s in sorted(cov.sections, key=lambda s: -s.virtual_size):
		pct = (s.matched_bytes / s.virtual_size * 100.0) if s.virtual_size else 0.0
		# Classify by whether we enumerated functions here, NOT the exec flag —
		# this XBE marks .rdata/.data executable, so the flag lies (see docs).
		kind = "code" if s.enumerated_bytes else "data"
		rows.append(
			"<tr>"
			f"<td>{html.escape(s.name)}</td>"
			f'<td class="muted">{kind}</td>'
			f'<td class="num">{s.virtual_size:,}</td>'
			f'<td class="num green">{s.matched_bytes:,}</td>'
			f'<td class="num">{pct:.1f}%</td>'
			f'<td class="num muted">{s.gap_bytes:,}</td>'
			"</tr>"
		)
	return (
		"<table>"
		"<thead><tr><th>section</th><th>kind</th><th>size</th>"
		"<th>from source</th><th>%</th><th>gap / verbatim</th></tr></thead>"
		f"<tbody>{''.join(rows)}</tbody></table>"
		'<p class="muted tight" style="margin-top: 10px;">'
		"<b>from source</b> = bytes of matched functions (reconstructed C). "
		"<b>gap / verbatim</b> = padding, data, jump tables, and un-matched code — "
		"carried from the original, not yet from source. Data sections are entirely gap.</p>"
	)


def _verify_buttons(project_path_str: str) -> str:
	"""Two run buttons: splice (our relocator) and relink (real XDK Link.Exe)."""
	path_q = quote(project_path_str)
	return (
		'<div class="hint-row" style="margin-top:10px;">'
		f'<form class="hint-form" method="post" action="/verify/launch?path={path_q}&method=splice">'
		'<button type="submit" class="btn-run">▶ verify (splice)</button></form>'
		f'<form class="hint-form" method="post" action="/verify/launch?path={path_q}&method=relink">'
		'<button type="submit" class="btn-run">▶ relink (Link.Exe)</button></form>'
		'<span class="muted">recompiles every matched function · needs Wine + toolchain</span>'
		"</div>"
	)


def _verify_panel(project_path_str: str) -> tuple[str, bool]:
	"""(panel_html, is_active). Live progress while a verify job runs; otherwise
	the cached result (or a prompt) plus run buttons. The oracle recompiles every
	matched function, so it's a background job — never computed on a page render."""
	job = _verify_for(project_path_str)
	if job is not None and job.is_active():
		pct = (job.done / job.total * 100.0) if job.total else 100.0
		current = (
			f' · <span class="muted">at {html.escape(job.current)}</span>' if job.current else ""
		)
		body = (
			'<div class="run-banner sweeping">'
			'<span class="badge pending">VERIFYING</span>'
			f'<span class="sweep-counts">{job.done}/{job.total} matched functions · '
			f"{html.escape(job.method)}</span>{current}</div>"
			f'<div class="sweep-bar"><div class="sweep-bar-fill" style="width:{pct:.1f}%"></div></div>'
		)
		return panel("Relink-verified", body, meta=f"{pct:.0f}% · recompiling + relinking"), True

	failed_note = ""
	if job is not None and job.state == "error":
		failed_note = (
			f'<p class="muted tight">last verify errored: {html.escape(job.error or "")}</p>'
		)

	cache = image_verify_cache_load(project_path_str)
	if cache is None:
		body = (
			'<p class="muted">Not yet computed — recompiles every matched function '
			"(needs Wine + the toolchain). Run it as a background job:</p>"
			f"{_verify_buttons(project_path_str)}{failed_note}"
		)
		return panel("Relink-verified", body), False

	pct = cache.get("verified_percent", 0.0)
	age = ""
	gen = cache.get("generated_at")
	if isinstance(gen, (int, float)):
		secs = max(0, int(time.time() - gen))
		age = f" · {secs // 3600}h{(secs % 3600) // 60}m ago" if secs >= 60 else " · just now"
	body = (
		'<div class="kv">'
		'<div class="k">verified</div>'
		f'<div class="v green">{cache.get("verified_bytes", 0):,} / '
		f"{cache.get('matched_bytes', 0):,} matched bytes ({pct:.1f}%)</div>"
		'<div class="k">functions</div>'
		f'<div class="v">{cache.get("functions_verified", 0)} / '
		f"{cache.get('functions', 0)} fully reproduced</div>"
		'<div class="k">method</div>'
		f'<div class="v">{html.escape(str(cache.get("method", "?")))}{age}</div>'
		"</div>"
		f"{_progress_bar(pct)}"
		'<p class="muted tight" style="margin-top:8px;">Matched functions recompiled, '
		"placed at their real VA, and byte-compared against the original image.</p>"
		f"{_verify_buttons(project_path_str)}{failed_note}"
	)
	return panel("Relink-verified", body), False


def view_stats(project_path_str: str) -> str:
	"""Per-model performance leaderboard for one project."""
	project = project_load(project_path_str)
	sdk_vas = _sdk_vas_for(project_path_str)
	stats = project_aggregate(project, sdk_vas=sdk_vas)
	rows = model_stats(stats.function_statuses)
	attempt_rows = model_attempt_stats(
		[_workspace_attempt_triples(s.workspace_path) for s in stats.function_statuses]
	)
	parsed = xbe_cached_load(str(project.xbe_path))
	cov = image_coverage(stats.function_statuses, parsed, sdk_vas=sdk_vas)

	attributed = sum(r.functions for r in rows)
	meta = f"{attributed} of {stats.game_functions:,} game functions attributed to a model"
	total_attempts = sum(r.attempts for r in attempt_rows)
	cov_meta = (
		f"{cov.matched_bytes:,} / {cov.total_bytes:,} bytes from source "
		f"({cov.from_source_percent:.1f}% of the whole image)"
	)
	verify_html, verify_active = _verify_panel(project_path_str)
	body = (
		crumbs(
			("home", "/"),
			("progress", "/progress"),
			(project.name, _progress_link(project_path_str)),
		)
		+ panel("Models — who won", _model_stats_table(rows), meta=meta)
		+ panel(
			"Models — effort per attempt",
			_model_attempt_table(attempt_rows),
			meta=f"{total_attempts:,} attempts across all functions",
		)
		+ panel(
			"Whole-image reconstruction",
			_image_budget_summary(cov) + _image_coverage_table(cov),
			meta=cov_meta,
		)
		+ verify_html
	)
	refresh = 4 if verify_active else None
	return page(f"stats · {project.name}", body, current_path=None, refresh_seconds=refresh)


def _image_budget_summary(cov) -> str:
	"""A one-line byte budget that separates the gap into 'code still to do' vs.
	'data/assets carried verbatim' — so a tiny from-source % reads as 'barely
	started decompiling', not 'barely reproduces'."""
	data_other = cov.gap_bytes
	cells = [
		("from source", cov.matched_bytes, "green"),
		("in progress", cov.partial_bytes, "amber"),
		("code to do", cov.todo_code_bytes, ""),
		("SDK (linked)", cov.sdk_bytes, "cyan"),
		("data / assets", data_other, "muted"),
	]
	spans = " · ".join(f'<span class="{cls}">{label}</span> {val:,}' for label, val, cls in cells)
	return (
		f'<p class="tight" style="margin-bottom:10px;">{spans}'
		f" &nbsp;=&nbsp; {cov.total_bytes:,} B total</p>"
	)


def _progress_link(project_path_str: str) -> str:
	return f"/progress?path={quote(project_path_str)}"


_STATE_SORT_ORDER = {"matched": 0, "partial": 1, "untouched": 2}


def _apply_filters(statuses: list, f: dict[str, str], symbols=None) -> list:
	out = statuses
	state = f.get("state") or ""
	if state in ("matched", "partial", "untouched"):
		out = [s for s in out if s.state == state]
	query = (f.get("q") or "").strip().lower()
	if query:
		# Match machine name or human label so search finds either.
		def hit(s) -> bool:
			label = symbols.label_for(s.va).lower() if symbols else ""
			return query in s.name.lower() or query in label

		out = [s for s in out if hit(s)]
	try:
		min_size = int(f.get("min_size") or "")
		out = [s for s in out if s.size >= min_size]
	except ValueError:
		pass
	try:
		max_size = int(f.get("max_size") or "")
		out = [s for s in out if s.size <= max_size]
	except ValueError:
		pass
	return out


def _apply_sort(statuses: list, sort_key: str, order: str) -> list:
	reverse = order == "desc"

	def keyer(s):
		if sort_key == "name":
			return s.name
		if sort_key == "size":
			return s.size
		if sort_key == "best":
			return s.best_match_percent if s.best_match_percent is not None else -1.0
		if sort_key == "iters":
			return s.iterations
		if sort_key == "state":
			return _STATE_SORT_ORDER.get(s.state, 99)
		return s.va  # default: VA

	return sorted(statuses, key=keyer, reverse=reverse)


def _progress_filter_bar(
	project_path_str: str,
	f: dict[str, str],
	page_size: int,
	total_filtered: int,
	total_unfiltered: int,
) -> str:
	def opt(value: str, label: str, selected: str) -> str:
		sel = " selected" if value == selected else ""
		return f'<option value="{value}"{sel}>{label}</option>'

	state_sel = f.get("state", "")
	sort_sel = f.get("sort", "va")
	order_sel = f.get("order", "asc")

	state_options = "".join(
		opt(v, label, state_sel)
		for v, label in (
			("", "all"),
			("matched", "matched"),
			("partial", "partial"),
			("untouched", "untouched"),
		)
	)
	sort_options = "".join(
		opt(v, label, sort_sel)
		for v, label in (
			("va", "VA"),
			("name", "name"),
			("size", "size"),
			("best", "best %"),
			("iters", "iters"),
			("state", "state"),
		)
	)
	order_options = "".join(
		opt(v, label, order_sel)
		for v, label in (
			("asc", "↑ asc"),
			("desc", "↓ desc"),
		)
	)

	count_chip = (
		f'<span class="muted">{total_filtered:,} match'
		+ (f" · {total_unfiltered:,} total" if total_filtered != total_unfiltered else "")
		+ "</span>"
	)

	return f"""
<form class="filter-bar" method="get" action="/progress">
  <input type="hidden" name="path"      value="{html.escape(project_path_str)}">
  <input type="hidden" name="page_size" value="{page_size}">
  <label>state <select name="state">{state_options}</select></label>
  <label>name contains <input type="text" name="q" value="{html.escape(f.get("q", ""))}" placeholder="fn_002D"></label>
  <label>size <input type="number" name="min_size" value="{html.escape(f.get("min_size", ""))}" placeholder="min" min="0">
    <span class="muted">–</span>
    <input type="number" name="max_size" value="{html.escape(f.get("max_size", ""))}" placeholder="max" min="0"></label>
  <label>sort <select name="sort">{sort_options}</select> <select name="order">{order_options}</select></label>
  <button type="submit">apply</button>
  <a href="/progress?path={quote(project_path_str)}" class="clear-filters">clear</a>
  {count_chip}
</form>
"""


_SDK_SWATCH = "#5b7da6"  # distinct from the matched/partial/untouched scale


def _sdk_vas_for(project_path_str: str) -> frozenset[int]:
	"""Load the SDK manifest sitting next to project.json (scripts/libmatch.py
	--save), if present. Empty otherwise → progress is reported over the whole image."""
	sdk_path = Path(project_path_str).parent / "sdk.json"
	return frozenset(sdk_manifest_load(sdk_path)) if sdk_path.is_file() else frozenset()


def _progress_summary(project: Project, stats: ProjectStats) -> str:
	m = stats.matched_functions
	p = stats.partial_functions
	u = stats.untouched_functions
	sdk = stats.sdk_functions
	total = stats.total_functions or 1
	# Bar spans the whole image; progress % below is measured against the game target (image minus SDK).
	game = stats.game_functions or 1

	seg_html = []
	for label, count, cls, inline in (
		("matched", m, "seg-matched", ""),
		("partial", p, "seg-partial", ""),
		("untouched", u, "seg-untouched", ""),
		("sdk", sdk, "", f"background:{_SDK_SWATCH};"),
	):
		pct = count / total * 100
		if pct <= 0:
			continue
		text = f"{label} {count}" if pct > 7 else ""
		cls_attr = f' class="{cls}"' if cls else ""
		seg_html.append(f'<div{cls_attr} style="flex: {pct:.4f};{inline}">{text}</div>')

	bar = '<div class="stacked-bar">' + "".join(seg_html) + "</div>"
	legend_items = [
		f'<span><span class="swatch matched"></span>matched · {m} ({m / game * 100:.1f}%)</span>',
		f'<span><span class="swatch partial"></span>partial · {p} ({p / game * 100:.1f}%)</span>',
		f'<span><span class="swatch untouched"></span>untouched · {u} ({u / game * 100:.1f}%)</span>',
	]
	if sdk:
		legend_items.append(
			f'<span><span class="swatch" style="background:{_SDK_SWATCH};"></span>'
			f"SDK · {sdk} (linked, not a target)</span>"
		)
	legend = '<div class="legend">' + "".join(legend_items) + "</div>"

	sdk_row = ""
	if sdk:
		sdk_row = (
			'  <div class="k">SDK (XDK, excluded)</div>'
			f'  <div class="v" style="color:{_SDK_SWATCH};">{sdk:,} functions / '
			f"{stats.sdk_bytes:,} bytes</div>\n"
		)

	return f"""
<div class="kv">
  <div class="k">name</div>           <div class="v amber">{html.escape(project.name)}</div>
  <div class="k">xbe</div>            <div class="v">{html.escape(str(project.xbe_path))}</div>
  <div class="k">workspaces</div>     <div class="v">{html.escape(str(project.workspace_root))}</div>
  <div class="k">game target</div>    <div class="v">{stats.game_functions:,} functions / {stats.game_bytes:,} bytes</div>
{sdk_row}  <div class="k">functions matched</div><div class="v green">{m} / {stats.game_functions}  ({m / game * 100:.2f}%)</div>
  <div class="k">bytes matched</div>  <div class="v green">{stats.matched_bytes:,} / {stats.game_bytes:,}  ({stats.game_matched_byte_percent:.2f}%)</div>
</div>
{bar}
{legend}
"""


def _progress_histogram(stats: ProjectStats) -> str:
	if stats.total_functions == 0:
		return '<div class="muted center" style="padding: 18px;">empty project</div>'

	# 11 buckets: 0% (untouched), 1-10, 11-20, ..., 91-100
	buckets = [0] * 11
	for s in stats.function_statuses:
		bp = s.best_match_percent
		if bp is None or bp <= 0.0:
			buckets[0] += 1
		elif bp >= 100.0:
			buckets[10] += 1
		else:
			idx = int(bp // 10) + 1
			buckets[min(idx, 10)] += 1

	max_count = max(buckets) or 1
	width = 800
	height = 160
	pad_l = 36
	pad_b = 28
	pad_t = 8
	pad_r = 8
	bar_area_w = width - pad_l - pad_r
	bar_area_h = height - pad_t - pad_b
	n_buckets = len(buckets)
	bar_w = bar_area_w / n_buckets

	bars = []
	labels = []
	for i, count in enumerate(buckets):
		if count == 0:
			continue
		h = (count / max_count) * bar_area_h
		x = pad_l + i * bar_w + 2
		y = pad_t + (bar_area_h - h)
		if i == 0:
			color = "var(--fg-faint)"
		elif i == 10:
			color = "var(--green)"
		elif i >= 7:
			color = "var(--amber)"
		else:
			color = "var(--cyan)"
		bars.append(
			f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w - 4:.1f}" height="{h:.1f}" '
			f'fill="{color}" opacity="0.85"/>'
		)
		bars.append(
			f'<text x="{x + (bar_w - 4) / 2:.1f}" y="{y - 4:.1f}" '
			f'fill="var(--fg)" font-size="10" text-anchor="middle">{count}</text>'
		)

	bucket_labels = [
		"0",
		"1-10",
		"11-20",
		"21-30",
		"31-40",
		"41-50",
		"51-60",
		"61-70",
		"71-80",
		"81-90",
		"91-100",
	]
	for i, lbl in enumerate(bucket_labels):
		cx = pad_l + i * bar_w + bar_w / 2
		labels.append(
			f'<text x="{cx:.1f}" y="{height - 10:.1f}" '
			f'fill="var(--fg-faint)" font-size="9" text-anchor="middle">{lbl}</text>'
		)

	# Y-axis ticks at 0, max/2, max
	y_ticks = []
	for v in (0, max_count // 2, max_count):
		y = pad_t + bar_area_h - (v / max_count * bar_area_h)
		y_ticks.append(
			f'<text x="{pad_l - 6:.1f}" y="{y + 3:.1f}" '
			f'fill="var(--fg-faint)" font-size="9" text-anchor="end">{v}</text>'
		)
		y_ticks.append(
			f'<line x1="{pad_l:.1f}" y1="{y:.1f}" x2="{width - pad_r:.1f}" y2="{y:.1f}" '
			f'stroke="rgba(180,196,212,0.06)"/>'
		)

	return (
		f'<svg class="hist" viewBox="0 0 {width} {height}" preserveAspectRatio="none">'
		+ "".join(y_ticks)
		+ "".join(bars)
		+ "".join(labels)
		+ '<text x="'
		+ str(pad_l)
		+ '" y="'
		+ str(height - 2)
		+ '" '
		'fill="var(--fg-faint)" font-size="9">match %</text>' + "</svg>"
	)


_PROVENANCE_TAG = {
	"user": '<span class="prov user" title="renamed by you">✎</span>',
	"sdk": '<span class="prov sdk" title="XDK library name (libmatch)">SDK</span>',
}


def _name_cell(s, symbols) -> str:
	"""Render the function name column: the human label up front, the machine
	`fn_<va>` name underneath when they differ, plus a provenance tag."""
	if symbols is None:
		return html.escape(s.name)
	label = symbols.label_for(s.va)
	provenance = symbols.provenance(s.va)
	tag = _PROVENANCE_TAG.get(provenance, "")
	if label == s.name:  # not renamed
		return html.escape(s.name)
	return (
		f'<span class="fn-label">{html.escape(label)}</span> {tag}'
		f'<div class="muted tight mono">{html.escape(s.name)}</div>'
	)


def _progress_function_table(
	page_slice,
	project_path_str: str,
	*,
	symbols=None,
	page: int,
	total_pages: int,
	total: int,
	page_size: int,
	filters: dict[str, str] | None = None,
) -> str:
	rows = []
	for s in page_slice:
		best_str = (
			f"{s.best_match_percent:.2f}%"
			if isinstance(s.best_match_percent, (int, float))
			else "—"
		)
		job = _job_for(s.workspace_path)
		if job and job.is_active():
			state_label = '<span class="fn-state partial">running</span>'
			action = (
				f'<a href="/decomp/run?root={html.escape(str(s.workspace_path))}'
				f'&amp;path={quote(project_path_str)}">iter {job.iterations_completed}/{job.max_iterations} →</a>'
			)
		else:
			state_label = f'<span class="fn-state {s.state}">{s.state}</span>'
			if s.state != "untouched" or s.iterations > 0:
				action = (
					f'<a href="/decomp/run?root={html.escape(str(s.workspace_path))}'
					f'&amp;path={quote(project_path_str)}">view →</a>'
					f'  <a href="/decomp/launch?path={quote(project_path_str)}'
					f'&amp;va={s.va:#x}" class="action-rerun">↻ rerun</a>'
				)
			else:
				action = (
					f'<a href="/decomp/launch?path={quote(project_path_str)}'
					f'&amp;va={s.va:#x}">▶ run</a>'
				)
		model = s.model or (job.model if job else "") or ""
		rows.append(
			f"<tr>"
			f"<td>{_name_cell(s, symbols)}</td>"
			f'<td class="num">0x{s.va:08x}</td>'
			f'<td class="size">{s.size}</td>'
			f"<td>{state_label}</td>"
			f"<td>{best_str}</td>"
			f'<td class="num">{s.iterations}</td>'
			f'<td class="muted">{html.escape(model)}</td>'
			f"<td>{action}</td>"
			f"</tr>"
		)

	pager = _progress_pager(
		project_path_str,
		page=page,
		total_pages=total_pages,
		total=total,
		page_size=page_size,
		filters=filters or {},
	)
	empty_msg = (
		"no functions match these filters" if filters and any(filters.values()) else "empty project"
	)
	return (
		"<table>"
		"<thead><tr>"
		"<th>name</th><th>VA</th><th>size</th><th>state</th>"
		"<th>best</th><th>iters</th><th>model</th><th></th>"
		"</tr></thead>"
		f"<tbody>{''.join(rows) or f'<tr><td colspan=8 class="muted center">{empty_msg}</td></tr>'}</tbody>"
		"</table>" + pager
	)


def _progress_pager(
	project_path_str: str,
	*,
	page: int,
	total_pages: int,
	total: int,
	page_size: int,
	filters: dict[str, str] | None = None,
) -> str:
	if total_pages <= 1:
		return ""

	filter_qs = _filters_to_qs(filters or {})

	def link(p: int, label: str, cls: str = "") -> str:
		qs = f"path={quote(project_path_str)}&page={p}&page_size={page_size}" + filter_qs
		if cls:
			return f'<a href="/progress?{qs}" class="{cls}">{label}</a>'
		return f'<a href="/progress?{qs}">{label}</a>'

	pages: list[str] = []
	if page > 1:
		pages.append(link(1, "« first"))
		pages.append(link(page - 1, "‹ prev"))
	else:
		pages.append('<span class="pg-disabled">« first</span>')
		pages.append('<span class="pg-disabled">‹ prev</span>')

	window = _pager_window(page, total_pages)
	last = 0
	for p in window:
		if last and p > last + 1:
			pages.append('<span class="pg-ellipsis">…</span>')
		if p == page:
			pages.append(f'<span class="pg-cur">{p}</span>')
		else:
			pages.append(link(p, str(p)))
		last = p

	if page < total_pages:
		pages.append(link(page + 1, "next ›"))
		pages.append(link(total_pages, "last »"))
	else:
		pages.append('<span class="pg-disabled">next ›</span>')
		pages.append('<span class="pg-disabled">last »</span>')

	hidden_filters = "".join(
		f'<input type="hidden" name="{k}" value="{html.escape(v)}">'
		for k, v in (filters or {}).items()
		if v
	)
	jump = (
		f'<form class="pg-jump" method="get" action="/progress">'
		f'<input type="hidden" name="path" value="{html.escape(project_path_str)}">'
		f'<input type="hidden" name="page_size" value="{page_size}">'
		f"{hidden_filters}"
		f'<span class="muted">jump</span>'
		f'<input type="number" name="page" min="1" max="{total_pages}" value="{page}">'
		f"</form>"
	)

	return (
		f'<div class="pager">'
		f'<span class="muted">{total:,} entries · page {page}/{total_pages} · {page_size}/page</span>'
		f'<div class="pages">{"".join(pages)}</div>'
		f"{jump}"
		f"</div>"
	)


def _filters_to_qs(filters: dict[str, str]) -> str:
	"""Encode active filter values as `&key=value` pairs for pagination links."""
	out = []
	for k, v in filters.items():
		if v:
			out.append(f"&{k}={quote(str(v))}")
	return "".join(out)


def _pager_window(page: int, total_pages: int, radius: int = 2) -> list[int]:
	"""Return sorted page numbers to display: always first/last plus a window around current."""
	pages = {1, total_pages, page}
	for d in range(1, radius + 1):
		if page - d >= 1:
			pages.add(page - d)
		if page + d <= total_pages:
			pages.add(page + d)
	return sorted(pages)


def view_launch_form(project_path_str: str, va_str: str) -> str:
	project = project_load(project_path_str)
	va = int(va_str, 0)
	fn = next((f for f in project.functions if f.va == va), None)
	if fn is None:
		return view_error(f"function VA {va:#x} not in {project.name}")

	workspace_path = project.workspace_for(fn)
	existing_job = _job_for(workspace_path)
	api_key_set = bool(os.environ.get("ANTHROPIC_API_KEY"))
	active = len(_active_jobs())

	warnings = []
	if not api_key_set:
		warnings.append(
			'<div class="error">ANTHROPIC_API_KEY is not set in the server\'s '
			"environment. Restart the web UI with it exported.</div>"
		)
	if active >= _MAX_CONCURRENT_JOBS:
		warnings.append(
			f'<div class="error">already at capacity: {active}/'
			f"{_MAX_CONCURRENT_JOBS} concurrent jobs. Wait for one to finish "
			f"or raise IVCS_MAX_CONCURRENT_JOBS.</div>"
		)
	if existing_job and existing_job.is_active():
		warnings.append(
			f'<div class="error">a job is already running for this workspace '
			f"(state: {existing_job.state}, iter {existing_job.iterations_completed}"
			f"/{existing_job.max_iterations}).</div>"
		)

	can_launch = (
		api_key_set
		and active < _MAX_CONCURRENT_JOBS
		and not (existing_job and existing_job.is_active())
	)

	# Surface existing on-disk state so the user knows what they'd overwrite.
	existing_attempts = []
	if (workspace_path / "history").is_dir():
		existing_attempts = sorted(int(p.stem) for p in (workspace_path / "history").glob("*.c"))
	existing_result = json_load_or_none(workspace_path / "result.json")
	existing_state_html = ""
	ctx_h_exists = (workspace_path / "ctx.h").is_file()
	if existing_attempts or existing_result or ctx_h_exists:
		best = (existing_result or {}).get("best_match_percent")
		best_str = f"{best:.2f}%" if isinstance(best, (int, float)) else "—"
		reason = (existing_result or {}).get("termination_reason") or "no result.json"
		existing_state_html = f"""
<div class="rerun-notice">
  <span class="badge partial">PRIOR RUN</span>
  <span>attempts on disk: <span class="amber">{len(existing_attempts)}</span>
        · best: <span class="green">{best_str}</span>
        · last reason: <span class="cyan">{html.escape(reason)}</span></span>
</div>
<label class="kv-checkbox">
  <input type="checkbox" name="wipe_history" value="1">
  wipe history before running (clears attempts, result.json, best.c; keeps ctx.h)
</label>
<label class="kv-checkbox">
  <input type="checkbox" name="reset_ctx_h" value="1"{" disabled" if not ctx_h_exists else ""}>
  regenerate ctx.h from auto-stub (discards hand-edits; uses current launcher rules)
</label>
"""

	model_choices = (
		("claude-haiku-4-5", "claude-haiku-4-5"),
		("claude-sonnet-4-6", "claude-sonnet-4-6"),
		("claude-opus-4-7", "claude-opus-4-7"),
		("local", "local (LM Studio)"),
		("ghidra", "ghidra"),
	)
	model_options = "".join(
		f'<option value="{value}"{" selected" if value == "claude-haiku-4-5" else ""}>{label}</option>'
		for value, label in model_choices
	)

	warmstart_exists = (workspace_path / "ghidra_warmstart.c").is_file()
	warmstart_label = (
		"use Ghidra warm-start (cached)"
		if warmstart_exists
		else "use Ghidra warm-start (adds ~3s; first XBE bootstrap costs ~100s)"
	)
	warmstart_html = f"""
<label class="kv-checkbox">
  <input type="checkbox" name="use_ghidra_warmstart" value="1">
  {warmstart_label}
</label>
"""

	launch_label = "▶ re-run" if existing_attempts else "▶ launch"

	form = f"""
<form method="post" action="/decomp/launch?path={quote(project_path_str)}&amp;va={va:#x}">
  <div class="kv">
    <div class="k">function</div>         <div class="v amber">{html.escape(fn.name)}</div>
    <div class="k">virtual address</div>  <div class="v num">0x{fn.va:08x}</div>
    <div class="k">size</div>             <div class="v">{fn.size} bytes</div>
    <div class="k">workspace</div>        <div class="v">{html.escape(str(workspace_path))}</div>
    <div class="k">model</div>            <div class="v">
      <select name="model">{model_options}</select>
    </div>
    <div class="k">max iterations</div>   <div class="v">
      <input type="number" name="max_iterations" value="8" min="1" max="50">
    </div>
    <div class="k">hard timeout (s)</div> <div class="v">
      <input type="number" name="hard_timeout_seconds" value="300" min="10" max="3600">
    </div>
  </div>
  {existing_state_html}
  {warmstart_html}
  <div style="margin-top: 14px;">
    <button type="submit"{" disabled" if not can_launch else ""}>{launch_label}</button>
    <a href="/progress?path={quote(project_path_str)}" style="margin-left: 12px;">cancel</a>
  </div>
</form>
"""
	body = (
		crumbs(
			("home", "/"),
			("progress", "/progress"),
			(project.name, f"/progress?path={quote(project_path_str)}"),
			("launch", None),
		)
		+ "".join(warnings)
		+ panel("Launch decomp run", form, meta=f"active jobs: {active}/{_MAX_CONCURRENT_JOBS}")
	)
	return page(f"launch · {fn.name}", body, current_path=None)


def _run_redirect(root: str, path: str) -> str:
	"""Redirect back to a workspace's run page, preserving the project path."""
	suffix = f"&path={quote(path)}" if path else ""
	return f"/decomp/run?root={quote(root)}{suffix}"


def _handle_symbol_rename(form: dict[str, str]) -> str:
	"""Persist a display-label rename, then return the run-page redirect."""
	path = form.get("path", "").strip()
	root = form.get("root", "").strip()
	va = int(form["va"], 0)
	symbol_rename(path, va, form.get("label", ""))
	return _run_redirect(root, path)


def _handle_notes_save(form: dict[str, str]) -> str:
	"""Persist per-function notes, then return the run-page redirect."""
	root = form["root"].strip()
	notes_save(root, form.get("notes", ""))
	return _run_redirect(root, form.get("path", "").strip())


def launch_job_from_form(
	project_path_str: str, va_str: str, form: dict[str, str]
) -> tuple[str, JobInfo]:
	"""Validate caps and form fields, then spawn a job. Returns (redirect_url, job)."""
	if len(_active_jobs()) >= _MAX_CONCURRENT_JOBS:
		raise JobsAtCapacity(f"{_MAX_CONCURRENT_JOBS} concurrent jobs already running")

	project = project_load(project_path_str)
	va = int(va_str, 0)
	fn = next((f for f in project.functions if f.va == va), None)
	if fn is None:
		raise ValueError(f"function VA {va:#x} not in {project.name}")

	existing_job = _job_for(project.workspace_for(fn))
	if existing_job and existing_job.is_active():
		raise RuntimeError(f"already running for this workspace (state={existing_job.state})")

	model = form.get("model", "claude-haiku-4-5").strip() or "claude-haiku-4-5"
	max_iter = max(1, min(50, int(form.get("max_iterations", "8") or "8")))
	timeout = max(10.0, min(3600.0, float(form.get("hard_timeout_seconds", "300") or "300")))
	wipe = form.get("wipe_history", "").lower() in ("1", "on", "true", "yes")
	reset_ctx = form.get("reset_ctx_h", "").lower() in ("1", "on", "true", "yes")
	use_ghidra = form.get("use_ghidra_warmstart", "").lower() in ("1", "on", "true", "yes")

	parsed = xbe_cached_load(str(project.xbe_path))
	symbols = symbol_map_load(project_path_str)
	job = launch_decomp_job(
		project,
		fn,
		model=model,
		max_iterations=max_iter,
		hard_timeout_seconds=timeout,
		parsed_xbe=parsed,
		wipe_history=wipe,
		reset_ctx_h=reset_ctx,
		use_ghidra_warmstart=use_ghidra,
		label_for=symbols.label_for,
	)
	_register_job(job)
	redirect = f"/decomp/run?root={quote(str(job.workspace_path))}&path={quote(project_path_str)}"
	return redirect, job


def sweep_launch(project_path_str: str) -> SweepState:
	"""Start a project-wide Ghidra baseline sweep in a daemon thread.

	Plans the queue (untouched, non-SDK, not-actively-running functions), then
	walks it serially — Ghidra headless is the bottleneck, so concurrency would
	only thrash it. Returns immediately; the SweepState mutates as work lands.
	Raises if a sweep is already live for this project.
	"""
	existing = _sweep_for(project_path_str)
	if existing and existing.is_active():
		return existing  # idempotent: a sweep is already walking this project

	project = project_load(project_path_str)
	sdk_vas = _sdk_vas_for(project_path_str)
	stats = project_aggregate(project, sdk_vas=sdk_vas)

	ws_by_va = {f.va: project.workspace_for(f).resolve() for f in project.functions}
	active_ws = _active_workspace_paths()
	queue = sweep_queue(
		stats.function_statuses,
		sdk_vas=sdk_vas,
		is_active=lambda va: ws_by_va.get(va) in active_ws,
	)

	state = SweepState(
		project_path=project_path_str,
		project_name=project.name,
		total=len(queue),
	)
	_register_sweep(state)

	parsed = xbe_cached_load(str(project.xbe_path))
	symbols = symbol_map_load(project_path_str)

	def attempt_one(fn):
		state.current = fn.name
		try:
			return ghidra_sweep_attempt_one(project, fn, parsed=parsed, label_for=symbols.label_for)
		except Exception as e:  # noqa: BLE001 — one bad function must not kill the sweep
			sys.stderr.write(f"[sweep] {fn.name} failed: {type(e).__name__}: {e}\n")
			return SweepOutcome(fn.va, fn.name, "failed", None, f"{type(e).__name__}: {e}")

	def log(outcome) -> None:
		state.done += 1
		if outcome.state == "matched":
			state.matched += 1
		elif outcome.state == "partial":
			state.partial += 1
		elif outcome.state == "failed":
			state.failed += 1

	def _run() -> None:
		state.started_at = time.time()
		try:
			sweep_run(
				queue,
				attempt_one=attempt_one,
				should_stop=lambda: state.stop_requested,
				log=log,
			)
			state.state = "stopped" if state.stop_requested else "done"
		except Exception as e:  # noqa: BLE001 — surface any orchestration failure
			state.error = f"{type(e).__name__}: {e}"
			state.state = "error"
		finally:
			state.current = None

	threading.Thread(target=_run, daemon=True, name=f"sweep-{project.name}").start()
	return state


def sweep_stop(project_path_str: str) -> None:
	"""Request a graceful stop: the worker finishes the current function, then
	halts at the next kill-switch poll."""
	sweep = _sweep_for(project_path_str)
	if sweep is not None and sweep.is_active():
		sweep.stop_requested = True


# Confidence gate for the auto-name pass: only tiny functions qualify, because a
# function whose *whole body* is small and references exactly one string is
# almost certainly an accessor returning that name; in a large function the
# single string is incidental. 24 bytes covers the `mov eax, offset str; ret`
# stubs with margin while admitting no false positives on the Halo 2 retail XBE.
_AUTONAME_MAX_SIZE = int(os.environ.get("IVCS_AUTONAME_MAX_SIZE", "24"))


def autoname_run(project_path_str: str, *, max_size: int = _AUTONAME_MAX_SIZE) -> int:
	"""Bulk-apply high-confidence string-derived names across a project.

	Names only unnamed, non-SDK, tiny functions whose single referenced string
	resolves to a unique, not-yet-taken label. Skips anything ambiguous (multiple
	strings, colliding labels) or already named — so it's safe to re-run and never
	clobbers a human rename. Fast (only small functions are disassembled); runs
	synchronously. Returns the number of functions newly named.
	"""
	project = project_load(project_path_str)
	parsed = xbe_cached_load(str(project.xbe_path))
	symbols = symbol_map_load(project_path_str)
	sdk_vas = _sdk_vas_for(project_path_str)

	candidates: list[tuple[int, str]] = []
	for fn in project.functions:
		if fn.size > max_size or fn.va in sdk_vas or symbols.provenance(fn.va) != "default":
			continue
		label = function_autoname_label(parsed, fn.va, fn.size)
		if label:
			candidates.append((fn.va, label))

	taken = frozenset(
		symbols.label_for(f.va) for f in project.functions if symbols.provenance(f.va) != "default"
	)
	plan = autoname_resolve(candidates, taken_labels=taken)
	for suggestion in plan:
		symbol_rename(project_path_str, suggestion.va, suggestion.label)
	return len(plan)


def verify_launch(project_path_str: str, method: str = "splice") -> VerifyState:
	"""Run the whole-image relink oracle over every matched function in a daemon
	thread, caching the result on completion.

	`method` is "splice" (our own relocator) or "relink" (the real XDK Link.Exe).
	Returns immediately; the VerifyState advances done/current as functions are
	checked. Idempotent while one is already running for this project. The oracle
	recompiles every matched function, which is exactly why it's a background job
	and not computed on a page render."""
	existing = _verify_for(project_path_str)
	if existing and existing.is_active():
		return existing

	project = project_load(project_path_str)
	parsed = xbe_cached_load(str(project.xbe_path))
	stats = project_aggregate(project, sdk_vas=_sdk_vas_for(project_path_str))
	total = sum(1 for s in stats.function_statuses if s.state == "matched")

	state = VerifyState(project_path=project_path_str, method=method, total=total)
	_register_verify(state)
	verifier = image_real_relink_verify if method == "relink" else image_splice_verify

	def on_result(fv) -> None:
		state.done += 1
		state.current = fv.name

	def _run() -> None:
		state.started_at = time.time()
		try:
			result = verifier(project, parsed, on_result=on_result)
			image_verify_cache_write(project_path_str, result, method=method, when=time.time())
			state.state = "done"
		except Exception as e:  # noqa: BLE001 — surface any failure to the UI
			state.error = f"{type(e).__name__}: {e}"
			state.state = "error"
		finally:
			state.current = None

	threading.Thread(target=_run, daemon=True, name=f"verify-{project.name}").start()
	return state


def view_error(message: str, current_path: str | None = None) -> str:
	body = (
		crumbs(("home", "/"), ("error", None))
		+ f'<div class="error">{html.escape(message)}</div>'
		+ '<p class="muted">Go <a href="/">back to the index</a>.</p>'
	)
	return page("error", body, current_path=current_path)


# ── HTTP plumbing ───────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
	def log_message(self, _fmt, *_args):
		sys.stderr.write(f"  {self.command} {self.path}\n")

	def do_POST(self):
		parts = urlsplit(self.path)
		q = {k: v[0] for k, v in parse_qs(parts.query).items()}
		route = parts.path

		length = int(self.headers.get("Content-Length", "0") or "0")
		raw = self.rfile.read(length).decode("utf-8") if length else ""
		form = {k: v[0] for k, v in parse_qs(raw).items()}

		try:
			if route == "/decomp/launch":
				redirect, _job = launch_job_from_form(
					q.get("path", ""),
					q.get("va", "0"),
					form,
				)
				self._redirect(redirect)
				return
			if route == "/symbol/rename":
				self._redirect(_handle_symbol_rename(form))
				return
			if route == "/notes/save":
				self._redirect(_handle_notes_save(form))
				return
			if route == "/sweep/launch":
				path = q.get("path", "") or form.get("path", "")
				sweep_launch(path)
				self._redirect(f"/progress?path={quote(path)}")
				return
			if route == "/sweep/stop":
				path = q.get("path", "") or form.get("path", "")
				sweep_stop(path)
				self._redirect(f"/progress?path={quote(path)}")
				return
			if route == "/autoname":
				path = q.get("path", "") or form.get("path", "")
				named = autoname_run(path)
				self._redirect(f"/progress?path={quote(path)}&named={named}")
				return
			if route == "/verify/launch":
				path = q.get("path", "") or form.get("path", "")
				method = (q.get("method") or form.get("method") or "splice").strip()
				verify_launch(path, "relink" if method == "relink" else "splice")
				self._redirect(f"/stats?path={quote(path)}")
				return
			self._send(404, view_error(f"unknown POST route: {route}"))
		except JobsAtCapacity as e:
			self._send(429, view_error(f"jobs at capacity: {e}"))
		except (FileNotFoundError, KeyError, ValueError) as e:
			self._send(400, view_error(f"{type(e).__name__}: {e}"))
		except Exception:  # noqa: BLE001
			tb = traceback.format_exc()
			sys.stderr.write(tb)
			self._send(500, view_error(tb))

	def do_GET(self):
		parts = urlsplit(self.path)
		q = {k: v[0] for k, v in parse_qs(parts.query).items()}
		route = parts.path
		try:
			if route == "/":
				html_out = view_index()
			elif route == "/decomp/run":
				html_out = view_decomp_run(q["root"], current_path=q.get("path") or None)
			elif route == "/decomp/attempt":
				html_out = view_decomp_attempt(
					q["root"], int(q["n"]), current_path=q.get("path") or None
				)
			elif route == "/decomp/launch":
				html_out = view_launch_form(q.get("path", ""), q.get("va", "0"))
			elif route == "/progress":
				project_path = q.get("path", "").strip()
				if not project_path:
					html_out = view_progress_index(current_path=None)
				else:
					page_n = max(1, int(q.get("page", "1") or "1"))
					size_n = max(10, min(500, int(q.get("page_size", "100") or "100")))
					named_q = q.get("named", "")
					html_out = view_progress(
						project_path,
						current_path=None,
						page_n=page_n,
						page_size=size_n,
						named=int(named_q) if named_q.isdigit() else None,
						filters={
							"state": q.get("state", ""),
							"q": q.get("q", ""),
							"min_size": q.get("min_size", ""),
							"max_size": q.get("max_size", ""),
							"sort": q.get("sort", "va"),
							"order": q.get("order", "asc"),
						},
					)
			elif route == "/stats":
				project_path = q.get("path", "").strip()
				if not project_path:
					html_out = view_progress_index(current_path=None)
				else:
					html_out = view_stats(project_path)
			elif route == "/healthz":
				self._send_json(200, {"ok": True})
				return
			else:
				self._send(404, view_error(f"unknown route: {route}"))
				return
			self._send(200, html_out)
		except FileNotFoundError as e:
			self._send(404, view_error(f"file not found: {e}"))
		except (XbeFormatError, KeyError, ValueError) as e:
			self._send(400, view_error(f"{type(e).__name__}: {e}"))
		except Exception:  # noqa: BLE001 — last-resort net for the UI
			tb = traceback.format_exc()
			sys.stderr.write(tb)
			self._send(500, view_error(tb))

	def _send(self, status: int, body: str) -> None:
		encoded = body.encode("utf-8")
		self.send_response(status)
		self.send_header("Content-Type", "text/html; charset=utf-8")
		self.send_header("Content-Length", str(len(encoded)))
		self.end_headers()
		self.wfile.write(encoded)

	def _redirect(self, location: str) -> None:
		self.send_response(302)
		self.send_header("Location", location)
		self.send_header("Content-Length", "0")
		self.end_headers()

	def _send_json(self, status: int, obj) -> None:
		encoded = json.dumps(obj).encode("utf-8")
		self.send_response(status)
		self.send_header("Content-Type", "application/json")
		self.send_header("Content-Length", str(len(encoded)))
		self.end_headers()
		self.wfile.write(encoded)


def main() -> int:
	parser = argparse.ArgumentParser()
	parser.add_argument("--host", default="127.0.0.1")
	parser.add_argument("--port", type=int, default=8765)
	args = parser.parse_args()

	server = ThreadingHTTPServer((args.host, args.port), Handler)
	url = f"http://{args.host}:{args.port}/"
	sys.stderr.write(f"iVCS web UI listening at {url}\n")
	sys.stderr.write("  ctrl-c to stop\n\n")
	try:
		server.serve_forever()
	except KeyboardInterrupt:
		sys.stderr.write("\nshutting down\n")
		server.shutdown()
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
