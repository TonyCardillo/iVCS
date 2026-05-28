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
import subprocess
import sys
import threading
import time
import traceback
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# Point default_diff_fn at the bundled objdiff-cli unless the user already
# pinned one. Without this, launching a decomp run from the UI dies with
# FileNotFoundError when the agent loop tries to diff the first attempt.
_BUNDLED_OBJDIFF = REPO_ROOT / "recon" / "objdiff-smoke" / "objdiff-cli"
if "IVCS_OBJDIFF_CLI" not in os.environ and _BUNDLED_OBJDIFF.is_file():
    os.environ["IVCS_OBJDIFF_CLI"] = str(_BUNDLED_OBJDIFF)

import capstone  # noqa: E402

from src.xbe import (  # noqa: E402
    ParsedXbe,
    XbeFormatError,
    XbeSection,
    xbe_build_flavor_detect,
    xbe_entry_point_get,
    xbe_kernel_thunk_address_get,
    xbe_load,
    xbe_section_find,
    xbe_section_read,
)
from src.launcher import JobInfo, launch_decomp_job  # noqa: E402
from src.objdiff import DiffKind, objdiff_parse  # noqa: E402
from src.project import (  # noqa: E402
    FunctionEntry,
    Project,
    ProjectStats,
    project_aggregate,
    project_load,
)


# ── Tiny XBE cache (parsing a 5 MB XBE is cheap, but redundant) ─────────────
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
header nav a.active, header nav a:hover { color: var(--cyan); }
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
td.flags span { color: var(--fg-faint); margin-right: 4px; }
td.flags span.on { color: var(--amber); }
td.size { color: var(--green); }

.va-strip {
  position: relative;
  height: 36px;
  border: 1px solid var(--line);
  margin-top: 14px;
  background: var(--bg);
}
.va-strip .seg {
  position: absolute;
  top: 0;
  bottom: 0;
  border-right: 1px solid var(--line-strong);
  background: linear-gradient(180deg, rgba(95,215,255,0.04), rgba(95,215,255,0.12));
}
.va-strip .seg.X { background: linear-gradient(180deg, rgba(255,180,84,0.05), rgba(255,180,84,0.18)); }
.va-strip .seg .lbl {
  position: absolute;
  top: 2px; left: 4px;
  font-size: 10px;
  color: var(--fg-dim);
  letter-spacing: 0.1em;
  text-transform: uppercase;
  white-space: nowrap;
}
.va-strip .seg.X .lbl { color: var(--amber); }
.va-strip .axis {
  position: absolute;
  bottom: -16px;
  font-size: 10px;
  color: var(--fg-faint);
}

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
pre.code .addr   { color: var(--fg-dim); }
pre.code .hex    { color: var(--green); }
pre.code .mn     { color: var(--cyan); }
pre.code .op     { color: var(--fg); }
pre.code .imm    { color: var(--amber); }
pre.code .ascii  { color: var(--violet); }

.hex-row { white-space: pre; }
.hex-row .addr   { color: var(--fg-dim); margin-right: 16px; }
.hex-row .bytes  { color: var(--green); }
.hex-row .ascii  { color: var(--fg-dim); margin-left: 16px; }

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
  grid-template-columns: 48px 1fr 120px 110px;
  gap: 12px;
  align-items: center;
  padding: 6px 8px;
  border-bottom: 1px solid var(--line);
}
.attempt-row:hover { background: var(--bg-row); }
.attempt-row .n { color: var(--fg-dim); }
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
.run-banner .amber  { color: var(--amber); }
.run-banner .cyan   { color: var(--cyan); }
.run-banner .green  { color: var(--green); }

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
    active: str = "",
    refresh_seconds: int | None = None,
) -> str:
    nav_items = [
        ("overview", "/"),
        ("sections", "/xbe" + (f"?path={html.escape(current_path)}" if current_path else "")),
        ("decomp",   "/decomp"),
        ("progress", "/progress"),
    ]
    nav_html = "".join(
        f'<a class="{"active" if active == name else ""}" href="{href}">{name}</a>'
        for name, href in nav_items
    )
    path_chip = (
        f'<span class="muted tight">[ xbe ]</span> '
        f'<span style="color: var(--amber);">{html.escape(current_path)}</span>'
        if current_path else ''
    )
    refresh_tag = (
        f'<meta http-equiv="refresh" content="{refresh_seconds}">'
        if refresh_seconds else ''
    )
    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
{refresh_tag}
<title>{html.escape(title)} · iVCS</title>
<style>{CSS}</style>
</head><body>
<header>
  <div class="brand">◇ &nbsp;i&middot;V&middot;C&middot;S<span class="dot">●</span></div>
  <div>{path_chip}</div>
  <nav>{nav_html}</nav>
</header>
<main>{body}</main>
</body></html>"""


def crumbs(*items: tuple[str, str | None]) -> str:
    parts = []
    for i, (label, href) in enumerate(items):
        if i:
            parts.append('<span class="sep">/</span>')
        if href:
            parts.append(f'<a href="{href}">{html.escape(label)}</a>')
        else:
            parts.append(f'<span>{html.escape(label)}</span>')
    return f'<div class="crumbs">{"".join(parts)}</div>'


def panel(head: str, body: str, meta: str = "") -> str:
    meta_html = f'<span class="meta">{html.escape(meta)}</span>' if meta else ''
    return (
        f'<div class="panel"><div class="panel-head">'
        f'<span>{html.escape(head)}</span>{meta_html}'
        f'</div><div class="panel-body">{body}</div></div>'
    )


# ── Views ───────────────────────────────────────────────────────────────────
LOGO = """\
 ┌──────────────────────────────────────────┐
 │  ░▒▓  i V C S  ▓▒░    matching-decomp    │
 │  └─ xbe · carver · coff · agent-loop ─┘  │
 └──────────────────────────────────────────┘"""


def view_index(default_path: str = "") -> str:
    projects = _discover_projects()
    if projects:
        proj_rows = "".join(
            f'<a class="proj-card" href="/progress?path={quote(path)}">'
            f'<div class="proj-name">{html.escape(name)}</div>'
            f'<div class="proj-meta">{count:,} functions</div>'
            f'<div class="proj-path muted">{html.escape(path.replace(str(REPO_ROOT) + "/", ""))}</div>'
            f'</a>'
            for path, name, count in projects
        )
        proj_panel = panel(
            "Projects",
            f'<div class="proj-grid">{proj_rows}</div>',
            meta=f"{len(projects)} detected · click to open dashboard",
        )
    else:
        proj_panel = ""

    body = f"""
<div class="ascii-logo">{LOGO}</div>
{proj_panel}
{panel("Load XBE", f'''
<form class="inline" action="/xbe" method="get">
  <input type="text" name="path" placeholder="/path/to/default.xbe" value="{html.escape(default_path)}"{" autofocus" if not projects else ""}>
  <button type="submit">Parse →</button>
</form>
<p class="muted" style="margin-top: 12px;">
  Point at any XBE on disk. Try <span style="color: var(--cyan);">/tmp/halo2_default.xbe</span>
  if you ran the demo script.
</p>
''')}
{panel("What you can poke at", '''
<div class="kv">
  <div class="k">overview</div>   <div class="v">Header, build flavor, decoded entry &amp; thunk addresses, VA strip.</div>
  <div class="k">sections</div>   <div class="v">All sections with flags, VA, raw offset, sizes. Click into hex view.</div>
  <div class="k">function</div>   <div class="v">Carve N bytes at VA, disassemble x86 with capstone.</div>
  <div class="k">decomp</div>     <div class="v">Watch a matching-decomp run: attempt timeline, diffs, best.c.</div>
</div>
''')}
"""
    return page("iVCS", body, current_path=None, active="overview")


def view_xbe(path: str) -> str:
    parsed = xbe_cached_load(path)
    flavor = xbe_build_flavor_detect(parsed)
    ep = xbe_entry_point_get(parsed)
    kt = xbe_kernel_thunk_address_get(parsed)
    h = parsed.header

    header_body = f"""
<div class="kv">
  <div class="k">file</div>             <div class="v">{html.escape(path)}</div>
  <div class="k">build flavor</div>     <div class="v amber">{flavor.name}</div>
  <div class="k">base address</div>     <div class="v cyan">{h.base_address:#010x}</div>
  <div class="k">image size</div>       <div class="v green">{h.size_of_image:,} bytes  ({h.size_of_image:#x})</div>
  <div class="k">entry point</div>      <div class="v cyan">{ep:#010x}  <span class="muted">(xor {h.entry_point_xor:#010x})</span></div>
  <div class="k">kernel thunk addr</div><div class="v cyan">{kt:#010x}  <span class="muted">(xor {h.kernel_thunk_address_xor:#010x})</span></div>
  <div class="k">section count</div>    <div class="v">{h.section_count}</div>
  <div class="k">section table</div>    <div class="v">{h.section_headers_address:#010x}</div>
</div>
{_va_strip_html(parsed)}
"""

    sections_rows = []
    for s in parsed.sections:
        flags_html = (
            f'<td class="flags">'
            f'<span class="{"on" if s.is_executable else ""}">X</span>'
            f'<span class="{"on" if s.is_writable else ""}">W</span>'
            f'<span class="{"on" if s.flags & 0x2 else ""}">P</span>'
            f'</td>'
        )
        sections_rows.append(
            f'<tr>'
            f'<td><a href="/section?path={html.escape(path)}&name={html.escape(s.name)}">{html.escape(s.name) or "<i>(unnamed)</i>"}</a></td>'
            f'{flags_html}'
            f'<td class="num">{s.virtual_address:#010x}</td>'
            f'<td class="size">{s.virtual_size:,}</td>'
            f'<td class="num">{s.raw_address:#010x}</td>'
            f'<td class="size">{s.raw_size:,}</td>'
            f'<td><a href="/function?path={html.escape(path)}&va={s.virtual_address:#x}&size=64">carve →</a></td>'
            f'</tr>'
        )
    sections_table = (
        '<table>'
        '<thead><tr><th>name</th><th>flags</th><th>VA</th><th>vsize</th><th>raw</th><th>rsize</th><th></th></tr></thead>'
        f'<tbody>{"".join(sections_rows)}</tbody>'
        '</table>'
    )

    fn_form = f"""
<form class="inline" action="/function" method="get">
  <input type="hidden" name="path" value="{html.escape(path)}">
  <input type="text"   name="va"   placeholder="0x002D1D94" value="{ep:#x}">
  <input type="number" name="size" value="64" min="1" max="4096" style="min-width: 80px;">
  <button type="submit">Disassemble →</button>
</form>
"""

    body = (
        crumbs(("home", "/"), ("overview", None))
        + panel("XBE Header", header_body, meta=f"{flavor.name} · {h.section_count} sections")
        + panel("Sections", sections_table, meta=f"{len(parsed.sections)} entries")
        + panel("Function explorer", fn_form, meta="carve + disassemble")
    )
    return page("XBE", body, current_path=path, active="sections")


def _va_strip_html(parsed: ParsedXbe) -> str:
    base = parsed.header.base_address
    end = base + parsed.header.size_of_image
    span = end - base or 1
    segs = []
    for s in parsed.sections:
        left = (s.virtual_address - base) / span * 100
        width = s.virtual_size / span * 100
        cls = "seg X" if s.is_executable else "seg"
        segs.append(
            f'<div class="{cls}" style="left: {left:.3f}%; width: {width:.3f}%;" '
            f'title="{html.escape(s.name)}  {s.virtual_address:#x}..{s.virtual_address + s.virtual_size:#x}">'
            f'<div class="lbl">{html.escape(s.name)}</div>'
            f'</div>'
        )
    return (
        f'<div class="va-strip">{"".join(segs)}'
        f'<div class="axis" style="left: 0;">{base:#x}</div>'
        f'<div class="axis" style="right: 0;">{end:#x}</div>'
        f'</div>'
        f'<div style="margin-top: 20px;" class="muted tight">virtual address space · amber = executable</div>'
    )


def view_section(path: str, name: str) -> str:
    parsed = xbe_cached_load(path)
    section = xbe_section_find(parsed, name)
    if section is None:
        raise XbeFormatError(f"no section named {name!r}")
    data = xbe_section_read(parsed, section)
    preview = data[:1024]

    info = f"""
<div class="kv">
  <div class="k">flags</div>     <div class="v">{section.flags:#010x}  <span class="muted">({_flag_words(section.flags)})</span></div>
  <div class="k">VA</div>        <div class="v cyan">{section.virtual_address:#010x} .. {section.virtual_address + section.virtual_size:#010x}</div>
  <div class="k">raw</div>       <div class="v cyan">{section.raw_address:#010x} .. {section.raw_address + section.raw_size:#010x}</div>
  <div class="k">virtual size</div><div class="v green">{section.virtual_size:,} bytes</div>
  <div class="k">raw size</div>  <div class="v green">{section.raw_size:,} bytes  <span class="muted">(showing first {len(preview)})</span></div>
</div>
"""

    hex_lines = _hex_dump(preview, base_address=section.virtual_address)
    body = (
        crumbs(("home", "/"), ("overview", f"/xbe?path={html.escape(path)}"), (f"§ {name}", None))
        + panel(f"Section · {name}", info)
        + panel("Hex (first 1 KiB)", f'<pre class="code">{hex_lines}</pre>')
    )
    return page(f"§{name}", body, current_path=path, active="sections")


def _flag_words(flags: int) -> str:
    words = []
    if flags & 0x01: words.append("WRITABLE")
    if flags & 0x02: words.append("PRELOAD")
    if flags & 0x04: words.append("EXECUTABLE")
    if flags & 0x08: words.append("INSERTED_FILE")
    if flags & 0x10: words.append("HEAD_PAGE_RO")
    if flags & 0x20: words.append("TAIL_PAGE_RO")
    return " | ".join(words) if words else "—"


def _hex_dump(data: bytes, base_address: int = 0) -> str:
    rows = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(16 * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        rows.append(
            f'<span class="addr">{base_address + i:08x}</span>'
            f'<span class="hex">{hex_part}</span>'
            f'  <span class="ascii">{html.escape(ascii_part)}</span>'
        )
    return "\n".join(rows)


def view_function(path: str, va_str: str, size: int) -> str:
    va = int(va_str, 16) if va_str.lower().startswith("0x") else int(va_str, 0)
    parsed = xbe_cached_load(path)
    from src.xbe import xbe_function_carve
    body_bytes = xbe_function_carve(parsed, va, size)

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    lines = []
    last_end = va
    for instr in md.disasm(body_bytes, va):
        hex_bytes = instr.bytes.hex()
        lines.append(
            f'<span class="addr">{instr.address:#010x}</span>  '
            f'<span class="hex">{hex_bytes:<14}</span>  '
            f'<span class="mn">{instr.mnemonic:<7}</span>'
            f'<span class="op">{html.escape(instr.op_str)}</span>'
        )
        last_end = instr.address + instr.size
    if not lines:
        lines.append('<span class="ascii">(capstone produced no instructions; bytes may be data)</span>')

    info = f"""
<div class="kv">
  <div class="k">virtual address</div><div class="v cyan">{va:#010x}</div>
  <div class="k">carved size</div>    <div class="v green">{size} bytes</div>
  <div class="k">instructions</div>   <div class="v">{len(lines)} (ends near {last_end:#x})</div>
</div>
<form class="inline" action="/function" method="get" style="margin-top: 14px;">
  <input type="hidden" name="path" value="{html.escape(path)}">
  <input type="text"   name="va"   value="{va:#x}">
  <input type="number" name="size" value="{size}" min="1" max="4096" style="min-width: 80px;">
  <button type="submit">Re-disassemble</button>
</form>
"""
    asm_block = '<pre class="code">' + "\n".join(lines) + '</pre>'
    body = (
        crumbs(("home", "/"), ("overview", f"/xbe?path={html.escape(path)}"), (f"fn @ {va:#x}", None))
        + panel("Function", info)
        + panel("Disassembly", asm_block, meta=f"{size}B · x86 32-bit")
    )
    return page(f"fn {va:#x}", body, current_path=path, active="sections")


# ── Decomp workspace views ──────────────────────────────────────────────────
def _workspace_candidates() -> list[Path]:
    """Directories that look like a FunctionWorkspace (have target.obj or result.json)."""
    roots = [Path("/tmp"), Path.cwd(), REPO_ROOT]
    seen: set[Path] = set()
    found: list[Path] = []
    for r in roots:
        if not r.is_dir():
            continue
        try:
            for entry in r.iterdir():
                if not entry.is_dir() or entry in seen:
                    continue
                seen.add(entry)
                if (entry / "target.obj").is_file() or (entry / "result.json").is_file():
                    found.append(entry)
        except PermissionError:
            continue
    return sorted(found)


def _objdiff_cli_path() -> str | None:
    explicit = os.environ.get("IVCS_OBJDIFF_CLI")
    if explicit and Path(explicit).is_file():
        return explicit
    bundled = REPO_ROOT / "recon" / "objdiff-smoke" / "objdiff-cli"
    if bundled.is_file():
        return str(bundled)
    return None


def _ensure_diff_json(workspace_root: Path, n: int, function_name: str | None) -> Path | None:
    """Lazily derive `NNNN.diff.json` from target.obj + NNNN.obj if it's missing."""
    history = workspace_root / "history"
    diff_path = history / f"{n:04d}.diff.json"
    if diff_path.is_file():
        return diff_path
    obj_path = history / f"{n:04d}.obj"
    target = workspace_root / "target.obj"
    if not obj_path.is_file() or not target.is_file():
        return None
    cli = _objdiff_cli_path()
    if cli is None:
        return None
    cmd = [cli, "diff", "-1", str(target), "-2", str(obj_path), "--format", "json", "-o", str(diff_path)]
    if function_name:
        cmd.append(function_name)
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=True)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return None
    return diff_path if diff_path.is_file() else None


def _workspace_function_name(workspace_root: Path) -> str | None:
    result = _load_json_or_none(workspace_root / "result.json")
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

    info = {
        "n": n,
        "c_path": c_path,
        "obj_path": obj_path,
        "diff_path": diff_path,
        "compiled": obj_path.is_file(),
        "match_percent": None,
        "function_symbol_name": None,
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


def _attempts_listing(workspace_root: Path) -> list[dict]:
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
    return [_attempt_info(workspace_root, n) for n in sorted(numbers)]


def _status_badge(result_json: dict | None) -> str:
    if result_json is None:
        return '<span class="badge pending">in progress</span>'
    reason = result_json.get("termination_reason", "?")
    success = result_json.get("success", False)
    cls = "matched" if success else ("failed" if reason in ("hard_timeout", "llm_no_progress") else "partial")
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
    dots = "".join(
        f'<circle cx="{x:.1f}" cy="{y:.1f}" r="2.5" fill="#5fd7ff"/>'
        for x, y in pts
    )
    grid = "".join(
        f'<line x1="0" x2="{width}" y1="{height - 4 - p / 100 * (height - 12):.1f}" '
        f'y2="{height - 4 - p / 100 * (height - 12):.1f}" '
        f'stroke="rgba(180,196,212,0.08)" stroke-width="1"/>'
        for p in (25, 50, 75, 100)
    )
    return (
        f'<svg class="spark" viewBox="0 0 {width} {height}" preserveAspectRatio="none">'
        f'{grid}'
        f'<path d="{path}" stroke="#5fd7ff" stroke-width="1.5" fill="none" opacity="0.9"/>'
        f'{dots}'
        '</svg>'
    )


def view_decomp_index(current_path: str | None) -> str:
    candidates = _workspace_candidates()
    rows = []
    for c in candidates:
        result = _load_json_or_none(c / "result.json")
        attempts = _attempts_listing(c)
        best = result.get("best_match_percent") if result else max((a["match_percent"] or 0 for a in attempts), default=None)
        fn = result.get("function_name") if result else "?"
        best_str = f"{best:.1f}%" if isinstance(best, (int, float)) else "—"
        rows.append(
            f'<tr>'
            f'<td><a href="/decomp/run?root={html.escape(str(c))}">{html.escape(c.name)}</a></td>'
            f'<td class="muted">{html.escape(fn)}</td>'
            f'<td class="num">{len(attempts)}</td>'
            f'<td>{best_str}</td>'
            f'<td>{_status_badge(result)}</td>'
            f'<td class="muted">{html.escape(str(c))}</td>'
            f'</tr>'
        )

    table = (
        '<table>'
        '<thead><tr><th>workspace</th><th>function</th><th>attempts</th><th>best</th><th>status</th><th>path</th></tr></thead>'
        f'<tbody>{"".join(rows) or "<tr><td colspan=6 class=\"muted center\">no workspaces autodetected</td></tr>"}</tbody>'
        '</table>'
    )

    picker = """
<form class="inline" action="/decomp/run" method="get">
  <input type="text" name="root" placeholder="/tmp/halo2_demo_fn_002D1D94" autofocus>
  <button type="submit">Open →</button>
</form>
<p class="muted" style="margin-top: 10px;">
  Any directory with a <span style="color: var(--cyan);">target.obj</span> or
  <span style="color: var(--cyan);">result.json</span> qualifies.
</p>
"""

    body = (
        crumbs(("home", "/"), ("decomp", None))
        + panel("Open workspace", picker)
        + panel("Autodetected workspaces", table, meta=f"{len(candidates)} found")
    )
    return page("decomp", body, current_path=current_path, active="decomp")


def view_decomp_run(root_str: str, current_path: str | None) -> str:
    root = Path(root_str)
    if not root.is_dir():
        raise FileNotFoundError(f"workspace not a directory: {root}")

    job = _job_for(root)
    result = _load_json_or_none(root / "result.json")
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

    header_body = f"""
<div class="kv">
  <div class="k">workspace</div>      <div class="v">{html.escape(str(root))}</div>
  <div class="k">function</div>       <div class="v amber">{html.escape(fn_name)}</div>
  <div class="k">attempts</div>       <div class="v">{len(attempts)}</div>
  <div class="k">best match</div>     <div class="v green">{(f"{best:.2f}%" if isinstance(best, (int, float)) else "—")}</div>
  <div class="k">status</div>         <div class="v">{_status_badge(result)}</div>
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
        timeline_rows.append(
            f'<div class="attempt-row">'
            f'<span class="n">#{a["n"]:04d}</span>'
            f'<a class="openrow" href="/decomp/attempt?root={html.escape(str(root))}&n={a["n"]}">view source &amp; diff →</a>'
            f'<span class="status">{mp_html}</span>'
            f'<span class="status">{status_html}</span>'
            f'</div>'
        )
    timeline = "".join(timeline_rows) or '<div class="muted center" style="padding: 18px;">no attempts on disk yet</div>'

    ctx_h = (root / "ctx.h").read_text() if (root / "ctx.h").is_file() else "(missing)"
    best_c = (root / "best.c").read_text() if (root / "best.c").is_file() else "(no best.c yet)"

    banner = ""
    refresh = None
    if job:
        if job.is_active():
            refresh = 3
            elapsed = int((time.time() if job.started_at else 0) - job.started_at) if job.started_at else 0
            banner = (
                f'<div class="run-banner running">'
                f'<span class="badge pending">{job.state.upper()}</span>'
                f'<span>iter <span class="amber">{job.iterations_completed}</span>/{job.max_iterations}'
                f' · elapsed {elapsed}s / {int(job.hard_timeout_seconds)}s'
                f' · model <span class="cyan">{html.escape(job.model)}</span></span>'
                f'<span class="muted">auto-refreshing every 3s</span>'
                f'</div>'
            )
        elif job.state == "error":
            banner = (
                f'<div class="run-banner failed">'
                f'<span class="badge failed">ERROR</span>'
                f'<span class="muted">{html.escape(job.error or "")}</span>'
                f'</div>'
            )
        else:
            reason = job.termination_reason or "done"
            best_str = f"{job.best_match_percent:.2f}%" if isinstance(job.best_match_percent, (int, float)) else "—"
            banner = (
                f'<div class="run-banner done">'
                f'<span class="badge matched">FINISHED</span>'
                f'<span>reason <span class="amber">{html.escape(reason)}</span>'
                f' · best <span class="green">{best_str}</span>'
                f' · iter {job.iterations_completed}/{job.max_iterations}</span>'
                f'</div>'
            )

    body = (
        crumbs(("home", "/"), ("decomp", "/decomp"), (root.name, None))
        + banner
        + panel("Run", header_body, meta=fn_name)
        + panel("Attempts", timeline, meta=f"{len(attempts)} total")
        + f'<div class="split">'
        + panel(
            "ctx.h",
            f'<pre class="code">{html.escape(ctx_h)}</pre>',
            meta="context header · prepended to every attempt",
        )
        + panel("best.c", f'<pre class="code">{html.escape(best_c)}</pre>', meta="highest-match attempt so far")
        + '</div>'
    )
    return page(
        f"decomp · {root.name}",
        body,
        current_path=current_path,
        active="decomp",
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
        compile_error = stderr_path.read_text() if stderr_path.is_file() else "compile failed (no diff produced, no stderr captured)"

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
            ("decomp", "/decomp"),
            (root.name, f"/decomp/run?root={html.escape(str(root))}"),
            (f"#{n:04d}", None),
        ),
        panel(f"Attempt #{n:04d}", head_body),
    ]
    if compile_error:
        sections.append(panel("Compile error", f'<pre class="code">{html.escape(compile_error)}</pre>'))
        sections.append(panel(f"{n:04d}.c", f'<pre class="code">{html.escape(c_text)}</pre>'))
    else:
        target_col, current_col, stats = _asm_dual_columns(info["diff_path"], info["function_symbol_name"])
        matched, differs, target_name, current_name = stats
        sections.append(panel(
            "Compilation",
            (
                '<div class="codedual">'
                f'<div class="col left">'
                f'<div class="col-head"><span>target · {html.escape(target_name)}</span><span class="sub">{matched} match · {differs} diff</span></div>'
                f'{target_col}'
                '</div>'
                f'<div class="col right">'
                f'<div class="col-head"><span>current · {html.escape(current_name)}</span><span class="sub">&lt; del · &gt; ins · | repl · o op · r arg</span></div>'
                f'{current_col}'
                '</div>'
                '</div>'
            ),
            meta=f"{n:04d}.obj vs target.obj",
        ))
        sections.append(panel(f"{n:04d}.c", f'<pre class="code">{_numbered_c(c_text)}</pre>', meta=f"{len(c_text.splitlines())} lines"))

    nav = []
    if n > 1:
        nav.append(f'<a href="/decomp/attempt?root={html.escape(str(root))}&n={n - 1}">← prev</a>')
    nav.append(f'<a href="/decomp/run?root={html.escape(str(root))}">↑ run</a>')
    if (root / "history" / f"{n + 1:04d}.c").is_file():
        nav.append(f'<a href="/decomp/attempt?root={html.escape(str(root))}&n={n + 1}">next →</a>')
    sections.append(f'<p class="tight" style="display: flex; gap: 18px; padding: 4px 0;">{"  ".join(nav)}</p>')

    return page(f"#{n:04d}", body="".join(sections), current_path=current_path, active="decomp")


_KIND_GLYPHS: dict[DiffKind, str] = {
    DiffKind.NONE:         " ",
    DiffKind.DELETE:       "&lt;",
    DiffKind.INSERT:       "&gt;",
    DiffKind.REPLACE:      "|",
    DiffKind.OP_MISMATCH:  "o",
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
    left_sym = next((s for s in left_syms if s.name == function_symbol_name), left_syms[0] if left_syms else None)
    right_sym = next((s for s in right_syms if s.name == function_symbol_name), right_syms[0] if right_syms else None)

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
        kind = (lrow.diff_kind if lrow else None) or (rrow.diff_kind if rrow else None) or DiffKind.NONE
        cls = kind.value.removeprefix("DIFF_").lower()
        glyph = _KIND_GLYPHS.get(kind, " ")

        if kind == DiffKind.NONE:
            matched += 1
        else:
            differs += 1

        # Left (target). No marker glyph on this side.
        if lrow is not None and lrow.instruction is not None:
            addr = f"{lrow.instruction.address:x}:" if lrow.instruction.address is not None else ""
            mnem, args = _split_instr(lrow.instruction.formatted)
            target_html.append(
                f'<div class="asm-row {cls}">'
                f'<span class="addr">{addr}</span>'
                f'<span class="mnem">{html.escape(mnem)}</span>'
                f'<span class="args">{html.escape(args)}</span>'
                '</div>'
            )
        else:
            target_html.append(f'<div class="asm-row {cls} empty">&nbsp;</div>')

        # Right (current). Marker glyph in first column.
        if rrow is not None and rrow.instruction is not None:
            addr = f"{rrow.instruction.address:x}:" if rrow.instruction.address is not None else ""
            mnem, args = _split_instr(rrow.instruction.formatted)
            current_html.append(
                f'<div class="asm-row {cls}">'
                f'<span class="marker">{glyph}</span>'
                f'<span class="addr">{addr}</span>'
                f'<span class="mnem">{html.escape(mnem)}</span>'
                f'<span class="args">{html.escape(args)}</span>'
                '</div>'
            )
        else:
            current_html.append(
                f'<div class="asm-row {cls} empty">'
                f'<span class="marker">{glyph}</span>'
                '</div>'
            )

    target_name = left_sym.name if left_sym else "—"
    current_name = right_sym.name if right_sym else "—"
    return "".join(target_html), "".join(current_html), (matched, differs, target_name, current_name)


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
        f'</div>'
    )


def _load_json_or_none(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def _attempt_status_labels(
    attempt: dict, *, is_in_flight: bool
) -> tuple[str | None, str, str]:
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
            ("compiling…", "pending", "compiling") if is_in_flight
            else ("compile failed", "failed", "compile")
        )
    if not attempt["diff_path"].is_file():
        return (
            ("diffing…", "pending", "diffing") if is_in_flight
            else ("diff failed", "failed", "diff")
        )
    return "symbol mismatch", "failed", "no match"


def _guess_function_name(root: Path) -> str | None:
    # If the workspace was named like "halo2_demo_fn_002D1D94", strip the prefix.
    name = root.name
    if "_fn_" in name:
        return "fn_" + name.split("_fn_", 1)[1]
    return None


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
        except Exception:  # noqa: BLE001 — malformed manifests just get skipped
            continue
    return found


def view_progress_index(current_path: str | None) -> str:
    projects = _discover_projects()
    if projects:
        rows = "".join(
            f'<tr>'
            f'<td><a href="/progress?path={quote(path)}">{html.escape(name)}</a></td>'
            f'<td class="num">{count:,} fns</td>'
            f'<td class="muted">{html.escape(path)}</td>'
            f'</tr>'
            for path, name, count in projects
        )
        recent = panel(
            "Detected projects",
            f'<table><thead><tr><th>name</th><th>size</th><th>path</th></tr></thead>'
            f'<tbody>{rows}</tbody></table>',
            meta=f"{len(projects)} found · scans projects/ and examples/",
        )
    else:
        recent = ""

    open_form = panel(
        "Open project",
        '''
<form class="inline" action="/progress" method="get">
  <input type="text" name="path" placeholder="/path/to/project.json"{autofocus}>
  <button type="submit">Aggregate →</button>
</form>
<p class="muted" style="margin-top: 12px;">
  Point at a <span style="color: var(--cyan);">project.json</span> manifest.
  Generate one with <span style="color: var(--cyan);">scripts/enumerate.py</span>.
</p>
'''.replace("{autofocus}", " autofocus" if not projects else ""),
    )
    body = crumbs(("home", "/"), ("progress", None)) + recent + open_form
    return page("progress", body, current_path=current_path, active="progress")


def view_progress(
    project_path_str: str,
    current_path: str | None,
    *,
    page_n: int = 1,
    page_size: int = 100,
    filters: dict[str, str] | None = None,
) -> str:
    project = project_load(project_path_str)
    stats = project_aggregate(project)
    filters = filters or {}

    all_statuses = list(stats.function_statuses)
    filtered = _apply_filters(all_statuses, filters)
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
        page_slice, project_path_str,
        page=page_n, total_pages=total_pages, total=total, page_size=page_size,
        filters=filters,
    )

    rng = (
        f"{start + 1}–{min(start + page_size, total)} of {total}"
        if total
        else "0 of 0"
    )
    body = (
        crumbs(("home", "/"), ("progress", "/progress"), (project.name, None))
        + panel("Project", summary, meta=f"{total_unfiltered} functions · {stats.total_bytes:,} bytes")
        + panel("Match distribution", histogram, meta="function count per 10% bucket")
        + panel("Functions", filter_bar + table, meta=f"{rng} · page {page_n}/{total_pages}")
    )
    return page(f"progress · {project.name}", body, current_path=current_path, active="progress")


_STATE_SORT_ORDER = {"matched": 0, "partial": 1, "untouched": 2}


def _apply_filters(statuses: list, f: dict[str, str]) -> list:
    out = statuses
    state = f.get("state") or ""
    if state in ("matched", "partial", "untouched"):
        out = [s for s in out if s.state == state]
    query = (f.get("q") or "").strip().lower()
    if query:
        out = [s for s in out if query in s.name.lower()]
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
        if sort_key == "name":     return s.name
        if sort_key == "size":     return s.size
        if sort_key == "best":     return s.best_match_percent if s.best_match_percent is not None else -1.0
        if sort_key == "iters":    return s.iterations
        if sort_key == "state":    return _STATE_SORT_ORDER.get(s.state, 99)
        return s.va  # default: VA

    return sorted(statuses, key=keyer, reverse=reverse)


def _progress_filter_bar(
    project_path_str: str, f: dict[str, str], page_size: int,
    total_filtered: int, total_unfiltered: int,
) -> str:
    def opt(value: str, label: str, selected: str) -> str:
        sel = " selected" if value == selected else ""
        return f'<option value="{value}"{sel}>{label}</option>'

    state_sel = f.get("state", "")
    sort_sel = f.get("sort", "va")
    order_sel = f.get("order", "asc")

    state_options = "".join(opt(v, l, state_sel) for v, l in (
        ("",          "all"),
        ("matched",   "matched"),
        ("partial",   "partial"),
        ("untouched", "untouched"),
    ))
    sort_options = "".join(opt(v, l, sort_sel) for v, l in (
        ("va",    "VA"),
        ("name",  "name"),
        ("size",  "size"),
        ("best",  "best %"),
        ("iters", "iters"),
        ("state", "state"),
    ))
    order_options = "".join(opt(v, l, order_sel) for v, l in (
        ("asc",  "↑ asc"),
        ("desc", "↓ desc"),
    ))

    count_chip = (
        f'<span class="muted">{total_filtered:,} match'
        + (f' · {total_unfiltered:,} total' if total_filtered != total_unfiltered else "")
        + '</span>'
    )

    return f"""
<form class="filter-bar" method="get" action="/progress">
  <input type="hidden" name="path"      value="{html.escape(project_path_str)}">
  <input type="hidden" name="page_size" value="{page_size}">
  <label>state <select name="state">{state_options}</select></label>
  <label>name contains <input type="text" name="q" value="{html.escape(f.get('q', ''))}" placeholder="fn_002D"></label>
  <label>size <input type="number" name="min_size" value="{html.escape(f.get('min_size', ''))}" placeholder="min" min="0">
    <span class="muted">–</span>
    <input type="number" name="max_size" value="{html.escape(f.get('max_size', ''))}" placeholder="max" min="0"></label>
  <label>sort <select name="sort">{sort_options}</select> <select name="order">{order_options}</select></label>
  <button type="submit">apply</button>
  <a href="/progress?path={quote(project_path_str)}" class="clear-filters">clear</a>
  {count_chip}
</form>
"""


def _progress_summary(project: Project, stats: ProjectStats) -> str:
    m = stats.matched_functions
    p = stats.partial_functions
    u = stats.untouched_functions
    total = stats.total_functions or 1
    m_pct = m / total * 100
    p_pct = p / total * 100
    u_pct = u / total * 100

    seg_html = []
    for label, count, pct, cls in (
        ("matched", m, m_pct, "seg-matched"),
        ("partial", p, p_pct, "seg-partial"),
        ("untouched", u, u_pct, "seg-untouched"),
    ):
        if pct <= 0:
            continue
        text = f"{label} {count}" if pct > 7 else ""
        seg_html.append(f'<div class="{cls}" style="flex: {pct:.4f};">{text}</div>')

    bar = '<div class="stacked-bar">' + "".join(seg_html) + '</div>'
    legend = (
        '<div class="legend">'
        f'<span><span class="swatch matched"></span>matched · {m} ({m_pct:.1f}%)</span>'
        f'<span><span class="swatch partial"></span>partial · {p} ({p_pct:.1f}%)</span>'
        f'<span><span class="swatch untouched"></span>untouched · {u} ({u_pct:.1f}%)</span>'
        '</div>'
    )

    return f"""
<div class="kv">
  <div class="k">name</div>           <div class="v amber">{html.escape(project.name)}</div>
  <div class="k">xbe</div>            <div class="v">{html.escape(str(project.xbe_path))}</div>
  <div class="k">workspaces</div>     <div class="v">{html.escape(str(project.workspace_root))}</div>
  <div class="k">functions matched</div><div class="v green">{m} / {stats.total_functions}  ({stats.matched_function_percent:.2f}%)</div>
  <div class="k">bytes matched</div>  <div class="v green">{stats.matched_bytes:,} / {stats.total_bytes:,}  ({stats.matched_byte_percent:.2f}%)</div>
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

    bucket_labels = ["0", "1-10", "11-20", "21-30", "31-40", "41-50", "51-60", "61-70", "71-80", "81-90", "91-100"]
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
        + '<text x="' + str(pad_l) + '" y="' + str(height - 2) + '" '
          'fill="var(--fg-faint)" font-size="9">match %</text>'
        + '</svg>'
    )


def _progress_function_table(
    page_slice,
    project_path_str: str,
    *,
    page: int,
    total_pages: int,
    total: int,
    page_size: int,
    filters: dict[str, str] | None = None,
) -> str:
    rows = []
    for s in page_slice:
        best_str = f"{s.best_match_percent:.2f}%" if isinstance(s.best_match_percent, (int, float)) else "—"
        job = _job_for(s.workspace_path)
        if job and job.is_active():
            state_label = f'<span class="fn-state partial">running</span>'
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
        reason = s.termination_reason or ""
        rows.append(
            f'<tr>'
            f'<td>{html.escape(s.name)}</td>'
            f'<td class="num">0x{s.va:08x}</td>'
            f'<td class="size">{s.size}</td>'
            f'<td>{state_label}</td>'
            f'<td>{best_str}</td>'
            f'<td class="num">{s.iterations}</td>'
            f'<td class="muted">{html.escape(reason)}</td>'
            f'<td>{action}</td>'
            f'</tr>'
        )

    pager = _progress_pager(
        project_path_str, page=page, total_pages=total_pages,
        total=total, page_size=page_size, filters=filters or {},
    )
    empty_msg = "no functions match these filters" if filters and any(filters.values()) else "empty project"
    return (
        '<table>'
        '<thead><tr>'
        '<th>name</th><th>VA</th><th>size</th><th>state</th>'
        '<th>best</th><th>iters</th><th>reason</th><th></th>'
        '</tr></thead>'
        f'<tbody>{"".join(rows) or f"<tr><td colspan=8 class=\"muted center\">{empty_msg}</td></tr>"}</tbody>'
        '</table>'
        + pager
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
        qs = (
            f"path={quote(project_path_str)}"
            f"&page={p}"
            f"&page_size={page_size}"
            + filter_qs
        )
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
        pages.append(link(total_pages, f"last »"))
    else:
        pages.append('<span class="pg-disabled">next ›</span>')
        pages.append('<span class="pg-disabled">last »</span>')

    hidden_filters = "".join(
        f'<input type="hidden" name="{k}" value="{html.escape(v)}">'
        for k, v in (filters or {}).items() if v
    )
    jump = (
        f'<form class="pg-jump" method="get" action="/progress">'
        f'<input type="hidden" name="path" value="{html.escape(project_path_str)}">'
        f'<input type="hidden" name="page_size" value="{page_size}">'
        f'{hidden_filters}'
        f'<span class="muted">jump</span>'
        f'<input type="number" name="page" min="1" max="{total_pages}" value="{page}">'
        f'</form>'
    )

    return (
        f'<div class="pager">'
        f'<span class="muted">{total:,} entries · page {page}/{total_pages} · {page_size}/page</span>'
        f'<div class="pages">{"".join(pages)}</div>'
        f'{jump}'
        f'</div>'
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
            'environment. Restart the web UI with it exported.</div>'
        )
    if active >= _MAX_CONCURRENT_JOBS:
        warnings.append(
            f'<div class="error">already at capacity: {active}/'
            f'{_MAX_CONCURRENT_JOBS} concurrent jobs. Wait for one to finish '
            f'or raise IVCS_MAX_CONCURRENT_JOBS.</div>'
        )
    if existing_job and existing_job.is_active():
        warnings.append(
            f'<div class="error">a job is already running for this workspace '
            f'(state: {existing_job.state}, iter {existing_job.iterations_completed}'
            f'/{existing_job.max_iterations}).</div>'
        )

    can_launch = api_key_set and active < _MAX_CONCURRENT_JOBS and not (
        existing_job and existing_job.is_active()
    )

    # Detect existing on-disk state so the user knows what they're about to overwrite.
    existing_attempts = []
    if (workspace_path / "history").is_dir():
        existing_attempts = sorted(
            int(p.stem) for p in (workspace_path / "history").glob("*.c")
        )
    existing_result = _load_json_or_none(workspace_path / "result.json")
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
  <input type="checkbox" name="reset_ctx_h" value="1"{' disabled' if not ctx_h_exists else ''}>
  regenerate ctx.h from auto-stub (discards hand-edits; uses current launcher rules)
</label>
"""

    model_options = "".join(
        f'<option value="{m}"{" selected" if m == "claude-haiku-4-5" else ""}>{m}</option>'
        for m in ("claude-haiku-4-5", "claude-sonnet-4-6", "claude-opus-4-7")
    )

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
      <input type="number" name="hard_timeout_seconds" value="180" min="10" max="3600">
    </div>
  </div>
  {existing_state_html}
  <div style="margin-top: 14px;">
    <button type="submit"{' disabled' if not can_launch else ''}>{launch_label}</button>
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
    return page(f"launch · {fn.name}", body, current_path=None, active="progress")


def launch_job_from_form(
    project_path_str: str, va_str: str, form: dict[str, str]
) -> tuple[str, JobInfo]:
    """Validate caps and form fields, then spawn a job. Returns (redirect_url, job)."""
    if len(_active_jobs()) >= _MAX_CONCURRENT_JOBS:
        raise JobsAtCapacity(
            f"{_MAX_CONCURRENT_JOBS} concurrent jobs already running"
        )

    project = project_load(project_path_str)
    va = int(va_str, 0)
    fn = next((f for f in project.functions if f.va == va), None)
    if fn is None:
        raise ValueError(f"function VA {va:#x} not in {project.name}")

    existing_job = _job_for(project.workspace_for(fn))
    if existing_job and existing_job.is_active():
        raise RuntimeError(
            f"already running for this workspace (state={existing_job.state})"
        )

    model = form.get("model", "claude-haiku-4-5").strip() or "claude-haiku-4-5"
    max_iter = max(1, min(50, int(form.get("max_iterations", "8") or "8")))
    timeout = max(10.0, min(3600.0, float(form.get("hard_timeout_seconds", "180") or "180")))
    wipe = form.get("wipe_history", "").lower() in ("1", "on", "true", "yes")
    reset_ctx = form.get("reset_ctx_h", "").lower() in ("1", "on", "true", "yes")

    parsed = xbe_cached_load(str(project.xbe_path))
    job = launch_decomp_job(
        project, fn,
        model=model,
        max_iterations=max_iter,
        hard_timeout_seconds=timeout,
        parsed_xbe=parsed,
        wipe_history=wipe,
        reset_ctx_h=reset_ctx,
    )
    _register_job(job)
    redirect = (
        f"/decomp/run?root={quote(str(job.workspace_path))}"
        f"&path={quote(project_path_str)}"
    )
    return redirect, job


def view_error(message: str, current_path: str | None = None) -> str:
    body = (
        crumbs(("home", "/"), ("error", None))
        + f'<div class="error">{html.escape(message)}</div>'
        + '<p class="muted">Go <a href="/">back to the index</a>.</p>'
    )
    return page("error", body, current_path=current_path)


# ── HTTP plumbing ───────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
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
                    q.get("path", ""), q.get("va", "0"), form,
                )
                self._redirect(redirect)
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
                html_out = view_index(default_path=q.get("path", ""))
            elif route == "/xbe":
                path = q.get("path", "").strip()
                if not path:
                    html_out = view_index()
                else:
                    html_out = view_xbe(path)
            elif route == "/section":
                html_out = view_section(q["path"], q["name"])
            elif route == "/function":
                html_out = view_function(q["path"], q.get("va", "0"), int(q.get("size", "64")))
            elif route == "/decomp":
                html_out = view_decomp_index(current_path=q.get("path") or None)
            elif route == "/decomp/run":
                html_out = view_decomp_run(q["root"], current_path=q.get("path") or None)
            elif route == "/decomp/attempt":
                html_out = view_decomp_attempt(q["root"], int(q["n"]), current_path=q.get("path") or None)
            elif route == "/decomp/launch":
                html_out = view_launch_form(q.get("path", ""), q.get("va", "0"))
            elif route == "/progress":
                project_path = q.get("path", "").strip()
                if not project_path:
                    html_out = view_progress_index(current_path=None)
                else:
                    page_n = max(1, int(q.get("page", "1") or "1"))
                    size_n = max(10, min(500, int(q.get("page_size", "100") or "100")))
                    html_out = view_progress(
                        project_path,
                        current_path=None,
                        page_n=page_n,
                        page_size=size_n,
                        filters={
                            "state":    q.get("state", ""),
                            "q":        q.get("q", ""),
                            "min_size": q.get("min_size", ""),
                            "max_size": q.get("max_size", ""),
                            "sort":     q.get("sort", "va"),
                            "order":    q.get("order", "asc"),
                        },
                    )
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
