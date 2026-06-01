"""Static presentation assets: the page CSS and the ASCII logo."""

from __future__ import annotations

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

LOGO = """\
 ┌──────────────────────────────────────────┐
 │  ░▒▓  i V C S  ▓▒░    matching-decomp    │
 │  └─ xbe · carver · coff · agent-loop ─┘  │
 └──────────────────────────────────────────┘"""
