"""objdiff/attempt derivation: locate objdiff-cli, lazily derive a diff JSON
for an attempt, read attempt metadata, and render the dual-column asm diff."""

from __future__ import annotations

import html
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from src.core.project import json_load_or_none
from src.decomp.objdiff import (
	DiffKind,
	objdiff_parse,
)
from src.webui.bootstrap import REPO_ROOT
from src.webui.state import _job_for


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
	except subprocess.CalledProcessError as e:
		sys.stderr.write(f"objdiff-cli failed (exit {e.returncode}) for {obj_path}:\n{e.stderr or ''}")
		return None
	except (subprocess.TimeoutExpired, FileNotFoundError) as e:
		sys.stderr.write(f"objdiff-cli could not run for {obj_path}: {type(e).__name__}: {e}\n")
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


def _guess_function_name(root: Path) -> str | None:
	# Recover "fn_<va>" from a "<prefix>_fn_<va>" workspace name.
	name = root.name
	if "_fn_" in name:
		return "fn_" + name.split("_fn_", 1)[1]
	return None


def _va_from_workspace(root: Path) -> int | None:
	"""Recover a function's VA from its `fn_<hex>` workspace dir name.

	The dir is keyed by the machine name (never renamed), so the VA is decodable
	straight out of it — the same anchor the symbol map and splice verifier use.
	"""
	m = re.search(r"fn_([0-9A-Fa-f]{8})", root.name)
	return int(m.group(1), 16) if m else None
