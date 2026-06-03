"""Read the standing best from a function workspace's on-disk attempt history.

`history/NNNN.diff.json` (+ the `NNNN.model` sidecars) are the immutable ground
truth behind `result.json`. The summary is a derived convenience that a weak
re-run can overwrite — clobbering `best_match_percent` to None even though the
attempts and `best.c` still hold a real partial/matched solution. Both the
progress view and the agent loop's prior-best inheritance reconcile against this
reader so neither trusts a clobberable summary.

Reads cached diffs only — no objdiff-cli re-derivation — so a whole-project scan
stays cheap. Attempts that were never viewed (no diff.json yet) simply don't
contribute a score, which is correct: their match% isn't recoverable without a
compile, and the webui derives the diff the first time the function is opened.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from src.decomp.objdiff import function_match_percent, objdiff_parse


@dataclass(frozen=True)
class HistoryBest:
	match_percent: float | None  # strongest scored attempt, None when none scored
	model: str | None  # model credited for that attempt (its .model sidecar)
	attempts: int  # number of LLM attempts on disk (excludes the #0 baseline)


def _attempt_match_read(diff_path: Path, function_name: str) -> float | None:
	"""Match% for one attempt: the target function's score from its cached diff.

	Name-matched via the shared objdiff reader (target/left side first), so a
	best.c defining helper functions still scores the verification target rather
	than whichever function symbol happens to come first. Returns None when the
	diff is absent, unparseable, or doesn't score that function (a symbol
	mismatch)."""
	if not diff_path.is_file():
		return None
	try:
		diff = objdiff_parse(json.loads(diff_path.read_text()))
	except (json.JSONDecodeError, OSError):
		return None
	return function_match_percent(diff, function_name)


def history_best_read(history_dir: Path, function_name: str) -> HistoryBest:
	"""Strongest attempt recorded under `history_dir`, read from cached diffs.

	Walks `NNNN.c` to enumerate attempts, reads each `NNNN.diff.json`'s match%
	for `function_name`, and returns the highest — ties broken by the earliest
	attempt, matching the best.c ownership convention. The baseline attempt #0
	(Ghidra warm-start) counts toward the best score but not the LLM attempt
	total."""
	if not history_dir.is_dir():
		return HistoryBest(match_percent=None, model=None, attempts=0)

	numbers: list[int] = []
	for entry in history_dir.iterdir():
		if entry.suffix != ".c":
			continue
		try:
			numbers.append(int(entry.stem))
		except ValueError:
			continue

	best_pct: float | None = None
	best_n: int | None = None
	for n in sorted(numbers):
		pct = _attempt_match_read(history_dir / f"{n:04d}.diff.json", function_name)
		if pct is not None and (best_pct is None or pct > best_pct):
			best_pct = pct
			best_n = n

	model: str | None = None
	if best_n is not None:
		model_path = history_dir / f"{best_n:04d}.model"
		if model_path.is_file():
			model = model_path.read_text().strip() or None

	attempts = sum(1 for n in numbers if n >= 1)
	return HistoryBest(match_percent=best_pct, model=model, attempts=attempts)
