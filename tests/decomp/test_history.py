"""Tests for the on-disk attempt-history reader.

`history_best_read` recovers the standing-best match% / model / attempt count
straight from the cached `history/NNNN.diff.json` files, so neither the progress
view nor the agent loop has to trust a clobberable result.json summary.
"""

import json
from pathlib import Path

from src.decomp.history import HistoryBest, history_best_read


def _write_attempt(history: Path, n: int, match_percent: float | None, model: str | None) -> None:
	"""Lay down one attempt the way the loop + webui leave it on disk."""
	history.mkdir(parents=True, exist_ok=True)
	stem = f"{n:04d}"
	(history / f"{stem}.c").write_text(f"// attempt {n}\n")
	if match_percent is not None:
		(history / f"{stem}.diff.json").write_text(
			json.dumps(
				{
					"left": {
						"symbols": [
							{
								"name": "_fn_00012000",
								"kind": "SYMBOL_FUNCTION",
								"match_percent": match_percent,
							}
						]
					}
				}
			)
		)
	if model is not None:
		(history / f"{stem}.model").write_text(model)


class TestHistoryBestRead:
	def test_missing_history_is_empty_example(self, tmp_path: Path):
		assert history_best_read(tmp_path / "nope") == HistoryBest(
			match_percent=None, model=None, attempts=0
		)

	def test_picks_strongest_attempt_example(self, tmp_path: Path):
		history = tmp_path / "history"
		_write_attempt(history, 1, 67.9, "alpha")
		_write_attempt(history, 2, 79.8, "beta")
		_write_attempt(history, 3, 70.0, "gamma")

		best = history_best_read(history)
		assert best.match_percent == 79.8
		assert best.model == "beta"
		assert best.attempts == 3

	def test_best_is_invariant_under_attempt_order_permutation(self, tmp_path: Path):
		# Oracle/invariant: the strongest attempt wins no matter what order the
		# files happen to be enumerated in — write them shuffled, same answer.
		history = tmp_path / "history"
		for n, pct in ((2, 79.8), (5, 50.0), (1, 67.9), (4, 79.8), (3, 12.0)):
			_write_attempt(history, n, pct, f"m{n}")

		best = history_best_read(history)
		assert best.match_percent == 79.8
		# Ties broken by earliest attempt — best.c ownership convention.
		assert best.model == "m2"
		assert best.attempts == 5

	def test_clobbered_summary_recovered_from_diffs_example(self, tmp_path: Path):
		# The reported bug shape: a later attempt fails to score (symbol mismatch
		# → no diff match%), yet the earlier attempts still hold a real best.
		history = tmp_path / "history"
		_write_attempt(history, 1, 67.9, "haiku")
		_write_attempt(history, 8, 79.8, "haiku")
		_write_attempt(history, 9, None, "haiku")  # failed attempt, no score

		best = history_best_read(history)
		assert best.match_percent == 79.8
		assert best.attempts == 3

	def test_unscored_attempts_yield_none_example(self, tmp_path: Path):
		history = tmp_path / "history"
		_write_attempt(history, 1, None, "haiku")
		_write_attempt(history, 2, None, "haiku")

		best = history_best_read(history)
		assert best.match_percent is None
		assert best.attempts == 2

	def test_baseline_attempt_zero_excluded_from_count_example(self, tmp_path: Path):
		# 0000 is the Ghidra warm-start baseline, not an LLM iteration: it counts
		# toward the best match% but not the reported attempt total.
		history = tmp_path / "history"
		_write_attempt(history, 0, 30.0, "ghidra")
		_write_attempt(history, 1, 55.0, "alpha")

		best = history_best_read(history)
		assert best.match_percent == 55.0
		assert best.attempts == 1
