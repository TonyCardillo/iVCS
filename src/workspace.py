"""Per-function workspace: filesystem layout for one matching-decomp attempt.

Layout (rooted at workspace.root):

    target.obj          ← ground truth, caller-supplied
    ctx.h               ← struct/typedef context, caller-supplied
    history/
        0001.c          ← attempt 1 source
        0001.obj        ← attempt 1 compiled output
        0001.diff.json  ← objdiff result for attempt 1
        0002.c
        ...
    best.c              ← copy of the highest-match_percent attempt
    result.json         ← final state when the loop exits

This module is purely a path manager — it doesn't compile, doesn't diff,
doesn't run the loop. Those concerns live in compile_tool.py and
agent_loop.py.
"""

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AttemptPaths:
    c: Path
    obj: Path
    diff_json: Path


@dataclass(frozen=True)
class FunctionWorkspace:
    root: Path
    function_name: str

    @property
    def target_obj(self) -> Path:
        return self.root / "target.obj"

    @property
    def ctx_h(self) -> Path:
        return self.root / "ctx.h"

    @property
    def history_dir(self) -> Path:
        return self.root / "history"

    @property
    def best_c(self) -> Path:
        return self.root / "best.c"

    @property
    def result_json(self) -> Path:
        return self.root / "result.json"

    def attempt_paths(self, n: int) -> AttemptPaths:
        if n < 1:
            raise ValueError(f"attempt number must be >= 1, got {n}")
        stem = f"{n:04d}"
        return AttemptPaths(
            c=self.history_dir / f"{stem}.c",
            obj=self.history_dir / f"{stem}.obj",
            diff_json=self.history_dir / f"{stem}.diff.json",
        )

    def initialize(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.history_dir.mkdir(exist_ok=True)

    def validate_inputs(self) -> None:
        if not self.target_obj.is_file():
            raise FileNotFoundError(f"target.obj missing at {self.target_obj}")
        if not self.ctx_h.is_file():
            raise FileNotFoundError(f"ctx.h missing at {self.ctx_h}")

    def attempts_existing(self) -> list[int]:
        if not self.history_dir.is_dir():
            return []
        numbers: list[int] = []
        for entry in self.history_dir.iterdir():
            if entry.suffix != ".c":
                continue
            try:
                numbers.append(int(entry.stem))
            except ValueError:
                continue
        return sorted(numbers)

    def next_attempt_number(self) -> int:
        existing = self.attempts_existing()
        return (existing[-1] + 1) if existing else 1
