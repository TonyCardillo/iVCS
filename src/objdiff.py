"""Typed Python wrapper around `objdiff-cli diff`.

Designed for the iVCS agent loop. Two halves:
- objdiff_parse(): pure function from JSON dict to typed DiffResult. Testable
  with fixture JSON; no subprocess.
- objdiff_run(): spawns objdiff-cli, returns parsed DiffResult.

We mirror the diff.proto schema only for the fields the agent loop will
actually consume — match_percent per symbol, per-instruction diff_kind,
formatted instruction text, branch_dest. Full schema is in
objdiff-core/protos/diff.proto if more fields are needed later.

Reference: https://github.com/encounter/objdiff/blob/main/objdiff-core/protos/diff.proto
"""

import json
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class DiffKind(str, Enum):
    """Per-instruction diff classification (mirrors objdiff's DiffKind enum)."""

    NONE = "DIFF_NONE"
    REPLACE = "DIFF_REPLACE"
    DELETE = "DIFF_DELETE"
    INSERT = "DIFF_INSERT"
    OP_MISMATCH = "DIFF_OP_MISMATCH"
    ARG_MISMATCH = "DIFF_ARG_MISMATCH"


@dataclass(frozen=True)
class DiffInstruction:
    formatted: str
    mnemonic: str
    address: int | None = None
    branch_dest: int | None = None


@dataclass(frozen=True)
class DiffInstructionRow:
    diff_kind: DiffKind
    instruction: DiffInstruction | None = None
    # Indices of arguments that differ from the other side. Empty if no arg diffs
    # or no instruction (e.g., on INSERT/DELETE rows the instruction may be absent).
    arg_diff_indices: tuple[int, ...] = ()


SYMBOL_KIND_FUNCTION = "SYMBOL_FUNCTION"


@dataclass(frozen=True)
class DiffSymbol:
    name: str
    kind: str
    match_percent: float | None
    instructions: tuple[DiffInstructionRow, ...] = ()


@dataclass(frozen=True)
class DiffSide:
    """One side of a diff (left = target, right = base)."""

    symbols: tuple[DiffSymbol, ...] = ()


@dataclass(frozen=True)
class DiffResult:
    left: DiffSide | None = None
    right: DiffSide | None = None

    def function_symbols(self, side: str = "left") -> tuple[DiffSymbol, ...]:
        """Convenience: return only SYMBOL_FUNCTION symbols from one side.

        Real objdiff output includes section markers like [.drectve], [.text]
        and metadata objects like @feat.00 mixed in with function symbols;
        the agent loop only cares about functions.
        """
        s = self.left if side == "left" else self.right
        if s is None:
            return ()
        return tuple(sym for sym in s.symbols if sym.kind == SYMBOL_KIND_FUNCTION)


def objdiff_parse(raw: dict) -> DiffResult:
    """Convert objdiff-cli's JSON dict into a typed DiffResult."""
    return DiffResult(
        left=_diff_side_parse(raw.get("left")),
        right=_diff_side_parse(raw.get("right")),
    )


def objdiff_run(
    target_obj: Path | str,
    base_obj: Path | str,
    symbol: str | None = None,
    cli_path: Path | str = "objdiff-cli",
    timeout_seconds: float = 30.0,
) -> DiffResult:
    """Spawn objdiff-cli to diff two object files; return parsed result.

    Raises CalledProcessError if the CLI returns non-zero.
    """
    cmd: list[str] = [
        str(cli_path),
        "diff",
        "-1",
        str(target_obj),
        "-2",
        str(base_obj),
        "--format",
        "json",
        "-o",
        "-",
    ]
    if symbol is not None:
        cmd.append(symbol)

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=True,
    )
    return objdiff_parse(json.loads(result.stdout))


def _diff_side_parse(side: dict | None) -> DiffSide | None:
    if side is None:
        return None
    symbols = tuple(_diff_symbol_parse(s) for s in side.get("symbols", []))
    return DiffSide(symbols=symbols)


def _diff_symbol_parse(s: dict) -> DiffSymbol:
    raw = s.get("match_percent")
    if raw is None:
        raw = s.get("matchPercent")  # tolerate camelCase from alternate serializers
    match_percent = float(raw) if raw is not None else None

    kind = s.get("kind", "")
    if not isinstance(kind, str):
        kind = ""

    instructions = tuple(_diff_row_parse(r) for r in s.get("instructions", []))
    return DiffSymbol(
        name=s["name"],
        kind=kind,
        match_percent=match_percent,
        instructions=instructions,
    )


def _diff_row_parse(row: dict) -> DiffInstructionRow:
    # JSON omits diff_kind when it's DIFF_NONE (the proto default).
    diff_kind_raw = row.get("diff_kind") or row.get("diffKind") or DiffKind.NONE.value
    diff_kind = DiffKind(diff_kind_raw) if diff_kind_raw in DiffKind._value2member_map_ else DiffKind.NONE

    instruction = _diff_instruction_parse(row.get("instruction"))
    arg_diff_indices = _arg_diff_parse(row.get("arg_diff") or row.get("argDiff") or [])
    return DiffInstructionRow(
        diff_kind=diff_kind,
        instruction=instruction,
        arg_diff_indices=arg_diff_indices,
    )


def _diff_instruction_parse(instr: dict | None) -> DiffInstruction | None:
    if instr is None:
        return None

    formatted = instr.get("formatted", "")
    address = _int_or_none(instr.get("address"))
    branch_dest = _int_or_none(instr.get("branch_dest") or instr.get("branchDest"))

    mnemonic = ""
    for part in instr.get("parts", []):
        opcode = part.get("opcode")
        if isinstance(opcode, dict) and "mnemonic" in opcode:
            mnemonic = opcode["mnemonic"]
            break

    return DiffInstruction(
        formatted=formatted,
        mnemonic=mnemonic,
        address=address,
        branch_dest=branch_dest,
    )


def _arg_diff_parse(args: list) -> tuple[int, ...]:
    """Return indices of arguments that have a non-null diff_index."""
    indices: list[int] = []
    for i, arg in enumerate(args):
        if not arg:
            continue
        if "diff_index" in arg or "diffIndex" in arg:
            indices.append(i)
    return tuple(indices)


def _int_or_none(value) -> int | None:
    if value is None:
        return None
    if isinstance(value, str):
        return int(value)
    return int(value)
