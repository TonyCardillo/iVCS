"""Typed wrapper around `objdiff-cli diff`.

Pure parser (objdiff_parse) split from the subprocess runner (objdiff_run) so
tests stay offline. Mirrors only the diff.proto fields the agent loop consumes:
https://github.com/encounter/objdiff/blob/main/objdiff-core/protos/diff.proto
"""

import json
import subprocess
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class DiffKind(StrEnum):
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
	"""left = target, right = base."""

	symbols: tuple[DiffSymbol, ...] = ()


@dataclass(frozen=True)
class DiffResult:
	left: DiffSide | None = None
	right: DiffSide | None = None

	def function_symbols(self, side: str = "left") -> tuple[DiffSymbol, ...]:
		"""objdiff also emits section markers ([.drectve], [.text]) and metadata
		(@feat.00); filter those out."""
		s = self.left if side == "left" else self.right
		if s is None:
			return ()
		return tuple(sym for sym in s.symbols if sym.kind == SYMBOL_KIND_FUNCTION)


def objdiff_parse(raw: dict) -> DiffResult:
	return DiffResult(
		left=_diff_side_parse(raw.get("left")),
		right=_diff_side_parse(raw.get("right")),
	)


def function_match_percent(diff: DiffResult, function_name: str) -> float | None:
	"""The match% of the function symbol named `function_name`, target (left)
	side first then base (right). None when neither side scores that symbol.

	Name-matched on purpose: a best.c that defines helper functions yields
	several function symbols, but only the verification target's score counts."""
	for side in ("left", "right"):
		for symbol in diff.function_symbols(side):
			if symbol.name == function_name:
				return symbol.match_percent
	return None


def objdiff_run(
	target_obj: Path | str,
	base_obj: Path | str,
	symbol: str | None = None,
	cli_path: Path | str = "objdiff-cli",
	timeout_seconds: float = 30.0,
) -> DiffResult:
	"""Raises CalledProcessError if the CLI returns non-zero."""
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
	diff_kind = (
		DiffKind(diff_kind_raw) if diff_kind_raw in DiffKind._value2member_map_ else DiffKind.NONE
	)

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
