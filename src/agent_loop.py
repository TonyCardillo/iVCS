"""Matching-decomp agent loop for one function.

Drives an LLM through repeated calls to compile_and_view_assembly, keeping
the highest match_percent seen. Exits on 100% match, iteration budget, or
hard timeout.
"""

import json
import re
import time
from dataclasses import dataclass
from typing import Protocol

from src.compile_tool import (
	CompileAndViewResult,
	CompileFn,
	DiffFn,
	compile_and_view_assembly,
	compile_error_format,
	function_match_percent,
	obj_function_symbol_canonicalize,
)
from src.ghidra_decompile import ghidra_pseudo_c_normalize_for_prompt
from src.workspace import FunctionWorkspace

COMPILE_TOOL_NAME = "compile_and_view_assembly"

_TOOL_SCHEMA: dict = {
	"type": "function",
	"function": {
		"name": COMPILE_TOOL_NAME,
		"description": (
			"Compile the supplied C code (concatenated with ctx.h) and diff "
			"the resulting object against the target. Returns compile errors "
			"if compilation fails, or a structured diff with match_percent "
			"and per-instruction rows if it succeeds."
		),
		"parameters": {
			"type": "object",
			"properties": {
				"c_code": {
					"type": "string",
					"description": "Complete C source for the function under decomp.",
				},
			},
			"required": ["c_code"],
		},
	},
}

_SOFT_TIMEOUT_PROMPT = (
	"You are running out of time. Submit your best C code now via the "
	"compile_and_view_assembly tool. Do not explain, just submit."
)


@dataclass(frozen=True)
class AgentConfig:
	model: str
	api_base: str
	api_key: str = "sk-local"
	max_iterations: int = 15
	hard_timeout_seconds: float = 300.0
	soft_timeout_fraction: float = 0.7


@dataclass(frozen=True)
class AgentResult:
	success: bool
	best_match_percent: float | None
	iterations: int
	termination_reason: str  # matched | budget_exhausted | llm_no_progress | hard_timeout


class LLMClient(Protocol):
	def complete(self, messages: list[dict], tools: list[dict]) -> dict:
		"""Returns an assistant message dict in OpenAI tool-call shape."""


@dataclass
class FakeLLMClient:
	"""Test double: returns scripted responses in order, raises when exhausted."""

	scripted: list[dict]
	_index: int = 0

	def complete(self, messages: list[dict], tools: list[dict]) -> dict:
		if self._index >= len(self.scripted):
			raise RuntimeError(
				f"FakeLLMClient exhausted after {self._index} calls (no more scripted responses)"
			)
		response = self.scripted[self._index]
		self._index += 1
		return response


def assistant_tool_call(tool_name: str, arguments: dict, tool_call_id: str = "call_1") -> dict:
	return {
		"role": "assistant",
		"content": None,
		"tool_calls": [
			{
				"id": tool_call_id,
				"type": "function",
				"function": {
					"name": tool_name,
					"arguments": json.dumps(arguments),
				},
			}
		],
	}


def assistant_text(text: str) -> dict:
	return {"role": "assistant", "content": text}


def agent_loop_run(
	workspace: FunctionWorkspace,
	target_asm: str,
	config: AgentConfig,
	*,
	llm_client: LLMClient,
	compile_fn: CompileFn,
	diff_fn: DiffFn,
) -> AgentResult:
	workspace.validate_inputs()
	_baseline_compile_attempt_zero(workspace, compile_fn=compile_fn)

	messages: list[dict] = [
		{"role": "system", "content": _system_prompt_build(workspace, target_asm)},
		{
			"role": "user",
			"content": "Begin. Use the compile_and_view_assembly tool with your first attempt.",
		},
	]
	tools = [_TOOL_SCHEMA]

	# Inherit prior best so a weaker second run can't clobber a stronger best.c.
	best_match, best_model = _prior_best(workspace)
	best_c_code: str | None = None
	start_time = time.monotonic()
	soft_timeout_injected = False
	iterations = 0

	for _ in range(config.max_iterations):
		elapsed = time.monotonic() - start_time
		if elapsed > config.hard_timeout_seconds:
			return _finalize(workspace, "hard_timeout", best_match, iterations, model=best_model)

		soft_threshold = config.hard_timeout_seconds * config.soft_timeout_fraction
		if not soft_timeout_injected and elapsed > soft_threshold:
			messages.append({"role": "user", "content": _SOFT_TIMEOUT_PROMPT})
			soft_timeout_injected = True

		response = llm_client.complete(messages, tools)
		messages.append(response)

		c_code = _extract_c_code(response)
		if c_code is None:
			return _finalize(workspace, "llm_no_progress", best_match, iterations, model=best_model)

		iterations += 1
		result = compile_and_view_assembly(
			workspace=workspace,
			c_code=c_code,
			compile_fn=compile_fn,
			diff_fn=diff_fn,
		)
		workspace.attempt_model_path(result.attempt_number).write_text(config.model)

		if (
			result.success
			and result.match_percent is not None
			and (best_match is None or result.match_percent > best_match)
		):
			best_match = result.match_percent
			best_model = config.model
			best_c_code = c_code
			workspace.best_c.write_text(c_code)

		if result.match_percent is not None and result.match_percent >= 100.0:
			return _finalize(
				workspace, "matched", best_match, iterations, best_c_code, model=best_model
			)

		tool_call_id = _tool_call_id(response)
		rendered = _render_tool_result(result, workspace.function_name)
		if tool_call_id is None:
			# Fence-sourced code has no tool_use to pair a tool message with.
			messages.append({"role": "user", "content": rendered})
		else:
			messages.append(
				{
					"role": "tool",
					"tool_call_id": tool_call_id,
					"content": rendered,
				}
			)

	return _finalize(workspace, "budget_exhausted", best_match, iterations, model=best_model)


def _prior_best(workspace: FunctionWorkspace) -> tuple[float | None, str | None]:
	"""Recover (best_match_percent, model) from a prior run's result.json.

	Lets a fresh run on an existing workspace inherit the standing best, so a
	weaker second model can't overwrite a stronger best.c and we keep attributing
	the solution to the model that earned it. Returns (None, None) for a fresh
	workspace.
	"""
	if not workspace.result_json.is_file():
		return None, None
	try:
		data = json.loads(workspace.result_json.read_text())
	except (json.JSONDecodeError, OSError):
		return None, None
	best = data.get("best_match_percent")
	model = data.get("model")
	return (
		best if isinstance(best, (int, float)) else None,
		model if isinstance(model, str) else None,
	)


def _baseline_compile_attempt_zero(workspace: FunctionWorkspace, *, compile_fn: CompileFn) -> None:
	"""Compile the Ghidra warm-start as attempt 0 so its match% acts as a baseline.

	The webui lazily derives 0000.diff.json from 0000.obj on first render; we
	only need to ensure 0000.obj exists. On compile failure, persist stderr
	next to 0000.c so the attempt view can show the actual cl.exe error.
	"""
	paths = workspace.attempt_paths(0)
	if not paths.c.is_file() or paths.obj.is_file():
		return
	workspace.attempt_model_path(0).write_text("ghidra")
	result = compile_fn(paths.c, paths.obj, workspace.root)
	if not result.success:
		stderr_path = paths.c.with_suffix(".stderr")
		stderr_path.write_text(compile_error_format(result))
		return
	obj_function_symbol_canonicalize(paths.obj, workspace.function_name)


def ghidra_only_run(
	workspace: FunctionWorkspace,
	*,
	compile_fn: CompileFn,
	diff_fn: DiffFn,
) -> AgentResult:
	"""Compile + diff attempt 0 only; no LLM. Writes result.json with model='ghidra'.

	Termination reasons:
	- 'ghidra_only': baseline compiled and diffed (best_match_percent set)
	- 'compile_failed': baseline compile failed (best_match_percent = None)
	- 'ghidra_unavailable': no 0000.c on disk (warm-start didn't run)
	"""
	workspace.validate_inputs()
	paths = workspace.attempt_paths(0)

	if not paths.c.is_file():
		return _finalize(workspace, "ghidra_unavailable", None, 0, model="ghidra")

	_baseline_compile_attempt_zero(workspace, compile_fn=compile_fn)
	if not paths.obj.is_file():
		return _finalize(workspace, "compile_failed", None, 0, model="ghidra")

	diff = diff_fn(workspace.target_obj, paths.obj, workspace.function_name)
	match = function_match_percent(diff, workspace.function_name)

	if match is not None and match >= 100.0:
		# "matched" so the aggregator counts it. best.c MUST be the normalized
		# source that actually compiled+matched (attempt 0), NOT the raw Ghidra
		# draft — the draft has undefined4/DAT_/FUN_ and won't recompile, which
		# breaks the relink oracle and the source-tree integrator downstream.
		return _finalize(
			workspace,
			"matched",
			match,
			0,
			best_c_code=_baseline_source_body(workspace),
			model="ghidra",
		)
	return _finalize(workspace, "ghidra_only", match, 0, model="ghidra")


def _baseline_source_body(workspace: FunctionWorkspace) -> str | None:
	"""The compilable C the baseline matched with: attempt 0's source minus the
	prepended ctx.h preamble. `_mirror_warmstart_as_attempt_zero` writes
	`0000.c = ctx.h + "\\n" + normalized`, so stripping the ctx.h prefix recovers
	exactly the normalized body — the right thing to record as best.c."""
	paths = workspace.attempt_paths(0)
	if not paths.c.is_file():
		return None
	full = paths.c.read_text()
	ctx = workspace.ctx_h.read_text() if workspace.ctx_h.is_file() else ""
	if ctx and full.startswith(ctx):
		return full[len(ctx) :].lstrip("\n")
	return full


def _system_prompt_build(workspace: FunctionWorkspace, target_asm: str) -> str:
	ctx_h = workspace.ctx_h.read_text()
	warmstart = _warmstart_section(workspace)
	return f"""You are an automated matching-decompilation system targeting the original Xbox \
(x86, MSVC 7.1 / cl 13.10, /O2). You receive an assembly listing and write C code that, \
when compiled, produces byte-identical machine code.

# Operating context
- Fully automated pipeline. No human review. Do not ask for clarification.
- The only tool is `compile_and_view_assembly`. Use it on every attempt.

# Output requirements
- Provide complete, self-contained C code as the `c_code` argument.
- Do not include `#include` directives — ctx.h is prepended automatically.
- MSVC 7.1 is C89: declare all locals at the top of the function. No `for (int i = ...)`.

# Success criteria
- Match score must reach 100.0%. Functional equivalence is insufficient.

# Diff vocabulary
The tool returns per-instruction diff rows with these kinds:
- DIFF_NONE: instruction matches the target
- DIFF_INSERT: your code emitted an extra instruction the target doesn't have
- DIFF_DELETE: target has an instruction your code didn't emit
- DIFF_REPLACE: entire instruction differs
- DIFF_OP_MISMATCH: same operands but different opcode
- DIFF_ARG_MISMATCH: same opcode, one or more args differ (arg index given)

# Strategy
- Read the diff carefully before re-submitting.
- Focus changes on the mismatched instructions; don't rewrite working code.
- Small source changes can produce large codegen changes — that's normal.
- Taking a temporary score drop to try a structural rewrite is allowed.

# Target function
Symbol: {workspace.function_name}

# Target assembly
```asm
{target_asm}
```

# Context header (ctx.h)
```c
{ctx_h}
```
{warmstart}"""


def _warmstart_section(workspace: FunctionWorkspace) -> str:
	if not workspace.ghidra_warmstart.is_file():
		return ""
	draft = ghidra_pseudo_c_normalize_for_prompt(workspace.ghidra_warmstart.read_text())
	return f"""
# Ghidra warm-start draft (machine-generated; may be wrong)
A Ghidra headless decompile of the target function. Use it as a starting point: \
the control flow and called names are usually plausible, but variable types are \
often `undefined4` and locals are over-decomposed. Rewrite freely, but the \
identified callees (kernel imports, helper functions) are reliable.

```c
{draft}```
"""


def _extract_c_code(response: dict) -> str | None:
	"""Falls back to ```c fence in text content when a model skips the tool call."""
	for tool_call in response.get("tool_calls") or []:
		if tool_call.get("function", {}).get("name") != COMPILE_TOOL_NAME:
			continue
		try:
			args = json.loads(tool_call["function"]["arguments"])
		except (KeyError, json.JSONDecodeError):
			continue
		if isinstance(args.get("c_code"), str):
			return args["c_code"]

	content = response.get("content")
	if isinstance(content, str):
		match = re.search(r"```c\s*\n(.*?)```", content, re.DOTALL)
		if match:
			return match.group(1).strip()
		match = re.search(r"```\s*\n(.*?)```", content, re.DOTALL)
		if match:
			return match.group(1).strip()

	return None


def _tool_call_id(response: dict) -> str | None:
	for tool_call in response.get("tool_calls") or []:
		return tool_call.get("id", "call_unknown")
	return None


def _render_tool_result(result: CompileAndViewResult, function_name: str) -> str:
	if not result.success:
		return f"COMPILE FAILED:\n{result.error or '(no output)'}"

	lines = [f"Match: {result.match_percent}%"]
	if result.diff_result is None:
		return "\n".join(lines)

	fn_symbol = None
	for symbol in result.diff_result.function_symbols("left"):
		if symbol.name == function_name:
			fn_symbol = symbol
			break

	if fn_symbol is None:
		lines.append(f"(symbol {function_name!r} not found in diff)")
		return "\n".join(lines)

	lines.append("Diff rows:")
	for row in fn_symbol.instructions:
		kind = row.diff_kind.value.removeprefix("DIFF_")
		if row.instruction is None:
			lines.append(f"  [{kind}]")
		else:
			tag = f"[{kind}"
			if row.arg_diff_indices:
				tag += f" args={list(row.arg_diff_indices)}"
			tag += "]"
			lines.append(f"  {tag:32s} {row.instruction.formatted}")
	return "\n".join(lines)


def _finalize(
	workspace: FunctionWorkspace,
	reason: str,
	best_match: float | None,
	iterations: int,
	best_c_code: str | None = None,
	*,
	model: str,
) -> AgentResult:
	success = reason == "matched"
	result = AgentResult(
		success=success,
		best_match_percent=best_match,
		iterations=iterations,
		termination_reason=reason,
	)
	workspace.result_json.write_text(
		json.dumps(
			{
				"success": success,
				"best_match_percent": best_match,
				"iterations": iterations,
				"termination_reason": reason,
				"function_name": workspace.function_name,
				"model": model,
			},
			indent=2,
		)
	)
	if best_c_code is not None and not workspace.best_c.is_file():
		workspace.best_c.write_text(best_c_code)
	return result


__all__ = [
	"AgentConfig",
	"AgentResult",
	"FakeLLMClient",
	"LLMClient",
	"agent_loop_run",
	"assistant_text",
	"assistant_tool_call",
	"ghidra_only_run",
]
