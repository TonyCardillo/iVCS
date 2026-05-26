# Agent loop design

A design sketch for iVCS v2's matching-decomp agent. Informed by `macabeus/mizuchi`'s tool-using pattern and the iVCS primitives we already have (`src/xbe.py`, `src/objdiff.py`, `src/xboxkrnl.py`, `src/decoder.py`, `src/cfg.py`). No code yet — this is the shape to react to before writing it.

## What the loop is for

Given one Xbox function — assembly, address, expected signature, surrounding context — produce C source that compiles (under `widberg/msvc8.0p`) to a byte-identical object. The "unit of work" is **one function per loop**.

Multi-function decomp is just running the loop many times. Cross-function context (struct layouts, neighboring symbols) feeds in as static input — the loop itself doesn't reason about *other* functions.

## Shape, end-to-end

```
                           ┌────────────────────────────────────────────┐
                           │                                            │
                           │              one function                  │
                           │                                            │
                           │   ┌──────────────────────────────────┐     │
                           │   │  per-function workspace          │     │
                           │   │    target.obj   (ground truth)   │     │
                           │   │    ctx.h        (struct/typedef) │     │
                           │   │    history/     (every attempt)  │     │
                           │   │    best.c       (highest score)  │     │
                           │   └──────────────────────────────────┘     │
                           │                                            │
                           │   ┌──────────────────────────────────┐     │
                           │   │  one Claude conversation         │     │
                           │   │  ┌───────────────────────┐       │     │
                           │   │  │ system prompt         │       │     │
                           │   │  │  + diff-kind glossary │       │     │
                           │   │  │  + target assembly    │       │     │
                           │   │  │  + ctx.h excerpt      │       │     │
                           │   │  │  + tools available    │       │     │
                           │   │  └───────────────────────┘       │     │
                           │   │  ┌───────────────────────┐       │     │
                           │   │  │ Claude proposes C     │       │     │
                           │   │  │ → tool call:          │       │     │
                           │   │  │   compile_and_view    │       │     │
                           │   │  │ ← compile result +    │       │     │
                           │   │  │   structured diff     │       │     │
                           │   │  │ Claude reasons,       │       │     │
                           │   │  │ proposes refined C    │       │     │
                           │   │  │ → tool call again     │       │     │
                           │   │  │ ...                   │       │     │
                           │   │  │ until: score == 100%  │       │     │
                           │   │  │     or: budget spent  │       │     │
                           │   │  │     or: soft timeout  │       │     │
                           │   │  └───────────────────────┘       │     │
                           │   └──────────────────────────────────┘     │
                           │                                            │
                           └────────────────────────────────────────────┘
```

This shape is **fundamentally different from v0.1's `src/agent.py`** (which regenerated the whole function on every iteration). The model holds a single conversation, calls a tool repeatedly, and refines its own output. This is the natural Claude tool-use pattern and is what mizuchi proved works.

## The tool the LLM gets: `compile_and_view_assembly`

The single most important tool. The model writes C, hands it to this tool, gets back:

- Compile success/failure (`stderr` if failed)
- The function's compiled assembly, side-by-side with target
- **The structured diff from `src/objdiff.py`** — per-instruction diff kind (NONE / INSERT / DELETE / REPLACE / OP_MISMATCH / ARG_MISMATCH), per-argument diff indices, current `match_percent`

Tool definition (sketch, in Anthropic tool-use format):

```python
{
    "name": "compile_and_view_assembly",
    "description": (
        "Compile the provided C code, link against ctx.h, and diff "
        "the resulting function against the target. Returns the diff "
        "summary including match_percent and per-instruction diff "
        "rows."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "c_code": {
                "type": "string",
                "description": "Full C source for the function under decomp.",
            },
        },
        "required": ["c_code"],
    },
}
```

The tool handler:
1. Concatenate `ctx.h` + input C
2. Invoke `wine cl.exe /c /O2 ...` to produce `attempt.obj`
3. If compile failed → return error message verbatim (no diff)
4. Else: `objdiff_run(target.obj, attempt.obj, symbol=fn_name)`
5. Render the `DiffResult` as compact structured text the model can reason about
6. Return that string

## Termination conditions

1. **Match**: `match_percent == 100.0` → success, write `best.c` and exit
2. **Budget exhausted**: hit `max_iterations` (default ~20) → save best so far, exit non-success
3. **Soft timeout** (mizuchi pattern): at 0.7× of hard timeout, send one extra user message: *"You're running out of time. Submit your best C code now in a `c` block. Do not call any more tools."* Then capture and exit
4. **Hard timeout**: kill the conversation, persist current best

## Rollback strategy

A subtle but important design choice: **do not auto-revert every score regression.**

The naive policy ("keep edit iff `match_percent` improved") gets stuck on local optima. A good decompiler will sometimes propose a structural rewrite that *temporarily* drops the score before climbing higher. Claude can reason about this in conversation.

What we *do* enforce:
- Persist `best.c` as the highest-`match_percent` attempt seen so far, regardless of the model's current state. If the run ends without a match, we hand back the best, not the last.
- If the conversation drifts (e.g., score has not improved in N consecutive tool calls), the loop *can* inject a system message: *"Your last 5 attempts have not improved on `best.c` (match: X%). Consider restarting from `best.c`."* Don't force it, suggest it.

## Caching

Per-prompt cache keyed by **content hash of the full prompt and tool history at the moment of each LLM call**. Two effects:

- Re-running the same function (after fixing the harness, e.g.) skips already-computed responses
- Stops short of caching `compile_and_view_assembly` results — those are deterministic given input C (modulo COFF timestamps, which objdiff ignores), so a separate `(c_code_hash) → diff` cache pays off massively when the model proposes the same C in different contexts

Two-tier cache layout:
```
~/.cache/ivcs/
├── llm/<conversation_id>.jsonl          # LLM response cache, append-only
└── compile/<c_code_sha256>.json         # diff JSON cache (90% of hits in practice)
```

## What goes in the system prompt

Borrowing mizuchi's structure, with substitutions:

1. **Operating context**: fully automated pipeline, no human review, no clarification questions
2. **Output requirements**: C code in a fenced block; system extracts the last ```c fence as the candidate
3. **Success criteria**: byte-identical compiled assembly; functional equivalence is *insufficient*
4. **Available tools**: spec for `compile_and_view_assembly` with field-by-field description of what it returns
5. **Diff-kind glossary** (verbatim from `src/objdiff.py`'s `DiffKind` enum):
   - `DIFF_NONE` — instruction matches
   - `DIFF_INSERT` — present in our compiled output, absent in target → we generated extra code
   - `DIFF_DELETE` — present in target, absent in ours → we're missing code
   - `DIFF_REPLACE` — entire instruction differs
   - `DIFF_OP_MISMATCH` — same operands, different opcode (rare)
   - `DIFF_ARG_MISMATCH` — same opcode, different argument(s); `arg_diff_indices` tells you which
6. **MSVC 8 C-mode dialect notes**: C89 only, declare all locals at function top, `__stdcall` calling convention by default, no `inline` keyword
7. **Target-specific context**: address of the function in the XBE, expected calling convention, expected return type if known
8. **The target assembly** (from `xbe_section_read()` + `Decoder` from `src/decoder.py`)
9. **`ctx.h` excerpt** — types, kernel function signatures (from `xboxkrnl_mangled_get()`), neighboring struct definitions

## How the existing iVCS primitives fit

| Primitive | Used for |
|---|---|
| `src/xbe.py` | Pull target function bytes out of `.text` by address range |
| `src/decoder.py` | Render target assembly as text for the prompt |
| `src/cfg.py` | (Optional) include CFG summary in prompt as a structural hint |
| `src/xboxkrnl.py` | Resolve thunk-table imports to names → populate `ctx.h` |
| `src/objdiff.py` | The tool's structured response; renders the diff for the model |

`src/agent.py` and `src/verifier.py` from v0.1 are obsoleted by this design and should be deleted in the same commit that lands the new loop. The shape is incompatible; keeping them around invites confusion.

## Decisions (locked in)

1. **LLM client: LiteLLM against local OpenAI-compatible endpoints. Claude/cloud APIs are out of scope.** Rationale: no API costs, no source-of-the-game-assembly leaving the machine, fully self-contained iteration. Practical implication: tool use depends on the local model's native tool-calling ability. Qwen2.5-Coder, Qwen3-Coder, Llama 3.1+, and DeepSeek-Coder all emit OpenAI-style `tool_calls`; older or distilled models may not. Recommended default: Qwen3-Coder-30B or similar via LM Studio / Ollama / vLLM at `http://127.0.0.1:1234/v1`.

2. **Exactly one tool: `compile_and_view_assembly`.** No `read_neighboring_function`, no `read_ctx_h`, no filesystem access. The full target assembly and full `ctx.h` go in the initial prompt. Mizuchi gets by with this; we will too.

3. **Best-so-far persistence, not every-iteration revert.** The loop tracks `best.c` (highest `match_percent` seen). Score regressions are *not* auto-reverted — the model is free to take temporary drops to escape local optima. If we end without a match, we hand back `best`, not last.

4. **CLI shape: `ivcs match --xbe ... --address ... --output ...`** — one function per invocation. Project-wide orchestration is layered above (a separate `ivcs run-project` or shell `xargs` over a function list).

## Single-function focus, deferred concerns

These were noted earlier as "open questions" but reduce to *out of scope for v2.0*:

- **Concurrency.** Inner loop is a single-function function; orchestrator handles parallelism. Not in the inner loop's design.
- **Budget exhaustion.** Persist `best`, exit non-success. Permuter is a Phase 4 milestone.
- **Token budget.** Start with 15 tool calls / 5 min hard / 3 min soft; tune by observation. Less critical than for cloud APIs since local-LLM tokens are free.

## What we're explicitly NOT building in the first cut

- Decomp-permuter integration (Phase 4)
- Function-similarity embeddings / "what to do next" picker (mizuchi has this; nice-to-have, not required)
- Web UI (CLI only; we have an objdiff-cli prebuilt that gives us a TUI for free if we want it)
- Multi-LLM ensembling (one Claude conversation per function)
- C++ class recovery (vtables, RTTI) — comes after a single C function matches reliably

## The thinnest possible MVP, concretely

Three files, roughly:

```
src/
├── agent_loop.py      # AgentLoop(workspace).run() → Result
├── compile_tool.py    # the compile_and_view_assembly tool implementation
└── workspace.py       # FunctionWorkspace dataclass + filesystem layout
```

Plus a CLI entry point that takes an XBE + a function address + an output dir and runs the loop:

```bash
ivcs match \
  --xbe path/to/game.xbe \
  --address 0x0001A340 \
  --output workspace/0001A340/
```

That's the v2.0 minimum-viable scope. Everything else — project-wide orchestration, parallelism, embeddings, permuter — is plumbing around this core.
