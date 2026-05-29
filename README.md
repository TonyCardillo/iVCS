# iVCS - intelligent Visual Code System

LLM-driven matching decompilation, targeting the original Xbox.

The pipeline currently functions end-to-end. See [Roadmap](#roadmap) for next steps.

## Pipeline

```
default.xbe (4.6 MB)
   │
   ├─ xbe_load + xbe_function_carve(va, size)        ← src/xbe.py
   ├─ relocs_resolve                                  ← src/relocs.py
   │     ├─ REL32  call rel32/jmp rel32/jcc rel32  →  _sub_*   or  _data_*
   │     └─ DIR32  call/jmp [imm32]                →  __imp__<mangled>  for kernel-thunk slots
   ├─ coff_object_build → target.obj                  ← src/coff.py
   │     (one .text section + IMAGE_REL_I386_{REL32,DIR32} relocs +
   │      static .text section symbol + external per unique reloc target)
   │
   ▼
FunctionWorkspace                                     ← src/workspace.py
   target.obj          (ground truth)
   ctx.h               (typedefs + __declspec(dllimport) externs)
   history/NNNN.{c,obj,diff.json}
   best.c, result.json
   │
   ▼
agent_loop_run                                        ← src/agent_loop.py
   ↻ LLM proposes C → compile_and_view_assembly
                       │
                       ├─ cl.exe /c /O2 (Wine)        ← src/compile_tool.py
                       └─ objdiff-cli diff JSON        ← src/objdiff.py
   exit on 100% match, budget exhausted, or LLM gives up
```

## What it does today

- Parses XBE: header, sections, XOR-decoded entry-point + kernel-thunk
  table, kernel-ordinal-to-name resolution
- Carves real functions from arbitrary virtual addresses in real shipped XBEs
- Discovers relocations in carved bytes via Capstone
- Synthesizes valid Microsoft COFF/i386 `.obj` files that
  `objdiff-cli` parses cleanly and lines up against MSVC-emitted base objects
- Runs a matching-decomp agent loop via LiteLLM (tested with Anthropic Claude Haiku)

## Quickstart

```bash
# 1. Set up
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. Run the test suite
pytest

# 3. End-to-end demo on a real Halo 2 function (requires Wine + XDK 5849 cl.exe + ANTHROPIC_API_KEY)
# Place a Halo 2 default.xbe at /tmp/halo2_default.xbe first.
IVCS_MSVC_DIR=/path/to/xdk5849-vc71 \
IVCS_WINE=wine \
IVCS_OBJDIFF_CLI=$(pwd)/recon/objdiff-smoke/objdiff-cli \
ANTHROPIC_API_KEY=sk-ant-... \
python scripts/halo2_demo.py
```

Environment:

| variable | purpose | default |
|---|---|---|
| `IVCS_MSVC_DIR` | Root of the XDK 5849 VC7.1 toolchain (must contain `bin/cl.exe`). Layout: `bin/`, `include/`, `lib/`. | `/Users/entmoot/Code/xdk5849-vc71` |
| `IVCS_WINE` | Wine binary to invoke `cl.exe` with. | `wine` (on PATH) |
| `IVCS_OBJDIFF_CLI` | Path to the `objdiff-cli` binary. | `objdiff-cli` (on PATH) |

## Repo layout

```
src/
  xbe.py            XBE format parser, function carving, XOR-decoded addresses
  xboxkrnl.py       371-entry ordinal → name table (ports abaire/xbdm_gdb_bridge data)
  relocs.py         REL32 + DIR32 discovery via Capstone; __imp__ resolution
  coff.py           Microsoft COFF/i386 .obj emitter
  carver.py         Three-line orchestrator: carve → resolve → coff
  workspace.py      Per-function filesystem layout
  compile_tool.py   The single tool the LLM agent gets; wraps cl.exe + objdiff
  agent_loop.py     LLM loop policy (budget, soft/hard timeouts, best tracking)
  llm_clients.py    LiteLLM client adapter (works with local/cloud providers)
  objdiff.py        objdiff-cli wrapper + typed JSON parser

tests/
scripts/
  smoke_run.py      End-to-end agent loop against the bundled objdiff-smoke fixture (no XBE needed)
  halo2_sanity.py   End-to-end pipeline diagnostic against a real Halo 2 XBE
  halo2_demo.py     Full carve → workspace → agent loop run
  webui.py          Local web UI for inspecting an XBE (sections, hex, disassembly, kernel ordinals)
recon/objdiff-smoke/
                    Real MSVC-emitted .obj fixtures + a bundled objdiff-cli
data/xboxkrnl_ordinals.json
                    Source of xboxkrnl exports
```

## Why Xbox

A mix of nostalgia and more greenfield decomp scene!

## Roadmap

In rough order of leverage:

1. **Calling-convention inference for internal callees** — disassemble the
   first/last bytes of each REL32 target, detect `ret imm16` → emit
   `_sub_*@N` symbol name. Closes the `__stdcall` `@N` decoration
   mismatches observed on every Halo 2 function tried so far.
2. **Auto-`ctx.h` synthesis** — from the `__imp__*` symbol set, look up each
   kernel function's signature from a bundled table and emit
   `__declspec(dllimport)` declarations automatically.
3. **Function-size discovery** — promote the linear-sweep "scan-until-ret"
   heuristic from the demo into `src/xbe.py`.
4. **Warm-start decompiler** — pipe carved bytes through Ghidra headless (or
   RetDec) for a pseudo-C first draft. The LLM "fixes" instead of "writes
   from scratch" — drastically higher first-attempt match rates per
   [mizuchi](https://github.com/macabeus/mizuchi)'s experience with `m2c`.
5. **Source-tree integrator** — splat-style YAML project layout, with the
   matched C committed back per-function.
6. **Codebase index + embeddings** — once we have ≥5 matched functions,
   embed them and retrieve similar examples as few-shot prompt context.
7. **x86 permuter** — non-LLM C-source mutation engine (swap commutative ops,
   reorder local declarations, equivalent idioms) to brute-force the
   last-mile register-allocation gap without spending LLM tokens. Original
   `decomp-permuter` is MIPS-focused; an x86 port is real work but pays off
   forever.

## Known constraints

- **Wine-stable deprecation (2026-09-01).** Migrate to Whisky before then.
- **Toolchain pinned to XDK 5849 (cl 13.10.3077, VC++ 7.1).** Verified
  byte-identical to Halo 2 retail's CRT via `__chkstk` extraction from
  `libcmt.lib`. Titles built on a different XDK family (e.g. 5933) would
  need the cl from that XDK to match.

## Out of scope

- C++ class recovery (vtables → classes)
- Whole-program optimization (`/GL` + `/LTCG`)
- Other consoles
- General-purpose decompilation (not trying to be Ghidra/IDA)
- Obfuscation / anti-debug handling

## Acknowledgments

- [Capstone](http://www.capstone-engine.org/) — disassembly
- [Cxbx-Reloaded](https://github.com/Cxbx-Reloaded/Cxbx-Reloaded) — XBE format
  reference
- [abaire/xbdm_gdb_bridge](https://github.com/abaire/xbdm_gdb_bridge) —
  `xboxkrnl.exe` ordinal table (`src/dyndxt_loader/xboxkrnl_exports.def.h`)
- [objdiff](https://github.com/encounter/objdiff) — instruction-aware .obj
  diffing
- [decomp.me](https://decomp.me) — scratch model + the `ctx.h` + extern
  pattern this project mirrors
- [mizuchi](https://github.com/macabeus/mizuchi) — pipeline-stage architecture
  ideas (m2c → permuter → LLM → compiler → objdiff → integrator)
- Microsoft Xbox XDK 5849 (Dec 2003) — the original Halo 2 toolchain
  (cl 13.10.3077, `libcmt.lib`), run under Wine
- [widberg/msvc8.0p](https://github.com/widberg/msvc8.0p) — initial
  exploratory toolchain (VC 8.0); superseded
- Chris Lewis, [The Unexpected Effectiveness of One-Shot Decompilation
  with Claude](https://blog.chrislewis.au/the-unexpected-effectiveness-of-one-shot-decompilation-with-claude/)
- The matching-decomp community at decomp.me
