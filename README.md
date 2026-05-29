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
                       ├─ cl.exe                       ← src/compile_tool.py
                       └─ objdiff-cli diff JSON        ← src/objdiff.py
   exit on 100% match, budget exhausted, or LLM gives up
```

## What it does today

- Parses XBE: header, sections, XOR-decoded entry-point + kernel-thunk
  table, kernel-ordinal-to-name resolution
- Enumerates every function in an XBE into a `project.json` manifest
- Carves functions from arbitrary virtual addresses in real XBEs
- Discovers relocations in carved bytes via Capstone
- Synthesizes valid Microsoft COFF/i386 `.obj` files that
  `objdiff-cli` parses cleanly and lines up against MSVC-emitted base objects
- Seeds attempt 0 with a Ghidra headless pseudo-C warm-start (optional)
- Runs a matching-decomp agent loop via LiteLLM

## Quickstart

```bash
# 1. Set up
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. Run the test suite
pytest

# 3. End-to-end agent-loop demo (requires Wine + XDK 5849 cl.exe; no XBE needed)
ANTHROPIC_API_KEY=sk-ant-... python scripts/smoke_run.py
```

Environment:

| variable | purpose | default |
| --- | --- | --- |
| `IVCS_MSVC_DIR` | Root of the XDK 5849 VC7.1 toolchain containing `bin/cl.exe`. | `<repo>/compilers/xdk5849-vc71` |
| `IVCS_WINE` | Wine binary to invoke `cl.exe`. | `wine` (on PATH) |
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
  project.py        Project manifest (project.json) load/save
  compile_tool.py   The single tool the LLM agent gets; wraps cl.exe + objdiff
  agent_loop.py     LLM loop policy (budget, soft/hard timeouts, best tracking)
  ghidra_decompile.py  Ghidra-headless warm-start: pseudo-C drafts for attempt 0
  launcher.py       Carve → synth target.obj → spawn an agent_loop run (UI entry point)
  llm_clients.py    LiteLLM client adapter (works with local/cloud providers)
  objdiff.py        objdiff-cli wrapper + typed JSON parser

tests/
scripts/
  enumerate.py      Enumerate all functions in an XBE → project.json manifest
  smoke_run.py      End-to-end agent loop against the bundled objdiff-smoke fixture (no XBE needed)
  halo2_sanity.py   End-to-end pipeline diagnostic against a real Halo 2 XBE
  webui.py          Local web UI for inspecting an XBE (sections, hex, disassembly, kernel ordinals)
ghidra_scripts/DecompileOne.java
                    Ghidra postscript: decompile one function by VA (see docs/ghidra_setup.md)
recon/objdiff-smoke/
                    Real MSVC-emitted .obj fixtures + a bundled objdiff-cli
data/xboxkrnl_ordinals.json
                    Source of xboxkrnl exports (371-entry ordinal → name table)
data/xboxkrnl_signatures.json
                    Hand-curated kernel-export signatures for ctx.h synthesis
compilers/xdk5849-vc71/
                    XDK 5849 VC7.1 toolchain (cl.exe)
tools/ghidra_12.0.3_PUBLIC/
                    Ghidra + XBE loader for warm-start decompilation. See docs/ghidra_setup.md.
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
3. **Source-tree integrator** — splat-style YAML project layout, with the
   matched C committed back per-function.
4. **Codebase index + embeddings** — once we have ≥5 matched functions,
   embed them and retrieve similar examples as few-shot prompt context.
5. **x86 permuter** — non-LLM C-source mutation engine (swap commutative ops,
   reorder local declarations, equivalent idioms) to brute-force the
   last-mile register-allocation gap without spending LLM tokens. Original
   `decomp-permuter` is MIPS-focused; an x86 port is real work but pays off
   forever.

## Known constraints

- Wine-stable deprecation on 2026-09-01, migrate to Whisky before then.

## Out of scope

- C++ class recovery (vtables → classes)
- Whole-program optimization (`/GL` + `/LTCG`)
- Other consoles
- General-purpose decompilation (not trying to be Ghidra/IDA)
- Obfuscation / anti-debug handling

## Acknowledgments

- [Capstone](http://www.capstone-engine.org/)
- [Cxbx-Reloaded](https://github.com/Cxbx-Reloaded/Cxbx-Reloaded)
- [abaire/xbdm_gdb_bridge](https://github.com/abaire/xbdm_gdb_bridge) —
  `xboxkrnl.exe` ordinal table
- [objdiff](https://github.com/encounter/objdiff)
- [decomp.me](https://decomp.me)
- [mizuchi](https://github.com/macabeus/mizuchi)
- Chris Lewis, [The Unexpected Effectiveness of One-Shot Decompilation
  with Claude](https://blog.chrislewis.au/the-unexpected-effectiveness-of-one-shot-decompilation-with-claude/)
