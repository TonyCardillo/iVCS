# iVCS - intelligent Visual Code System

iVCS is a matching-decompilation platform for the original Xbox. It combines reverse engineering tools with LLMs to automate the decompilation workflow.

## Pipeline

TODO: put a much higher-level pipeline here

Old way too verbose pipeline to remove:

```text
default.xbe (4.6 MB)
   │
   ├─ xbe_load + xbe_function_carve(va, size)        ← src/xbe.py
   ├─ relocs_resolve                                  ← src/relocs.py
   │     ├─ REL32  call rel32/jmp rel32/jcc rel32  →  _fn_*@N (conv-inferred)  or  _data_*
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

## Features

- Project workspaces in `projects/`
- Parses XBE format and enumerators every function into `project.json` manifest
- Synthesizes `ctx.h` with inferred typedefs, struct layouts, and calling conventions
- Deterministic first decomp attempt with normalized Ghidra output
- A decomp agent loop (Claude or local)
- Byte-splice verification against the original image
- Similar-function match propagation
- Identify funciton names from static libraries and discoverable strings
- Coverage reports

## Quickstart

TODO: quick start for the webui (the main frontend)

Environment:

| variable | purpose | default |
| --- | --- | --- |
| `IVCS_MSVC_DIR` | Root of the XDK 5849 VC7.1 toolchain containing `bin/cl.exe`. | `<repo>/compilers/xdk5849-vc71` |
| `IVCS_WINE` | Wine binary to invoke `cl.exe`. | `wine` (on PATH) |
| `IVCS_OBJDIFF_CLI` | Path to the `objdiff-cli` binary. | `objdiff-cli` (on PATH) |

## Repo layout

```text
src/
  xbe.py            XBE format parser, function carving, XOR-decoded addresses
  xboxkrnl.py       371-entry ordinal → name table
  relocs.py         REL32 + DIR32 discovery via Capstone; __imp__ resolution
  coff.py           Microsoft COFF/i386 .obj emitter
  coff_read.py      COFF/i386 .obj reader (inverse of coff.py) for whole-image verify
  relink.py         One-function linker
  pe_read.py        Minimal PE32 reader: pull linked section bytes back out
  link_tool.py      Link.Exe wrapper
  relink_image.py   Real relink via Link.Exe: pad-to-VA, stub externals, extract
  carver.py         Three-line orchestrator: carve → resolve → coff
  workspace.py      Per-function filesystem layout
  project.py        Project manifest (project.json) load/save + match aggregation
  integrator.py     Segment model + commit matched C into the source tree + coverage
  compile_tool.py   LLM agent tool
  agent_loop.py     LLM loop policy
  ghidra_decompile.py  Ghidra-headless warm-start
  launcher.py       Carve → synth target.obj → spawn an agent_loop run
  llm_clients.py    LiteLLM client adapter
  objdiff.py        objdiff-cli wrapper + typed JSON parser
  fingerprint.py    x86 structural index: hashes, cluster, similarity
  archive.py        !<arch> static-library parser (extract COFF members from .lib)
  libmatch.py       Match the image against XDK library signatures to name SDK code
  strings_xref.py   String xref: recover string refs per function; project-wide auto-name pass
  symbols.py        VA-keyed human-label overlay
  batch.py          Overnight batch harness
  sweep.py          Project-wide Ghidra baseline sweep
  notes.py          Per-function free-text notes

tests/
scripts/
  enumerate.py      Enumerate all functions in an XBE → project.json manifest
  integrate.py      Commit matched functions into the source tree; coverage report
  codindex.py       Structural code index: cluster duplicates, find similar functions
  libmatch.py       Name SDK functions by matching the image against the XDK .libs
  batch.py          CLI entry point for the overnight batch harness
  smoke_run.py      End-to-end agent loop against the bundled objdiff-smoke fixture (no XBE needed)
  halo2_sanity.py   End-to-end pipeline diagnostic against a real Halo 2 XBE
  webui.py          Local web UI: XBE explorer, decomp run/launch, batch/sweep control
ghidra_scripts/   Ghidra postscripts (see docs/ghidra_setup.md):
                    DecompileOne.java — decompile one function by VA;
                    DumpStructs.java  — harvest composite layouts as C typedefs
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

## Roadmap

In rough order of leverage:

- x86 permuter: non-LLM C-source mutation engine (swap commutative ops, reorder local declarations, equivalent idioms) to brute-force the last-mile register-allocation gap without spending LLM tokens.

## Known constraints

- Wine-stable deprecation on 2026-09-01, migrate to Whisky before then.

## Out of scope... for now

- C++
- Whole-program optimization (`/GL` + `/LTCG`)
- Other consoles
- Obfuscation handling

## Acknowledgments

- [Capstone](http://www.capstone-engine.org/)
- [Ghidra]
- [Ghidra XBE Extension](https://github.com/XboxDev/ghidra-xbe)
- [Cxbx-Reloaded](https://github.com/Cxbx-Reloaded/Cxbx-Reloaded)
- [abaire/xbdm_gdb_bridge](https://github.com/abaire/xbdm_gdb_bridge) —
  `xboxkrnl.exe` ordinal table
- [objdiff](https://github.com/encounter/objdiff)
- [decomp.me](https://decomp.me)
- [mizuchi](https://github.com/macabeus/mizuchi)
- Chris Lewis, [The Unexpected Effectiveness of One-Shot Decompilation
  with Claude](https://blog.chrislewis.au/the-unexpected-effectiveness-of-one-shot-decompilation-with-claude/)
