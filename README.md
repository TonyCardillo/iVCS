# iVCS - intelligent Visual Code System

iVCS is a matching-decompilation platform for the original Xbox. It combines reverse engineering tools with LLMs to automate the decompilation workflow.

## Pipeline

For each function enumerated from an XBE:

1. **Carve & target** — carve the function's bytes and synthesize a ground-truth
   `.obj`, the byte-exact target the decomp is matched against.
2. **Warm-start** — seed the first attempt with normalized Ghidra pseudo-C.
3. **Agent loop** — the LLM proposes C; we compile it (XDK `cl.exe`) and diff it
   against the target (`objdiff`). The per-instruction diff feeds the next
   attempt, hill-climbing until the function matches or the budget runs out.
4. **Verify** — relink the compiled bytes to the function's real address and
   byte-compare against the original image.
5. **Integrate** — commit matched functions into a segment-organized source tree
   and report coverage.

## Features

- Project workspaces in `projects/`
- Parses XBE format and enumerates every function into a `project.json` manifest
- Synthesizes `ctx.h` with inferred typedefs, struct layouts, and calling conventions
- Deterministic first decomp attempt with normalized Ghidra output
- A decomp agent loop (Claude or local)
- Byte-splice verification against the original image
- Similar-function match propagation
- Identify function names from static libraries and discoverable strings
- Coverage reports

## Quickstart

The web UI (`scripts/webui.py`) is the main frontend: explore an XBE, launch and
monitor decomp runs, drive the batch/sweep harnesses, and read coverage.

```bash
# 1. Install (creates .venv from pyproject.toml + uv.lock)
uv sync

# 2. Enumerate an XBE into a project manifest the UI can load
mkdir -p projects/halo2-retail
uv run python scripts/enumerate.py path/to/default.xbe --name halo2-retail \
    --output projects/halo2-retail/project.json

# 3. Launch the UI (cloud runs need a key; a local LM Studio model works without one)
export ANTHROPIC_API_KEY=sk-ant-...   # optional
uv run python scripts/webui.py        # serves http://127.0.0.1:8765/ (--port to change)
```

Then open <http://127.0.0.1:8765/> and point it at
`projects/halo2-retail/project.json`. (`objdiff-cli` is auto-detected from the
bundled copy, so `IVCS_OBJDIFF_CLI` is optional.)

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
