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

The web UI (`src/webui/`) is the main frontend: explore an XBE, launch and
monitor decomp runs, drive the batch/sweep harnesses, and read coverage.

```bash
# 1. Install (creates .venv from pyproject.toml + uv.lock)
uv sync

# 2. Enumerate an XBE into a project manifest the UI can load
mkdir -p projects/halo2-retail
uv run python -m src enumerate path/to/default.xbe \
    --name halo2-retail \
    --output projects/halo2-retail/project.json

# 3. Launch the UI (cloud runs need a key; a local LM Studio model works without one)
export ANTHROPIC_API_KEY=sk-ant-...   # optional
uv run python -m src.webui            # serves http://127.0.0.1:8765/ (--port to change)
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

## CLI

Everything the web UI does is also a subcommand of `python -m src`:

```bash
python -m src enumerate game.xbe --name halo2 -o projects/halo2/project.json
python -m src report   projects/halo2/project.json   # per-segment coverage
python -m src commit   projects/halo2/project.json   # promote matched best.c into the tree
python -m src verify   projects/halo2/project.json   # byte-splice verify against the image
python -m src relink   projects/halo2/project.json   # real-relink verify via XDK Link.Exe
python -m src cluster  projects/halo2/project.json   # group structurally-identical functions
python -m src similar  projects/halo2/project.json --function NAME
python -m src libmatch projects/halo2/project.json d3d8.lib --save   # name SDK code
python -m src batch    projects/halo2/project.json   # overnight unattended grind
```

## Repo layout

The library is organized by pipeline stage; one CLI (`python -m src`) and the web
UI (`python -m src.webui`) are the two thin frontends over it.

```text
src/
  paths.py          Repo-relative resource locations (data/, compilers/, tools/, recon/)
  __main__.py       Unified CLI entry: `python -m src <command>`
  core/             Shared data models
    project.py        Project manifest load/save + match aggregation + manifest builder
    workspace.py      Per-function filesystem layout
  formats/          Binary substrate
    xbe.py            XBE parser, function carving, XOR-decoded addresses
    xboxkrnl.py       371-entry ordinal → name table
    relocs.py         REL32 + DIR32 discovery via Capstone; __imp__ resolution
    coff.py           Microsoft COFF/i386 .obj emitter
    coff_read.py      COFF/i386 .obj reader (inverse of coff.py) for whole-image verify
    pe_read.py        Minimal PE32 reader: pull linked section bytes back out
    archive.py        !<arch> static-library parser (extract COFF members from .lib)
    carver.py         Three-line orchestrator: carve → resolve → coff
  decomp/           Warm-start + agent loop
    ghidra_decompile.py  Ghidra-headless warm-start
    agent_loop.py     LLM loop policy
    compile_tool.py   LLM agent tool (compile + view assembly)
    objdiff.py        objdiff-cli wrapper + typed JSON parser
    llm_clients.py    LiteLLM client adapter
  verify/           Relink, compare, integrate
    relink.py         One-function linker
    relink_image.py   Real relink via Link.Exe: pad-to-VA, stub externals, extract
    link_tool.py      Link.Exe wrapper
    integrator.py     Segment model + commit matched C into the source tree + coverage
  analysis/         Naming / dedup / annotations
    fingerprint.py    x86 structural index: hashes, cluster, similarity
    libmatch.py       Match the image against XDK library signatures to name SDK code
    strings_xref.py   String xref + project-wide auto-name pass
    symbols.py        VA-keyed human-label overlay
    notes.py          Per-function free-text notes
  drivers/          Loops that drive the engine
    launcher.py       Carve → synth target.obj → spawn an agent_loop run
    batch.py          Overnight batch harness (planning logic)
    sweep.py          Project-wide Ghidra baseline sweep
  cli/              Thin CLI frontends (one subcommand each)
    enumerate · report/commit/verify/relink · cluster/similar · libmatch · batch
  webui/            Local web UI: XBE explorer, decomp run/launch, batch/sweep control
  dev/              Diagnostics: smoke_run (objdiff-smoke fixture), halo2_sanity (real XBE)

tests/              Mirrors the src/ package layout (core/ formats/ decomp/ …)
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
