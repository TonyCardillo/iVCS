# iVCS - intelligent Visual Code System

LLM-driven matching decompilation, targeting the original Xbox.

The pipeline currently functions end-to-end. See [Roadmap](#roadmap) for next steps.

## Pipeline

```
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

## What it does today

- Parses XBE: header, sections, XOR-decoded entry-point + kernel-thunk
  table, kernel-ordinal-to-name resolution
- Enumerates every function in an XBE into a `project.json` manifest
- Carves functions from arbitrary virtual addresses in real XBEs
- Discovers relocations in carved bytes via Capstone
- Synthesizes valid Microsoft COFF/i386 `.obj` files that
  `objdiff-cli` parses cleanly and lines up against MSVC-emitted base objects
- Infers callee calling conventions from their bytes and decorates symbols
  (`_fn_X@N`, `__imp__Name@N`) so stdcall call sites match
- Auto-synthesizes `ctx.h`: typedefs, `@N`-pinned target/callee forward decls,
  and `__declspec(dllimport)` kernel decls from a curated signature table
- Harvests Ghidra's recognized struct layouts (`XBE_FILE_HEADER`, ...) into
  `ctx.h` (byte-exact, `pack(1)`) and rewrites `<Type>_<addr>` struct-instance
  globals in the warm-start to typed absolute derefs, so struct-referencing
  drafts resolve their member offsets instead of erroring on undeclared types
- Seeds attempt 0 with a Ghidra headless pseudo-C warm-start (optional),
  pinning the draft's definition to the `@N`-inferred `int __stdcall` so it
  agrees with ctx.h instead of colliding (MSVC C2373/C2371), and padding
  Ghidra's under-count call sites up to each stdcall callee's `@N` arity
- Runs a matching-decomp agent loop via LiteLLM
- Integrates matched functions into a segment-organized source tree (grouped by
  the XBE section each lives in), sharing one `include/ivcs_common.h` typedef
  preamble across all committed sources (each keeps only a slim per-function
  header for its own decls), reporting per-segment matched/committed coverage and
  flagging enumeration gaps/overlaps — `scripts/integrate.py`
- Byte-splice verifies matched functions against the original image: recompiles
  each matched `best.c`, relocates it to the VA it actually occupies (a
  one-function linker over the compiled COFF), and byte-compares — a whole-image
  verified-matched % that catches address mistakes the relocation-aware
  per-function diff masks (`scripts/integrate.py verify`)
- Cross-checks that same claim with the real XDK `Link.Exe` as an independent
  oracle: pads each matched function to land at its exact original VA, resolves
  its externals through an absolute-symbol stub, links, reads the placed bytes
  back out of the PE, and byte-compares — agreeing with our own relocator to the
  byte (`scripts/integrate.py relink`)
- Builds a structural code index (a coddog-style port to x86): fingerprints every
  function by exact bytes, opcode skeleton, and operand-shape, then clusters
  duplicates and ranks similar functions by opcode edit-distance — surfacing how
  much work collapses (Halo 2: 14.2% of functions are opcode-redundant, one
  match each covers a whole cluster) and feeding few-shot retrieval, with no
  LLM/embedding model (`scripts/codindex.py`)
- Identifies SDK functions against the XDK static libraries (FLIRT-style): reads
  each `!<arch>` library's COFF objects, fingerprints their functions, and matches
  the image against them on relocation-invariant hashes — naming the SDK portion
  and scoping it out of the real decomp target (Halo 2: 538 functions confidently
  named against 6 libs in ~12 s, e.g. `_XGetLaunchInfo@8`, `_D3DIndexBuffer_GetDesc@8`)
  — `scripts/libmatch.py`

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
  coff_read.py      COFF/i386 .obj reader (inverse of coff.py) for whole-image verify
  relink.py         One-function linker: place compiled bytes at their real VA
  pe_read.py        Minimal PE32 reader: pull linked section bytes back out
  link_tool.py      Link.Exe wrapper (argv builder + Wine invocation)
  relink_image.py   Real relink via Link.Exe: pad-to-VA, stub externals, extract
  carver.py         Three-line orchestrator: carve → resolve → coff
  workspace.py      Per-function filesystem layout
  project.py        Project manifest (project.json) load/save + match aggregation
  integrator.py     Segment model + commit matched C into the source tree + coverage
  compile_tool.py   The single tool the LLM agent gets; wraps cl.exe + objdiff
  agent_loop.py     LLM loop policy (budget, soft/hard timeouts, best tracking)
  ghidra_decompile.py  Ghidra-headless warm-start: pseudo-C drafts for attempt 0
  launcher.py       Carve → synth target.obj → spawn an agent_loop run (UI entry point)
  llm_clients.py    LiteLLM client adapter (works with local/cloud providers)
  objdiff.py        objdiff-cli wrapper + typed JSON parser
  fingerprint.py    x86 structural index: exact/opcode/equiv hashes, cluster, similarity
  archive.py        !<arch> static-library parser (extract COFF members from .lib)
  libmatch.py       Match the image against XDK library signatures to name SDK code

tests/
scripts/
  enumerate.py      Enumerate all functions in an XBE → project.json manifest
  integrate.py      Commit matched functions into the source tree; coverage report
  codindex.py       Structural code index: cluster duplicates, find similar functions
  libmatch.py       Name SDK functions by matching the image against the XDK .libs
  smoke_run.py      End-to-end agent loop against the bundled objdiff-smoke fixture (no XBE needed)
  halo2_sanity.py   End-to-end pipeline diagnostic against a real Halo 2 XBE
  webui.py          Local web UI for inspecting an XBE (sections, hex, disassembly, kernel ordinals)
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

## Why Xbox

A mix of nostalgia and more greenfield decomp scene!

## Roadmap

In rough order of leverage:

1. **Cluster-aware matching** — wire the structural index (`src/fingerprint.py`)
   into the loop: when a function matches, auto-propagate to its byte-exact
   cluster (the lone Halo 2 match already covers an 11-member exact cluster), and
   seed the agent with the nearest already-matched function's source as few-shot
   context. (The index itself — fingerprints, clustering, similarity search —
   already shipped via `scripts/codindex.py`.)
2. **Semantic embeddings (later)** — the structural index finds same-skeleton
   code; embeddings would add *semantic* retrieval (similar intent, different
   shape). Worth it only once structural retrieval is exhausted.
3. **x86 permuter** — non-LLM C-source mutation engine (swap commutative ops,
   reorder local declarations, equivalent idioms) to brute-force the
   last-mile register-allocation gap without spending LLM tokens. Original
   `decomp-permuter` is MIPS-focused; an x86 port is real work but pays off
   forever.

Whole-image relink + verify (the previous #1) shipped: both
`scripts/integrate.py verify` (our own relocator) and `scripts/integrate.py
relink` (the real XDK Link.Exe, as an independent cross-check) place each
matched function at its true VA and byte-compare against the original image.
Producing a bootable XBE (headers/cert) remains out of scope — verification is
at section-bytes level.

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
