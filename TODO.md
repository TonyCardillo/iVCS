# TODO

## v2 reset — Xbox matching decomp

v0.1 (single-function x86-32 GCC `-O0`, PyQt5 GUI) has been stripped. The engine pieces worth keeping (decoder, CFG, verifier shell, agent loop scaffold) remain. Everything compiler-specific or GUI-specific has been deleted.

### Reset completed
- [x] Delete PyQt5 GUI (`src/gui/`, `main.py`)
- [x] Delete `src/loader.py` (placeholder stub)
- [x] Delete `src/session.py` (wrong shape for multi-function projects)
- [x] Drop PyQt5 from requirements
- [x] Tests still pass after reset (25 passing, 1 skipped — unchanged from baseline)

### Recon needed before next code (no work yet)
- [ ] **MSVC toolchain reproducibility** — can XDK `cl.exe` 13.10 + `link.exe` run reproducibly under Wine on macOS, or is a Windows VM required? Look at `wibo`, `mwccdecompiler`, any existing Xbox decomp projects.
- [ ] **`asm-differ` for x86 MSVC** — port from the MIPS version; design the instruction alignment + scoring approach (Myers or Hunt-McIlroy over decoded instructions, register-aware coloring).

### v2 milestones (high level)
1. **XBE loader** — header, section table, kernel imports by ordinal; CLI `ivcs dump <xbe>`.
2. **Kernel ordinal database** — port from Cxbx-Reloaded.
3. **MSVC toolchain harness** — reproducible `cl.exe` + `link.exe` from source → object file → byte-extractable function.
4. **Bootstrap with ground truth** — compile a hand-written C function with the XDK, prove the loop end-to-end before any LLM call.
5. **Instruction-aware differ + score** — replace byte-position match% with edit distance over decoded instructions.
6. **Diff-driven agent loop** — retarget prompts from "write C from asm" to "read this diff, propose one C edit."
7. **Project layout** — splat-style YAML, per-function asm/src split, `progress.json`.
8. **Pick a target game** — small early title, C-heavy, ideally not `/GL+/LTCG`.

### Out of scope for v2
- C++ class recovery (vtables → classes) — Phase 4, after a single function matches reliably
- Whole-program optimization (`/GL+/LTCG`) — pick targets that don't use it
- Other consoles (N64, GameCube) — different toolchain
- Re-introduction of a GUI — CLI/library first; if a UI returns later, it'll be a web frontend over a daemon

### Non-goals (unchanged)
- Production-ready general-purpose decompiler (Ghidra/IDA exist)
- Obfuscation / anti-debug handling
- Commercial support
