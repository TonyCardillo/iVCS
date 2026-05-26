# TODO

## v2 reset — Xbox matching decomp

v0.1 (single-function x86-32 GCC `-O0`, PyQt5 GUI) has been stripped. The engine pieces worth keeping (decoder, CFG, verifier shell, agent loop scaffold) remain. The v2 plan has been substantially simplified by two pieces of existing tooling:

- **`widberg/msvc8.0` branch `msvc8.0p`** — portable VS2005 / VC80 x86 toolchain, runs under Wine on macOS. Already in use by `widberg/FUELDecompilation`, a shipping matching decomp.
- **`encounter/objdiff`** — instruction-aware diffing for x86/x86_64 with MSVC demangling. Native macOS arm64 prebuilt. Emits structured JSON via `objdiff-cli diff`.

Together these eliminate the two largest pieces of original work I'd expected v2 to require. What's left is the actually-interesting part: the agent loop that drives objdiff with an LLM.

### Reset completed
- [x] Delete PyQt5 GUI (`src/gui/`, `main.py`)
- [x] Delete `src/loader.py` (placeholder stub)
- [x] Delete `src/session.py` (wrong shape for multi-function projects)
- [x] Drop PyQt5 from requirements
- [x] Tests still pass (25 passing, 1 skipped — unchanged from baseline)

### Recon completed
- [x] **MSVC toolchain reproducibility** — `widberg/msvc8.0p` works on Apple Silicon via Wine 11.0 + Rosetta. See `recon/wine-validation/`. Hello-world compiles at both `/O0` and `/O2`.
- [x] **objdiff design for LLM integration** — `objdiff-cli diff --format json-pretty` produces a fully-structured per-function diff (instruction rows with `diff_kind`, per-argument `diff_index`, `match_percent`). x86 + MSVC demangling first-class. macOS arm64 prebuilt is 6.5 MB.
- [x] **Cross-validation against `macabeus/mizuchi`** — a parallel project doing exactly this in TypeScript. Confirms the architecture (objdiff loop, compile-then-diff iteration, prompt-driven hill climbing). Patterns worth borrowing into iVCS:
  - Tool-using agent (LLM calls a `compile_and_view_assembly` tool repeatedly in one conversation) over one-shot regenerate-from-scratch — much better convergence shape.
  - Soft-timeout pattern: hard timeout T, soft timeout 0.7×T with "you're running out of time, submit best now" prompt.
  - LLM-response cache keyed by prompt-content hash (`claude-cache.json` style).
  - Context-file concatenation: skip `#include` resolution, just append a known-good `ctx.h` after the LLM's code at compile time.
  - Explicit named diff-kind vocabulary in the system prompt ("INSERT / DELETE / REPLACE / OP_MISMATCH / ARG_MISMATCH") — matches objdiff enum, helps the model reason.

### Built so far in v2
- [x] **`src/xbe.py`** — MVP XBE loader: header + section table + section bytes. 16 tests. No kernel ordinal DB, no XOR descrambling yet.
- [x] **`src/objdiff.py`** — typed Python wrapper around `objdiff-cli diff`. Pure-parse + thin-spawn split for testability. 12 tests using fixture JSON captured from the smoke test.

### Active milestones

1. **Ground-truth end-to-end smoke test** ✅ — `recon/objdiff-smoke/`. Confirmed objdiff sees past COFF timestamp noise (100% match across identical builds) and pinpoints per-function changes (8.6% on `sum_to_n` for `<=` → `<`, others at 100%).

2. **XBE loader** ✅ — `src/xbe.py` (header + sections + section bytes). Kernel ordinal DB still pending.

3. **`xboxkrnl` ordinal database** — port the ~370 ordinal-to-signature mappings from Cxbx-Reloaded so XBE imports can be resolved to function names + signatures. Mostly mechanical translation; data not code.

4. **Project scaffolding** — given an XBE path and a splat-style YAML, produce an `objdiff.json` describing target/base object pairs per function. Bridge between an Xbox title and the diff loop.

5. **Agent loop (informed by mizuchi)** — Python orchestrator over `src/objdiff.py` + `cl.exe`:
   - Tool-using LLM session with `compile_and_view_assembly` available (one conversation, multiple iterations within it — *not* the v0.1 regenerate-from-scratch shape).
   - Hard / TTFT / soft timeout layering.
   - Response cache keyed by prompt-content hash.
   - System prompt names objdiff's diff kinds explicitly (INSERT / DELETE / REPLACE / OP_MISMATCH / ARG_MISMATCH).
   - `ctx.h`-concatenation compile path; no `#include` resolution.
   - LLM proposes one C edit per turn; compile + diff; keep if `match_percent` improved.

6. **Target selection** — pick a real Xbox title. Small, C-heavy, not `/GL+/LTCG`, late-era so VC8 codegen is compatible (XDK 5849+). Open question — needs scouting.

### Long-running risks / deferred decisions

- **Wine-stable deprecation (2026-09-01).** Migrate to Whisky or Apple GPTK before then. Validation works today; not urgent.
- **VC8 vs VC7.1.** widberg's repo is VC8 (late-era XDK only). Earlier Xbox titles need VC7.1, for which no portable equivalent exists publicly. Either package one (apply widberg's recipe to VS2003 media) or restrict the target list to late-era titles.
- **Stock VC80 vs XDK VC80.** Microsoft's XDK shipped a customized `cl.exe` with Xbox intrinsics. For perfect byte-matching we may need the XDK's specific binary. Stock + the `msvc8.0p` `__usercall` patch may get close enough for most functions; verify empirically when we have a real target.
- **COFF timestamp non-determinism.** Same source compiled twice produces different bytes (timestamp field in COFF header). objdiff parses structurally so this likely doesn't matter for our path — confirm in milestone 1.

### Out of scope for v2
- C++ class recovery (vtables → classes) — comes after a single function matches reliably
- Whole-program optimization (`/GL+/LTCG`) — pick targets that don't use it
- Other consoles — different toolchains
- Re-introduction of a GUI — CLI/library first

### Non-goals
- Production-ready general-purpose decompiler (Ghidra/IDA exist)
- Obfuscation / anti-debug handling
- Commercial support
