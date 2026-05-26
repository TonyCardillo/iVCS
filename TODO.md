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

### Active milestones

1. **Ground-truth end-to-end smoke test** *(next)* — compile the same C twice under `widberg/msvc8.0p`, run `objdiff-cli diff` on the pair, confirm 100% match. Then introduce a one-line C change, confirm a structured non-100% diff comes out. This is the dress rehearsal for the agent loop: it proves the data shape we'll be feeding the LLM is real and useful before we touch the LLM.

2. **XBE loader** — header, section table, kernel imports by ordinal (port from Cxbx-Reloaded's ordinal DB). CLI `ivcs dump <xbe>`.

3. **Project scaffolding** — `objdiff.json` generator from a splat-style YAML describing an Xbox title (sections, known function addrs, file splits).

4. **Agent loop** — Python orchestrator over `objdiff-cli diff` + `cl.exe`:
   - Parse JSON diff for one function
   - Format diff into LLM prompt (structured, not raw text)
   - LLM proposes ONE minimal C edit (hill-climb, not regenerate)
   - Apply edit → `cmake --build` → re-diff
   - Keep if `match_percent` improved, revert if not
   - Repeat per function

5. **Target selection** — pick a real Xbox title. Constraints: small, C-heavy (not heavily templated C++), not `/GL+/LTCG`, late-era so VC8 codegen is compatible (XDK 5849+). Open question — needs scouting.

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
