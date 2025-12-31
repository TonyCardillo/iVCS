# TODO

## Current Status (v0.1.0 - MVP)

iVCS is a **proof-of-concept** for LLM-based decompilation. Core functionality is complete and working.

**What works:**
- ✅ x86-32 disassembly (Capstone)
- ✅ Sound CFG extraction (basic blocks + edges)
- ✅ Local LLM integration (LiteLLM)
- ✅ Binary verification (GCC compilation + byte comparison)
- ✅ Iterative refinement (LLM feedback loop)
- ✅ GUI (PyQt5 with tactical theme)
- ✅ Tests (25 passing)

**Scope:**
- Single functions only (not whole programs)
- x86-32 architecture
- GCC compiler (not MSVC/Clang)
- Simple optimization levels (-O0 primarily)

## Potential Future Work

### Nice-to-Have Improvements

1. **Example Binaries**
   - Add `examples/` directory with sample .bin files
   - Include expected C output for comparison
   - Document how to create test cases

2. **Better Documentation**
   - Screenshot of GUI in README
   - Video demo/walkthrough
   - Common issues troubleshooting guide

3. **Code Quality**
   - Add type hints to all functions (`mypy --strict`)
   - Increase test coverage
   - Run `ruff check` and fix all issues

### Research Questions (Out of Scope for MVP)

These are interesting directions but not planned:

- **Multi-function support** - Decompile entire programs
- **Architecture support** - ARM, MIPS, x86-64
- **Compiler support** - MSVC, Clang verification
- **Optimization levels** - Handle -O2, -O3 code
- **Advanced CFG** - Loop detection, dominators
- **Diff visualization** - Show instruction-level differences
- **Context handling** - External symbols, function calls
- **Caching** - Store successful decompilations

### Non-Goals

Explicitly out of scope:

- ❌ Production-ready decompiler (this is a proof-of-concept)
- ❌ Obfuscation handling
- ❌ Anti-debugging detection
- ❌ Custom IR/optimization passes
- ❌ Commercial support

## Recently Completed ✅

- [x] Integrate Local LLM via LiteLLM
- [x] Create minimal foundation (Decoder, CFG, Verifier, Agent)
- [x] Build GUI with decompilation workflow
- [x] Write comprehensive tests
- [x] Improve CFG formatting (sound, more helpful)
- [x] Allow LLM chain-of-thought (reasoning before code)
- [x] Clean up documentation
