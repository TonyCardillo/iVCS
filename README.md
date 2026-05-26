# iVCS

LLM-driven matching decompilation, targeting the original Xbox.

**Status: v2 in progress.** v0.1 (single-function x86-32 GCC `-O0` PoC, PyQt5 GUI) has been stripped down. v2 reorients toward real game decomp: MSVC 7.1/8.0 toolchain via the Xbox XDK, XBE binaries, instruction-aware diffing, and a diff-driven LLM nudging loop.

## Why Xbox

- x86-32 with SSE/MMX — Capstone already handles it
- MSVC `cl.exe` 13.10/14 from the XDK is obtainable as a binary (no compiler port required, unlike IDO for N64)
- XBE format is PE-derived and well-documented
- Cxbx-Reloaded has already enumerated ~370 `xboxkrnl.exe` exports by ordinal — symbol resolution for free
- Mostly-uncharted territory compared to the N64/GameCube decomp scenes

## Carried over from v0.1

- `src/decoder.py` — Capstone x86-32 wrapper
- `src/cfg.py` — basic-block / edge extraction
- `src/agent.py` — LLM iteration scaffold and prompt skeleton (will be retargeted to diff-driven prompts)
- `src/verifier.py` — compile-and-compare shape (GCC/ELF specifics will be replaced with MSVC/PE)

## Removed in the v2 reset

- PyQt5 GUI (`src/gui/`, `main.py`)
- `src/loader.py` — placeholder stub, will be replaced by a real XBE parser
- `src/session.py` — per-binary comment store; not the right shape for a multi-function project

## What's still needed (recon-pending)

- XBE format parser + kernel-ordinal table (port from Cxbx-Reloaded)
- MSVC `cl.exe` / `link.exe` toolchain harness (under Wine or a Windows VM — TBD)
- Instruction-aware asm differ (no off-the-shelf x86 MSVC version exists)
- Project-layout convention (splat-style YAML, per-function asm/src split)
- CLI entry point

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest
```

## Acknowledgments

- [Capstone](http://www.capstone-engine.org/) — disassembly
- [Cxbx-Reloaded](https://github.com/Cxbx-Reloaded/Cxbx-Reloaded) — XBE format reference, kernel ordinal table
- The matching-decomp community at [decomp.me](https://decomp.me)
- Chris Lewis, [The Unexpected Effectiveness of One-Shot Decompilation with Claude](https://blog.chrislewis.au/the-unexpected-effectiveness-of-one-shot-decompilation-with-claude/)
