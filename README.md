# iVCS - Intelligent Visual Coding Software

Local LLM-based decompilation with iterative binary verification.
v0.1.0 - Proof of concept

## Overview

iVCS demonstrates using local LLMs to decompile x86-32 assembly to C code that compiles to **byte-perfect** matches (matching decompilation). This approach combines:
- Pattern recognition (LLM generates C code)
- Compiler verification (to ensure byte-perfect matching)
- Iterative refinement (feedback loop for the LLM)

Currently, it works on single functions, x86-32, GCC, with no/simple optimizations (-O0). 
This is NOT a production-ready decompiler like Ghidra or IDA Pro.


## Quick Start

```bash
# 1. Install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 2. Start your local LLM server (e.g., LM Studio) on port 1234

# 3. Launch iVCS
python main.py

# 4. Load a binary and click Decompile!
```

## Architecture

```text
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Decoder    │────►│ CFG Extract  │────►│  Local LLM   │
│  (Capstone)  │     │(Blocks+Edges)│     │  (Generate C)│
└──────────────┘     └──────────────┘     └──────┬───────┘
                                                 │
                            ┌────────────────────┘
                            │
                            ▼
                     ┌──────────────┐     ┌──────────────┐
                     │   Verifier   │◄────┤Perfect Match?│
                     │(gcc compare) │     └──────────────┘
                     └──────┬───────┘            │ No
                            │ Yes                │
                            ▼                    ▼
                     ┌──────────────┐     ┌──────────────┐
                     │  Return C!   │     │Refine + Retry│
                     └──────────────┘     └──────────────┘
```

## Usage

### Prerequisites

1. **Local LLM Server** - You need a local OpenAI-compatible LLM server running at `http://127.0.0.1:1234`
   - Recommended: [LM Studio](https://lmstudio.ai/), [Ollama](https://ollama.ai/), or similar
   - Model: Qwen3-4B-2507 or any code-capable model
   - Ensure the server is running before starting iVCS

2. **GCC Compiler** - Required for binary verification
   ```bash
   # macOS
   xcode-select --install

   # Ubuntu/Debian
   sudo apt-get install build-essential
   ```

### Run GUI (Recommended)

```bash
# Activate virtual environment
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Launch GUI
python main.py
```

**GUI Workflow:**
1. Click **⟨ LOAD BINARY ⟩** to select a binary file
2. Adjust base address, offset, and size if needed
3. Click **⟨ DECOMPILE ⟩** to generate C code
4. Wait for LLM iterations (typically 1-2 iterations)
5. View results: match percentage, compilation status, and generated C code

**Status Indicators:**
- **◉ READY** - System initialized
- **◉ ACTIVE** - Binary loaded, ready to decompile
- **◉ DECOMPILING...** - LLM is generating/refining C code
- **◉ SUCCESS** - Perfect binary match achieved (100%)
- **◉ PARTIAL** - Decompilation completed but not perfect match
- **◉ ERROR** - An error occurred


## Project Structure

```
iVCS/
├── src/
│   ├── decoder.py      # Capstone wrapper
│   ├── cfg.py          # CFG extraction
│   ├── verifier.py     # Binary verification
│   ├── agent.py        # LLM integration
│   ├── loader.py       # Binary file loader
│   ├── session.py      # Session management
│   └── gui/            # PyQt5 application
│       ├── app.py
│       ├── theme.py    # SciFi theme (for fun)
│       └── ...
├── tests/
│   ├── test_decoder.py
│   ├── test_cfg.py
│   └── test_verifier.py
├── README.md           # This file
├── TODO.md             # Roadmap
└── requirements.txt
```

## Limitations

Known limitations so far:

- **Single functions only** - Cannot decompile entire programs
- **x86-32 only** - No x86-64, ARM, MIPS support
- **GCC only** - Eventually want to add support for other compilers
- **Simple code** - Primarily tested with -O0, may struggle with heavy optimizations
- **No data sections** - Only processes .text (code), ignores .data/.rodata/.bss
- **No context** - Doesn't handle external symbols, function calls to other functions
- **Local LLM required** - Needs OpenAI-compatible API endpoint (LM Studio, Ollama, etc.)

## Acknowledgments

- [Capstone](http://www.capstone-engine.org/) - Disassembly framework
- Chris Lewis's blog post: [The Unexpected Effectiveness of One-Shot Decompilation with Claude](https://blog.chrislewis.au/the-unexpected-effectiveness-of-one-shot-decompilation-with-claude/)
- The decompilation community at [decomp.me](https://decomp.me)
