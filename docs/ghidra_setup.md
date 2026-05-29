# Ghidra warm-start setup (macOS)

Ghidra is an optional pseudo-C source for the agent's first attempt. The
LLM "fixes" Ghidra's draft rather than writing from scratch, which
historically lifts first-attempt match rates significantly.

Status: landed. The integration lives in `src/ghidra_decompile.py`
(headless wrapper) + `ghidra_scripts/DecompileOne.java` (decompile postscript),
wired into `agent_loop.py` (warm-start prompt + `ghidra_only_run` baseline)
and the webui launch form. Follow the install below to enable it locally.

## Why we need it

A first-attempt prompt that already has plausible variable shapes and
control flow lets the model skip the "guess the function's purpose" stage
and focus on register-allocation matching. JSRF and other projects pre-seed
Ghidra with a symbol table so the pseudo-C uses real names instead of
`FUN_00012000` / `DAT_002D0CF5`. We will do the same with our kernel-import
table and discovered `fn_XXXXXXXX` labels.

## Version pinning

Ghidra and its loader extensions must match on minor version. The XBE
loader publishes per-Ghidra-version `.zip` releases; mixing versions
silently breaks XBE import.

Plan: pick a single Ghidra release that the XBE loader has a build for,
and pin that pair. Record both versions in this file when chosen.

| component | pinned version | source |
| --- | --- | --- |
| Ghidra | 12.0.3_PUBLIC | <https://github.com/NationalSecurityAgency/ghidra/releases> |
| XBE loader | `ghidra_12.0.3_PUBLIC_20260225_ghidra-xbe.zip` | <https://github.com/XboxDev/ghidra-xbe/releases/tag/build-202602250354> |
| Java | 21+ | Temurin via Homebrew: `brew install --cask temurin@21` |

The XBE loader publishes per-Ghidra-version `.zip`s. The most recent
loader build targets Ghidra 12.0.3; no 12.1 build exists. If you already
downloaded a different Ghidra, swap to 12.0.3 to match the loader.

## Install steps

1. Install Java 21+ (Temurin via Homebrew works: `brew install --cask temurin@21`).
2. Download a Ghidra release from
   <https://github.com/NationalSecurityAgency/ghidra/releases>. Unzip it
   into the repo's `tools/` folder, e.g. `tools/ghidra_12.0.3_PUBLIC`
   — that path is the default `IVCS_GHIDRA_HOME`.
3. Locate an XBE loader extension built for the exact Ghidra version
   chosen in step 2. Save the loader `.zip` next to Ghidra.
4. Install the loader: open Ghidra, `File > Install Extensions`, green
   plus icon, select the loader `.zip`, tick its checkbox, restart Ghidra.
5. Smoke test:
   - `File > New Project > Non-Shared Project`, name it `halo2`.
   - `File > Import File`, select `/tmp/halo2_default.xbe`. Format must
     read "Xbox Executable Format (XBE)". If it doesn't, the loader is
     not active.
   - Double-click the imported file. Accept the default analyzers. Wait
     for the bottom-right progress bar to clear (a few minutes).

## Memory-map gotcha (from JSRF guide)

After analysis, Ghidra marks `.rdata` and `.data` executable. This
matters only if we ever delink whole sections through Ghidra; per-function
warm-start does not touch this.

If we later add section delinking: `Window > Memory Map`, uncheck the
`X` column for `.rdata` and `.data`.

## Headless smoke test

Once GUI import succeeds, confirm headless works (this is what our wrapper
will call):

```bash
tools/ghidra_12.0.3_PUBLIC/support/analyzeHeadless \
    /tmp/ghidra-projects halo2 \
    -import /tmp/halo2_default.xbe \
    -overwrite
```

A clean run prints "Analysis succeeded" near the end and leaves a
`halo2.gpr` and `halo2.rep/` under `/tmp/ghidra-projects/`.

## Wrapper

Implemented in `src/ghidra_decompile.py` (`ghidra_project_ensure` +
`ghidra_decompile_function`) + `ghidra_scripts/DecompileOne.java`, with the
`use Ghidra warm-start` checkbox in `scripts/webui.py`. Drafts cache to
`<workspace>/ghidra_warmstart.c`.

## Open questions to revisit after install

- Does Ghidra's calling-convention output ever conflict with our
  `__stdcall` inference for kernel imports? If yes, post-process to
  strip Ghidra's argument list and use ours.
- Pseudo-C noise stripping (`bVar3 = (byte)uVar2;` style temporaries):
  worth it, or trust the LLM to ignore?
- Project-state staleness: a new XBE means a new project. Simplest is
  hashing the XBE bytes and keying the project dir by hash.
