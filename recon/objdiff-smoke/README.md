# objdiff + XDK 5849 VC7.1 round-trip smoke test

End-to-end validation that `objdiff-cli` produces a usable, structured diff against object files emitted by the XDK 5849 VC7.1 toolchain under Wine. This is the dress rehearsal for the agent loop — proving the data shape the LLM will consume is real and useful before any LLM work.

## Result (run on 2026-05-25)

| Test | Source pair | `match_percent` per function | Outcome |
|---|---|---|---|
| 1. Identical | `fixture.c` vs `fixture.c` | classify 100% / sum_to_n 100% / dot_product 100% | ✅ pass |
| 2. One-char change | `fixture.c` vs `variant.c` (sum_to_n `<=` → `<`) | classify **100%** / sum_to_n **8.6%** / dot_product **100%** | ✅ pass |

**Two critical findings.**

1. **COFF timestamp non-determinism is a non-issue for objdiff.** `target.obj` and `base.obj` were built from identical source but had different MD5s (different COFF timestamps). objdiff still reported 100% match across all three functions because it parses COFF structurally and only diffs the relevant section content. The byte-level timestamp paranoia from the wine validation milestone goes away.

2. **Per-function isolation works perfectly.** A change confined to `sum_to_n` produced a diff that left `classify` and `dot_product` at 100% and pinpointed the change to `sum_to_n` alone. This is exactly the granularity an LLM agent needs.

## The data shape (excerpt from `variant_diff_pretty.json`)

Each diff row has a `diff_kind` and (where applicable) a fully-parsed `instruction`:

```json
{
  "diff_kind": "DIFF_ARG_MISMATCH",
  "instruction": {
    "address": "13",
    "size": 2,
    "formatted": "jl short 0x19",
    "parts": [
      {"opcode": {"mnemonic": "jl", "opcode": 306}},
      {"arg": {"opaque": "short"}},
      {"basic": " "},
      {"arg": {"branch_dest": "25"}}
    ],
    "branch_dest": "25"
  },
  "arg_diff": [
    {},
    {"diff_index": 0}
  ]
}
```

That row says: "the conditional jump opcode is the same on both sides, but argument index 1 (the branch destination) differs." `arg_diff[i].diff_index` is the per-argument diff signal — non-null means that argument differs from the other side.

`DiffKind` values observed in this test:
- `DIFF_NONE` (omitted when zero in JSON) — instruction identical
- `DIFF_INSERT` — instruction in base/variant but not target
- `DIFF_DELETE` — instruction in target but not base/variant
- `DIFF_ARG_MISMATCH` — same opcode, different argument(s)

(Schema also defines `DIFF_REPLACE`, not exercised here.)

## What this means for the agent loop

The LLM doesn't have to parse assembly text. It receives typed structure: mnemonic, opcode ID, per-argument type (signed immediate / unsigned / register name / relocation / branch target). The prompt can be a structured summary like:

```
fn _sum_to_n (match: 8.6%)
  [DIFF_INSERT]         (5 new instructions in base)
  [DIFF_ARG_MISMATCH]   jl short 0x19   (arg 1 — branch dest — differs)
  [DIFF_DELETE]         nop
  [DIFF_DELETE]         add eax, ecx
  [DIFF_DELETE]         add ecx, 0x1
  [DIFF_DELETE]         cmp ecx, edx
  [DIFF_DELETE]         jle short 0x10
```

The model proposes ONE C edit, we rebuild, re-diff, hill-climb. No assembly parsing, no per-instruction text wrangling.

## Surprises and notes

- **`<` vs `<=` produces wildly different codegen at `/O2`.** Our variant change dropped the match from 100% to 8.6% — MSVC restructured the loop entirely. This is a useful real-world reminder that "one-character source diffs" can produce large object-level diffs. Matching decomp is not about character similarity.
- **MSVC C-mode is C89.** No in-loop variable declarations (`for (int i = 0; ...)` is a syntax error). All locals at function top.
- **Function symbols are prefixed with `_`** (MSVC `__cdecl` mangling for C).
- **`match_percent` is non-null on one side and null on the other** in the pretty JSON for unsymmetric diffs. Use the compact `--format json` if you need it on both sides, or compute from instruction counts. Not blocking but worth knowing.

## Files

- `fixture.c` — three-function ground-truth source
- `variant.c` — same, with sum_to_n changed to use `<`
- `build.sh` — wraps `wine cl.exe` for any source.c → output.obj
- `objdiff-cli` — encounter/objdiff v3.7.1, macOS arm64 (gitignored)
- `target.obj`, `base.obj`, `variant.obj` — build artifacts (gitignored)
- `identical.json`, `variant_diff.json`, `variant_diff_pretty.json` — diff outputs (gitignored)

## Reproducing

```bash
./build.sh fixture.c target.obj /O2
./build.sh fixture.c base.obj /O2
./build.sh variant.c variant.obj /O2

./objdiff-cli diff -1 target.obj -2 base.obj    --format json -o identical.json
./objdiff-cli diff -1 target.obj -2 variant.obj --format json -o variant_diff.json
```
