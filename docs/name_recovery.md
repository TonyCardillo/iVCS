# Name & structure recovery in retail Xbox builds

What naming signal a stripped retail XBE actually carries, so the project-wide
"quick start" passes (turning `fn_<VA>` blanks into real names) target what's
there instead of what we wish were there.

Status: findings from the Halo 2 retail XBE (`halo2_default.xbe`, build
2342-era). Drives `src/analysis/strings_xref.py`, `src/analysis/libmatch.py`,
`src/formats/xboxkrnl.py`.

## The governing principle

**Shipping builds strip whatever the runtime doesn't need.** Names, asserts,
and reflection metadata cost ROM and leak internals, so retail titles compile
them out. Every "recover the original names from X" idea has to be checked
against the actual binary before it's worth building — assume nothing.

## What we checked, and what we found (Halo 2 retail)

| Signal | Other decomps lean on it | Halo 2 retail | Notes |
| --- | --- | --- | --- |
| `__FILE__` assert paths | Bungie/PC builds: recover whole dir tree | **Stripped** (game code) | Only *Havok* middleware paths survive (`\world\hkWorld.cpp`, `\error\hkError.cpp`) — it kept its own asserts. |
| MSVC RTTI (`.?AV…@@`) | Demangle → class names + inheritance | **Stripped** (`/GR-`) | Only CRT `std::bad_alloc`, `std::exception`. No game classes. |
| HaloScript function table | name → signature (→ VA, on Halo 1) | **Stripped** | The script *compiler* doesn't ship; only the bytecode interpreter (opcodes, no names). Canonical names (`object_create`, `unit_get_health`, `ai_place`) = 0 matches. |
| hs type / global / enum tables | — | **Present** | 16-byte structs in `.data` (e.g. `0x0046dd80`): type names (`integer`, `point3d`), globals (`games-played`), AI/damage/report enums. **No `.text` pointers** — names are decoupled from implementations. |
| String literals (debug/error/script ids) | — | **Present, rich** | ~12k strings; the basis of `strings_xref`. |
| Kernel import ordinals | — | **Present** | Resolved by `xboxkrnl`. |
| SDK library stamps + code | — | **Present** | `D3D8LTCG`, `DSOUND`, `XGRAPHCL`, `XNET`, `LIBCMT`/`LIBCPMT`; `libmatch` excludes/names XDK code. |

### A trap worth remembering

XBE section flags are **not** reliable for "this is code." `.rdata` and `.data`
are flagged *executable* in this binary, so string/data detection must gate on
content (printable + NUL-terminated + length), never on the exec bit. See the
note in `src/strings_xref.string_at_va`.

## What iVCS actually uses (all clean-room, binary-derived)

- **String xref** (`strings_xref`) — the strings a function references, surfaced
  as click-to-adopt hints, plus a project-wide auto-name pass for the
  unambiguous case (one referenced string → label). On Halo 2: ~746 functions
  get a hint; 50 tiny accessor stubs auto-named (`unit_enter_vehicle`,
  `slayer_engine_globals`, …).
- **Kernel ordinals** (`xboxkrnl`) and **SDK signature matching** (`libmatch`).
- Names then flow into every caller's `ctx.h` as `#define <label> fn_<VA>`
  aliases (`launcher._callee_alias_line`), so the model reads/writes real names
  while matching stays anchored to `fn_<VA>`.

## Clean-room line

Names derived from the binary — strings, kernel ordinals, lib signatures, and
(where present) RTTI/`__FILE__` — are defensible RE. Names lifted from a leaked
source tree are not. Keep the provenance straight; that distinction is the whole
ballgame for a clean-room tool.

## Implication for non-retail builds

Debug, beta, or non-shipping Xbox builds often retain the assert paths, RTTI,
and the full script function table. The recognizers we *didn't* build here (an
`__FILE__`-driven TU/folder reconstructor, an RTTI class-namer, a HaloScript
function-table parser) become viable on those — title- or build-specific
plugins on top of the generic engine, not core.
