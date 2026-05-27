"""xboxkrnl.exe ordinal database — lookup ordinal → export name.

The original Xbox kernel exports its functions by ordinal only (no name
table in the import descriptor). To turn a thunk-table entry like
ordinal 156 into a human-readable `KeTickCount`, we ship the published
ordinal mapping as JSON.

Data source: abaire/xbdm_gdb_bridge, src/dyndxt_loader/xboxkrnl_exports.def.h
Ordinal range 1..378 with seven gaps (367..373). 371 named exports.
"""

import json
from pathlib import Path

_DATA_PATH = Path(__file__).parent.parent / "data" / "xboxkrnl_ordinals.json"


def _ordinals_load() -> dict[int, dict]:
    raw = json.loads(_DATA_PATH.read_text())
    return {int(k): v for k, v in raw.items()}


_ORDINALS: dict[int, dict] = _ordinals_load()

XBOXKRNL_ORDINAL_MIN: int = min(_ORDINALS)
XBOXKRNL_ORDINAL_MAX: int = max(_ORDINALS)


def xboxkrnl_name_get(ordinal: int) -> str | None:
    entry = _ORDINALS.get(ordinal)
    return entry["name"] if entry is not None else None


def xboxkrnl_mangled_get(ordinal: int) -> str | None:
    """Returns the MSVC stdcall mangling, e.g. `Foo@8`."""
    entry = _ORDINALS.get(ordinal)
    return entry["mangled"] if entry is not None else None


def xboxkrnl_ordinals_known() -> frozenset[int]:
    return frozenset(_ORDINALS)
