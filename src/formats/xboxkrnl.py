"""xboxkrnl.exe ordinal database — lookup ordinal → export name.

The original Xbox kernel exports its functions by ordinal only (no name
table in the import descriptor). To turn a thunk-table entry like
ordinal 156 into a human-readable `KeTickCount`, we ship the published
ordinal mapping as JSON.

Data sources:
  - data/xboxkrnl_ordinals.json   (ordinal → name + mangled @N)
  - data/xboxkrnl_signatures.json (name → return type + arg types,
                                   or variable type)
"""

import json
from dataclasses import dataclass

from src.paths import DATA_DIR as _DATA_DIR

_ORDINALS_PATH = _DATA_DIR / "xboxkrnl_ordinals.json"
_SIGNATURES_PATH = _DATA_DIR / "xboxkrnl_signatures.json"


@dataclass(frozen=True)
class KernelFunctionSig:
	return_type: str
	arg_types: tuple[str, ...]
	varargs: bool = False


@dataclass(frozen=True)
class KernelVariableSig:
	var_type: str


KernelSig = KernelFunctionSig | KernelVariableSig


def _ordinals_load() -> dict[int, dict]:
	raw = json.loads(_ORDINALS_PATH.read_text())
	return {int(k): v for k, v in raw.items()}


def _signatures_load() -> dict[str, KernelSig]:
	raw = json.loads(_SIGNATURES_PATH.read_text())
	out: dict[str, KernelSig] = {}
	for name, entry in raw.items():
		if name.startswith("_"):
			continue
		if entry.get("kind") == "variable":
			out[name] = KernelVariableSig(var_type=entry["type"])
		else:
			out[name] = KernelFunctionSig(
				return_type=entry["return"],
				arg_types=tuple(entry["args"]),
				varargs=bool(entry.get("varargs", False)),
			)
	return out


def _byte_count_from_mangled(mangled: str) -> int | None:
	"""The popped byte count encoded in an `@N` stdcall mangling (tolerating a
	leading fastcall `@`), or None when the name carries no `@N` suffix."""
	if "@" not in mangled.lstrip("@"):
		return None
	suffix = mangled.rsplit("@", 1)[1]
	try:
		return int(suffix)
	except ValueError:
		return None


def _byte_counts_load(ordinals: dict[int, dict]) -> dict[str, int | None]:
	return {e["name"]: _byte_count_from_mangled(e["mangled"]) for e in ordinals.values()}


_ORDINALS: dict[int, dict] = _ordinals_load()
_SIGNATURES: dict[str, KernelSig] = _signatures_load()
_BYTE_COUNT_BY_NAME: dict[str, int | None] = _byte_counts_load(_ORDINALS)

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


def xboxkrnl_signature_get(name: str) -> KernelSig | None:
	"""Hand-curated return/arg types for a kernel export, keyed by the
	plain (unmangled) name. Returns None when no signature is curated;
	callers should fall back to int-placeholder typing from @N."""
	return _SIGNATURES.get(name)


def xboxkrnl_mangled_byte_count(name: str) -> int | None:
	"""Popped byte count for a kernel export, parsed from its `@N` mangling and
	keyed by plain name. O(1) via a table precomputed at import (like _SIGNATURES);
	called once per kernel import per function carve. None for an unknown name or
	one without an `@N` suffix."""
	return _BYTE_COUNT_BY_NAME.get(name)
