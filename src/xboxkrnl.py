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
from pathlib import Path

_DATA_DIR = Path(__file__).parent.parent / "data"
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


_ORDINALS: dict[int, dict] = _ordinals_load()
_SIGNATURES: dict[str, KernelSig] = _signatures_load()

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
	"""Popped byte count from the mangling table, looked up by plain name.

	Walks the ordinal table — O(N) but the table is tiny (361 entries)
	and this is called once per kernel import per function carve.
	"""
	for entry in _ORDINALS.values():
		if entry["name"] != name:
			continue
		mangled = entry["mangled"]
		if "@" not in mangled.lstrip("@"):
			return None
		suffix = mangled.rsplit("@", 1)[1]
		try:
			return int(suffix)
		except ValueError:
			return None
	return None
