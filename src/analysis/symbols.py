"""VA-keyed human-label overlay for the decomp.

A function's *machine symbol* (`_fn_00175F40`) encodes its virtual address in the
name; the splice verifier decodes the VA straight back out of it, so that name can
never be renamed. This module is the other half: a pure *display* layer mapping a
VA to a friendly label for the web UI and ctx comments. Renaming here never
touches the matching/verify path.

Precedence, highest first:
  1. user override   — `symbols.json` next to project.json, edited by you
  2. SDK name        — `sdk.json` from libmatch (the XDK library identification)
  3. default         — `fn_<VA>`, derived, never stored

Both sidecars sit beside project.json, matching `sdk.json`'s convention.
"""

import json
import os
from dataclasses import dataclass
from pathlib import Path

from src.analysis.libmatch import sdk_manifest_load

_USER_SIDECAR = "symbols.json"
_SDK_SIDECAR = "sdk.json"


@dataclass(frozen=True)
class SymbolMap:
	user: dict[int, str]
	sdk: dict[int, str]

	def label_for(self, va: int) -> str:
		if va in self.user:
			return self.user[va]
		if va in self.sdk:
			return self.sdk[va]
		return f"fn_{va:08X}"

	def provenance(self, va: int) -> str:
		if va in self.user:
			return "user"
		if va in self.sdk:
			return "sdk"
		return "default"


def _user_sidecar(project_path: Path) -> Path:
	return Path(project_path).parent / _USER_SIDECAR


def _load_user_labels(project_path: Path) -> dict[int, str]:
	path = _user_sidecar(project_path)
	if not path.is_file():
		return {}
	raw = json.loads(path.read_text())
	return {int(va, 16): label for va, label in raw.get("labels", {}).items()}


def symbol_map_load(project_path: Path | str) -> SymbolMap:
	"""Load the merged label overlay from the sidecars beside project.json."""
	project_path = Path(project_path)
	sdk_path = project_path.parent / _SDK_SIDECAR
	sdk = sdk_manifest_load(sdk_path) if sdk_path.is_file() else {}
	return SymbolMap(user=_load_user_labels(project_path), sdk=sdk)


def symbol_rename(project_path: Path | str, va: int, label: str) -> None:
	"""Set (or clear) the user label for `va`, persisting to `symbols.json`.

	A blank label removes the override, reverting the VA to its SDK name or the
	`fn_<VA>` default. The on-disk key is the canonical `0x`-prefixed uppercase VA.
	"""
	project_path = Path(project_path)
	labels = _load_user_labels(project_path)
	cleaned = label.strip()
	if "\n" in cleaned or "\r" in cleaned:
		raise ValueError("a label must be a single line")

	if cleaned:
		labels[va] = cleaned
	else:
		labels.pop(va, None)

	serialized = {f"0x{v:08X}": name for v, name in sorted(labels.items())}
	_atomic_write(_user_sidecar(project_path), json.dumps({"labels": serialized}, indent=2) + "\n")


def _atomic_write(path: Path, text: str) -> None:
	"""Write via a sibling temp file + os.replace so a crash mid-write can't
	truncate the user's labels — symbols.json is their only durable data."""
	tmp = path.with_name(f"{path.name}.tmp")
	tmp.write_text(text)
	os.replace(tmp, path)
