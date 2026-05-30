"""Drive XDK 5849's Link.Exe under Wine — the real-relink half of whole-image verify.

The byte-splice verifier (integrator Phase 4a) places each function with our own
one-function relocator. This module is the path to proving a match with the
*real* linker: feed the committed `.obj` files to Link.Exe and let it produce a
candidate image, which a section-level diff then compares against the original.

Producing a bootable XBE (headers, certificate, XOR'd fields) is out of scope;
verification stays at the section-bytes level. `link_argv` is pure and tested;
`default_link_fn` binds it to the real binary via the same IVCS_* environment
variables `compile_tool` documents.
"""

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from src.compile_tool import _winepath


@dataclass(frozen=True)
class LinkOutput:
	success: bool
	out_path: Path
	stdout: str = ""
	stderr: str = ""


def link_argv(
	link_exe: str,
	obj_paths_w: list[str],
	out_path_w: str,
	*,
	base_address: int,
	entry: str | None = None,
	extra_flags: tuple[str, ...] = (),
) -> list[str]:
	"""Build the Link.Exe command line.

	Defaults produce a fixed-base, CRT-free resource DLL (`/DLL /NOENTRY
	/NODEFAULTLIB /FIXED`) so a relocatable section can be linked and its bytes
	extracted without dragging in startup code. An explicit `entry` swaps
	`/NOENTRY` for `/ENTRY:<symbol>`. All paths are already Windows-form.
	"""
	argv = [link_exe, "/nologo", "/DLL", "/NODEFAULTLIB", "/FIXED"]
	argv.append("/NOENTRY" if entry is None else f"/ENTRY:{entry}")
	argv.append(f"/BASE:0x{base_address:X}")
	argv.extend(extra_flags)
	argv.append(f"/OUT:{out_path_w}")
	argv.extend(obj_paths_w)
	return argv


def default_link_fn(
	objs: list[Path],
	out_path: Path,
	*,
	base_address: int,
	entry: str | None = None,
	extra_flags: tuple[str, ...] = (),
) -> LinkOutput:
	"""Spawn XDK 5849's Link.Exe 7.10.3077 under Wine to link `objs` → `out_path`.

	IVCS_MSVC_DIR (default <repo>/compilers/xdk5849-vc71) and IVCS_WINE (default
	"wine") override the toolchain location, matching `default_compile_fn`.
	"""
	default_msvc_dir = Path(__file__).parent.parent / "compilers" / "xdk5849-vc71"
	msvc_dir = Path(os.environ.get("IVCS_MSVC_DIR", str(default_msvc_dir)))
	wine = os.environ.get("IVCS_WINE", "wine")

	msvc_w = _winepath(wine, str(msvc_dir))
	objs_w = [_winepath(wine, str(p.absolute())) for p in objs]
	out_w = _winepath(wine, str(out_path.absolute()))

	env = os.environ.copy()
	env["WINEPATH"] = f"{msvc_w}\\bin"
	env["LIB"] = f"{msvc_w}\\lib"
	env.setdefault("WINEDEBUG", "err+all,fixme-all")

	link_exe = str(msvc_dir / "bin" / "Link.Exe")
	argv = link_argv(
		link_exe, objs_w, out_w, base_address=base_address, entry=entry, extra_flags=extra_flags
	)
	completed = subprocess.run(
		[wine, *argv],
		capture_output=True,
		text=True,
		env=env,
		timeout=120,
		check=False,
	)
	success = completed.returncode == 0 and out_path.is_file()
	return LinkOutput(
		success=success, out_path=out_path, stdout=completed.stdout, stderr=completed.stderr
	)
