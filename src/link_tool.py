"""Drive XDK 5849's Link.Exe under Wine; the real-relink half of whole-image verify.

The independent cross-check for integrator Phase 4a: link committed `.obj`s into a
candidate image for a section-level diff against the original. Verification stays
at the section-bytes level; a bootable XBE is out of scope. `link_argv` is pure;
`default_link_fn` binds it to the binary via the same IVCS_* vars as compile_tool.
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

	Defaults to a fixed-base, CRT-free DLL (`/DLL /NOENTRY /NODEFAULTLIB /FIXED`)
	so a section links and its bytes extract without startup code. Paths are
	already Windows-form.
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
	"""Link `objs` → `out_path` via Link.Exe 7.10.3077 under Wine.

	IVCS_MSVC_DIR and IVCS_WINE override the toolchain, matching default_compile_fn.
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
