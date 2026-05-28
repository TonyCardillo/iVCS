"""Ghidra-headless warm-start: pseudo-C drafts for the matching-decomp agent.

Two operations:
- ghidra_project_ensure: idempotently import + analyze an XBE into a Ghidra
  project. Pays the ~100s analysis cost once.
- ghidra_decompile_function: invoke a Jython post-script that decompiles
  one function by VA and writes C source to a file. Project must already
  exist (re-imports would re-pay the analysis cost).
"""

import os
import subprocess
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


_GHIDRA_SCRIPTS_DIR = Path(__file__).parent.parent / "ghidra_scripts"
_DECOMPILE_SCRIPT = "DecompileOne.java"
_XBE_LOADER = "XbeLoader"
_ANALYSIS_SUCCESS_MARKER = "REPORT: Analysis succeeded"
_IMPORT_SUCCESS_MARKER = "REPORT: Import succeeded"
_LOCK_ERROR_MARKER = "Unable to lock project"
_LOCK_RETRY_ATTEMPTS = 3
_LOCK_RETRY_BACKOFF_SECONDS = 2.0


class GhidraError(RuntimeError):
    pass


@dataclass(frozen=True)
class GhidraConfig:
    ghidra_home: Path
    project_dir: Path
    xbe_path: Path
    project_name: str = "ivcs"
    script_dir: Path = _GHIDRA_SCRIPTS_DIR

    @property
    def analyze_headless(self) -> Path:
        return self.ghidra_home / "support" / "analyzeHeadless"

    @property
    def program_name(self) -> str:
        return self.xbe_path.name

    @property
    def project_gpr(self) -> Path:
        return self.project_dir / f"{self.project_name}.gpr"


AnalyzeHeadlessFn = Callable[[list[str]], "subprocess.CompletedProcess[str]"]
"""(argv) -> CompletedProcess. Injected for testing; default spawns the real binary."""


def ghidra_config_from_env(xbe_path: Path) -> GhidraConfig:
    """Defaults match the install path documented in docs/ghidra_setup.md.

    IVCS_GHIDRA_HOME, IVCS_GHIDRA_PROJECT_DIR, IVCS_GHIDRA_PROJECT_NAME
    override the per-host bits.

    Default project name = XBE filename stem, so multiple XBEs each get
    their own analyzed project under /tmp/ghidra-projects/ instead of
    sharing one and re-analyzing on every switch.
    """
    home = Path(os.environ.get(
        "IVCS_GHIDRA_HOME",
        str(Path.home() / "Downloads" / "ghidra_12.0.3_PUBLIC"),
    ))
    project_dir = Path(os.environ.get("IVCS_GHIDRA_PROJECT_DIR", "/tmp/ghidra-projects"))
    project_name = os.environ.get("IVCS_GHIDRA_PROJECT_NAME") or xbe_path.stem
    return GhidraConfig(
        ghidra_home=home,
        project_dir=project_dir,
        xbe_path=xbe_path,
        project_name=project_name,
    )


def ghidra_project_ensure(
    config: GhidraConfig,
    *,
    analyze_headless_fn: AnalyzeHeadlessFn | None = None,
    timeout_seconds: float = 600.0,
) -> None:
    """No-op if `<project_dir>/<project_name>.gpr` already exists."""
    if config.project_gpr.is_file():
        return

    config.project_dir.mkdir(parents=True, exist_ok=True)
    argv = _import_argv(config)
    run = analyze_headless_fn or _default_run
    result = run(argv)

    if result.returncode != 0 or _ANALYSIS_SUCCESS_MARKER not in (result.stdout or ""):
        raise GhidraError(
            f"project bootstrap failed (rc={result.returncode})\n"
            f"--- argv ---\n{argv}\n"
            f"--- stdout (tail) ---\n{_tail(result.stdout)}\n"
            f"--- stderr (tail) ---\n{_tail(result.stderr)}"
        )


def ghidra_decompile_function(
    va: int,
    config: GhidraConfig,
    *,
    analyze_headless_fn: AnalyzeHeadlessFn | None = None,
    timeout_seconds: float = 120.0,
) -> str:
    """Returns the pseudo-C for the function at `va`. Project must exist."""
    if not config.project_gpr.is_file():
        raise GhidraError(
            f"project not bootstrapped: {config.project_gpr} does not exist. "
            "Call ghidra_project_ensure first."
        )

    with tempfile.NamedTemporaryFile(
        mode="r", suffix=".c", delete=False, dir=config.project_dir
    ) as f:
        out_path = Path(f.name)
    try:
        argv = _decompile_argv(config, va, out_path)
        run = analyze_headless_fn or _default_run
        result = _run_with_lock_retry(argv, run)
        if result.returncode != 0:
            raise GhidraError(
                f"decompile failed for va=0x{va:08x} (rc={result.returncode})\n"
                f"--- stdout (tail) ---\n{_tail(result.stdout)}\n"
                f"--- stderr (tail) ---\n{_tail(result.stderr)}"
            )
        if not out_path.is_file() or out_path.stat().st_size == 0:
            raise GhidraError(
                f"decompile produced no output for va=0x{va:08x}\n"
                f"--- stdout (tail) ---\n{_tail(result.stdout)}"
            )
        return out_path.read_text()
    finally:
        out_path.unlink(missing_ok=True)


def _run_with_lock_retry(
    argv: list[str],
    run: AnalyzeHeadlessFn,
    *,
    attempts: int = _LOCK_RETRY_ATTEMPTS,
    backoff_seconds: float = _LOCK_RETRY_BACKOFF_SECONDS,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> "subprocess.CompletedProcess[str]":
    """Retry when Ghidra reports `Unable to lock project` (transient JVM-shutdown race)."""
    for attempt in range(attempts):
        result = run(argv)
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        if _LOCK_ERROR_MARKER not in stdout and _LOCK_ERROR_MARKER not in stderr:
            return result
        if attempt == attempts - 1:
            return result
        sleep_fn(backoff_seconds * (2 ** attempt))
    return result


def _import_argv(config: GhidraConfig) -> list[str]:
    return [
        str(config.analyze_headless),
        str(config.project_dir),
        config.project_name,
        "-import", str(config.xbe_path),
        "-overwrite",
        "-loader", _XBE_LOADER,
    ]


def _decompile_argv(config: GhidraConfig, va: int, out_path: Path) -> list[str]:
    return [
        str(config.analyze_headless),
        str(config.project_dir),
        config.project_name,
        "-process", config.program_name,
        "-noanalysis",
        "-scriptPath", str(config.script_dir),
        "-postScript", _DECOMPILE_SCRIPT, f"0x{va:08x}", str(out_path),
    ]


def _default_run(argv: list[str]) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        check=False,
        timeout=600,
    )


def _tail(s: str | None, lines: int = 40) -> str:
    if not s:
        return "(empty)"
    parts = s.splitlines()
    return "\n".join(parts[-lines:])


__all__ = [
    "AnalyzeHeadlessFn",
    "GhidraConfig",
    "GhidraError",
    "ghidra_config_from_env",
    "ghidra_decompile_function",
    "ghidra_project_ensure",
]
