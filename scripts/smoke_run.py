#!/usr/bin/env python3
"""End-to-end smoke run of the iVCS agent loop.

Targets `_classify` from recon/objdiff-smoke/target.obj (compiled from
fixture.c by the XDK 5849 VC7.1 toolchain, cl 13.10). Uses Claude Haiku as
a stand-in for a real local model; same OpenAI-shape tool-call surface
that any local LLM endpoint would present.

Prereqs:
  - Wine + XDK 5849 VC7.1 toolchain (default IVCS_MSVC_DIR=<repo>/compilers/xdk5849-vc71)
  - objdiff-cli binary (bundled at recon/objdiff-smoke/objdiff-cli)
  - ANTHROPIC_API_KEY set in env
  - From the project root: `.venv/bin/python scripts/smoke_run.py`

This script intentionally hardcodes the target disassembly rather than
dumping it dynamically; that's a deliberate scope choice while the
COFF-to-asm extraction story is still TBD. The disassembly comes from
`recon/objdiff-smoke/identical.json` which captured it during the
smoke test.

Will spawn:
  - wine cl.exe (per attempt)
  - objdiff-cli (per attempt)
  - real Claude Haiku API calls (real $$, though Haiku is cheap)
"""

import os
import sys
import tempfile
from pathlib import Path

# Make `import src.*` work when run directly.
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.workspace import FunctionWorkspace  # noqa: E402
from src.decomp.agent_loop import AgentConfig, agent_loop_run  # noqa: E402
from src.decomp.compile_tool import default_compile_fn, default_diff_fn  # noqa: E402
from src.decomp.llm_clients import LiteLLMClient  # noqa: E402

REPO_ROOT = Path(__file__).parent.parent
TARGET_OBJ = REPO_ROOT / "recon" / "objdiff-smoke" / "target.obj"
OBJDIFF_CLI = REPO_ROOT / "recon" / "objdiff-smoke" / "objdiff-cli"

# Disassembly of _classify captured during recon/objdiff-smoke/; src was `int classify(int x)`.
CLASSIFY_ASM = """\
0x00 mov   eax, [esp+0x4]
0x04 test  eax, eax
0x06 jge   short 0xc
0x08 or    eax, 0xffffffff
0x0b ret
0x0c xor   ecx, ecx
0x0e test  eax, eax
0x10 setne cl
0x13 mov   eax, ecx
0x15 ret
"""

# Empty for this fixture; no Xbox kernel calls or external types.
CTX_H = "/* no external dependencies for this fixture */\n"


def check_prereqs() -> None:
	missing = []
	if "ANTHROPIC_API_KEY" not in os.environ:
		missing.append("ANTHROPIC_API_KEY not set")
	if not TARGET_OBJ.is_file():
		missing.append(f"target.obj missing at {TARGET_OBJ}")
	if not OBJDIFF_CLI.is_file():
		missing.append(f"objdiff-cli missing at {OBJDIFF_CLI}")

	msvc_dir = Path(os.environ.get("IVCS_MSVC_DIR", str(REPO_ROOT / "compilers" / "xdk5849-vc71")))
	if not (msvc_dir / "bin" / "cl.exe").is_file():
		missing.append(f"cl.exe not at {msvc_dir}/bin/cl.exe")

	import shutil

	if shutil.which("wine") is None:
		missing.append("wine not on PATH")

	if missing:
		print("MISSING PREREQS:", file=sys.stderr)
		for m in missing:
			print(f"  - {m}", file=sys.stderr)
		sys.exit(2)


def main() -> int:
	check_prereqs()
	os.environ.setdefault("IVCS_OBJDIFF_CLI", str(OBJDIFF_CLI))

	with tempfile.TemporaryDirectory(prefix="ivcs-smoke-") as tmp:
		ws = FunctionWorkspace(root=Path(tmp), function_name="_classify")
		ws.initialize()
		ws.target_obj.write_bytes(TARGET_OBJ.read_bytes())
		ws.ctx_h.write_text(CTX_H)

		print(f"workspace: {ws.root}")
		print(f"function:  {ws.function_name}")
		print(f"target:    {ws.target_obj} ({ws.target_obj.stat().st_size} bytes)")
		print()

		config = AgentConfig(
			model="anthropic/claude-haiku-4-5",
			api_base="",  # cloud, not local; api_base unused
			max_iterations=8,
			hard_timeout_seconds=180.0,
		)
		client = LiteLLMClient(
			model="anthropic/claude-haiku-4-5", api_key=os.environ["ANTHROPIC_API_KEY"]
		)

		print("running agent_loop_run...")
		result = agent_loop_run(
			workspace=ws,
			target_asm=CLASSIFY_ASM,
			config=config,
			llm_client=client,
			compile_fn=default_compile_fn,
			diff_fn=default_diff_fn,
		)

		print()
		print("RESULT")
		print(f"  success:               {result.success}")
		print(f"  best_match_percent:    {result.best_match_percent}")
		print(f"  iterations:            {result.iterations}")
		print(f"  termination_reason:    {result.termination_reason}")
		print()
		if ws.best_c.is_file():
			print(f"best.c ({ws.best_c.stat().st_size} bytes):")
			print("-" * 60)
			print(ws.best_c.read_text())
			print("-" * 60)

		return 0 if result.success else 1


if __name__ == "__main__":
	sys.exit(main())
