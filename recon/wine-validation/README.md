# Wine + widberg/msvc8.0p validation

One-off validation that the MSVC 8 toolchain (`widberg/msvc8.0` branch `msvc8.0p`) compiles a C file on macOS via Wine. This is the gate for every downstream toolchain decision in iVCS v2.

## Result (run on 2026-05-25)

- Host: Apple M4 Pro, macOS Tahoe 26.5
- Wine: 11.0 (Homebrew cask, x86_64 via Rosetta 2)
- `cl.exe /c hello.c` → Intel 80386 COFF object, 543 bytes
- `cl.exe /c /O2 hello.c` → also works
- `dumpbin /DISASM hello.obj` → works (noisy: Wine probes for D3D on launch, spams MoltenVK info — irrelevant)

## Known caveats

- **`com.apple.quarantine` strip required.** Homebrew's wine-stable cask installs ad-hoc-signed binaries; macOS Tahoe Gatekeeper SIGKILL's them on launch with no dialog. One-time fix:
  ```
  xattr -dr com.apple.quarantine "/Applications/Wine Stable.app"
  ```
- **wine-stable is deprecated on 2026-09-01.** Plan to migrate to Whisky / Apple GPTK before then.
- **COFF timestamps are non-deterministic** across builds (MSVC 8 has no `/Brepro` flag). Diffing at the byte level needs a post-process step to zero out the timestamp field. (objdiff parses COFF structurally, so this likely doesn't matter for the diff path — verify in next milestone.)

## Files

- `hello.c` — minimal test source (one function + main)
- `run.sh` — repro harness; expects widberg toolchain at `/Users/entmoot/Code/msvc8.0p`
- `hello.obj` — gitignored build artifact
