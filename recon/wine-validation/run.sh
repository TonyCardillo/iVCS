#!/usr/bin/env bash
# Wine + widberg/msvc8.0p validation harness.
#
# Goal: prove `cl.exe hello.c` produces a PE/COFF .obj on macOS via Wine.
# This is the gate for every downstream toolchain decision in iVCS v2.
#
# Approach: skip vcvars32.bat (cmd.exe quoting is fragile under wine) and set
# the three env vars it would have set (PATH, INCLUDE, LIB) directly in the
# unix shell as Windows-style paths. Wine forwards them to cl.exe.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
MSVC_DIR="${MSVC_DIR:-/Users/entmoot/Code/msvc8.0p}"
export WINEPREFIX="${WINEPREFIX:-$HOME/.wine_msvc8}"
export WINEDEBUG="${WINEDEBUG:-err+all,fixme-all}"

if ! command -v wine >/dev/null 2>&1; then
    echo "FAIL: 'wine' not on PATH. brew install --cask wine-stable && xattr -dr com.apple.quarantine '/Applications/Wine Stable.app'" >&2
    exit 1
fi

echo "wine: $(wine --version 2>&1 | head -1)"
echo "MSVC_DIR: $MSVC_DIR"
echo "WINEPREFIX: $WINEPREFIX"

# Initialize the wineprefix on first run (silent, quick).
wine wineboot --init >/dev/null 2>&1 || true

# Convert unix paths to wine paths once.
MSVC_W="$(wine winepath -w "$MSVC_DIR" 2>/dev/null)"
HELLO_W="$(wine winepath -w "$HERE/hello.c" 2>/dev/null)"
OUT_W="$(wine winepath -w "$HERE/hello.obj" 2>/dev/null)"

echo "MSVC_W: $MSVC_W"

# What vcvars32.bat sets, replicated as wine-compatible env.
# PATH needs unix paths so wine can locate the exe; cl.exe finds its DLL
# siblings via Windows search rules inside the exe's directory.
export WINEPATH="$MSVC_W\\bin;$MSVC_W\\PlatformSDK\\bin"
export INCLUDE="$MSVC_W\\ATLMFC\\INCLUDE;$MSVC_W\\INCLUDE;$MSVC_W\\PlatformSDK\\include"
export LIB="$MSVC_W\\ATLMFC\\LIB;$MSVC_W\\LIB;$MSVC_W\\PlatformSDK\\lib"

cd "$HERE"
rm -f hello.obj

# /c = compile only, /Fo<file> = output filename, /nologo = quiet banner
wine "$MSVC_DIR/bin/cl.exe" /nologo /c "/Fo$OUT_W" "$HELLO_W"

echo "---"
if [[ -f "$HERE/hello.obj" ]]; then
    echo "SUCCESS"
    file "$HERE/hello.obj"
    echo "Size: $(wc -c < "$HERE/hello.obj") bytes"
else
    echo "FAIL: hello.obj not produced"
    exit 1
fi
