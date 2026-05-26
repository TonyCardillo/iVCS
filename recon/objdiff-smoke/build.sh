#!/usr/bin/env bash
# Wrapper around widberg/msvc8.0p cl.exe under Wine.
#
# Usage: build.sh <source.c> <output.obj> [extra cl.exe flags...]
set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <source.c> <output.obj> [extra flags...]" >&2
    exit 2
fi

SRC="$1"
OUT="$2"
shift 2

MSVC_DIR="${MSVC_DIR:-/Users/entmoot/Code/msvc8.0p}"
export WINEPREFIX="${WINEPREFIX:-$HOME/.wine_msvc8}"
export WINEDEBUG="${WINEDEBUG:-err+all,fixme-all}"

MSVC_W="$(wine winepath -w "$MSVC_DIR" 2>/dev/null)"
SRC_W="$(wine winepath -w "$(cd "$(dirname "$SRC")" && pwd)/$(basename "$SRC")" 2>/dev/null)"
OUT_W="$(wine winepath -w "$(cd "$(dirname "$OUT" 2>/dev/null || dirname "$(realpath "$OUT" 2>/dev/null || echo "$OUT")")" && pwd)/$(basename "$OUT")" 2>/dev/null)"

export WINEPATH="$MSVC_W\\bin;$MSVC_W\\PlatformSDK\\bin"
export INCLUDE="$MSVC_W\\ATLMFC\\INCLUDE;$MSVC_W\\INCLUDE;$MSVC_W\\PlatformSDK\\include"
export LIB="$MSVC_W\\ATLMFC\\LIB;$MSVC_W\\LIB;$MSVC_W\\PlatformSDK\\lib"

wine "$MSVC_DIR/bin/cl.exe" /nologo /c "/Fo$OUT_W" "$@" "$SRC_W"
