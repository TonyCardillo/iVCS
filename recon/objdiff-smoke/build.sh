#!/usr/bin/env bash
# Wrapper around the XDK 5849 VC7.1 cl.exe under Wine.
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

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MSVC_DIR="${MSVC_DIR:-$REPO_ROOT/compilers/xdk5849-vc71}"
export WINEDEBUG="${WINEDEBUG:-err+all,fixme-all}"

MSVC_W="$(wine winepath -w "$MSVC_DIR" 2>/dev/null)"
SRC_W="$(wine winepath -w "$(cd "$(dirname "$SRC")" && pwd)/$(basename "$SRC")" 2>/dev/null)"
OUT_W="$(wine winepath -w "$(cd "$(dirname "$OUT" 2>/dev/null || dirname "$(realpath "$OUT" 2>/dev/null || echo "$OUT")")" && pwd)/$(basename "$OUT")" 2>/dev/null)"

export WINEPATH="$MSVC_W\\bin"
export INCLUDE="$MSVC_W\\include"
export LIB="$MSVC_W\\lib"

wine "$MSVC_DIR/bin/cl.exe" /nologo /c "/Fo$OUT_W" "$@" "$SRC_W"