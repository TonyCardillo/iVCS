#!/bin/bash
# Compile benchmarks to x86-32 object files
# Uses same flags as verifier.py for consistency

set -e

echo "Compiling benchmarks to x86-32..."

# Compiler flags matching verifier.py
FLAGS="-target i386-unknown-linux-gnu -m32 -O0 -fno-asynchronous-unwind-tables -fno-stack-protector -fno-pie"

for c_file in *.c; do
    if [ -f "$c_file" ]; then
        base=$(basename "$c_file" .c)
        echo "  $c_file -> ${base}.o"
        gcc -c $FLAGS "$c_file" -o "${base}.o"
        echo "    Size: $(stat -f%z "${base}.o") bytes"
    fi
done

echo ""
echo "Compilation complete!"
echo ""
echo "To view disassembly:"
echo "  objdump -d -Mintel benchmarks/01_return_constant.o"
echo ""
echo "To test with iVCS:"
echo "  python main.py  # then load a .o file"
