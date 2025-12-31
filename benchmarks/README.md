# iVCS Benchmarks

Simple C programs compiled to x86-32 for testing decompilation quality.

## Benchmarks

| Name | Description | Binary Size | 
|------|-------------|-------------|
| `01_return_constant.o` | Returns `42` | 10 bytes | 
| `02_simple_arithmetic.o` | Returns `5 + 7` | 10 bytes | 
| `03_local_variable.o` | Local var: `x = 10; return x * x` | 18 bytes | 
| `04_simple_if.o` | If statement with two branches | 34 bytes | 
| `05_simple_loop.o` | While loop summing 0-4 | 50 bytes | 

## Usage

### Compile Benchmarks
```bash
cd benchmarks
./compile.sh
```

### View Disassembly
```bash
objdump -d -Mintel benchmarks/01_return_constant.o
```

### Run Automated Tests
```bash
python benchmarks/test_benchmarks.py
```

## Compilation Flags

Same as `verifier.py`:
```bash
-target i386-unknown-linux-gnu
-m32
-O0
-fno-asynchronous-unwind-tables
-fno-stack-protector
-fno-pie
```
