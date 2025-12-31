// Benchmark 4: Simple conditional
// Expected: Conditional jump, two return paths
int function_00000000() {
    int x = 5;
    if (x > 3) {
        return 1;
    } else {
        return 0;
    }
}
