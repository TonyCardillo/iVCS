// Benchmark 5: Simple loop
// Expected: Loop with counter, accumulator
int function_00000000() {
    int sum = 0;
    int i = 0;
    while (i < 5) {
        sum = sum + i;
        i = i + 1;
    }
    return sum;
}
