/* Three small functions exercising the codegen patterns matching-decomp
 * agents actually have to deal with: forward branches, a counted loop,
 * and a loop with pointer-indexed loads and arithmetic.
 *
 * MSVC 8 in C mode is C89: all locals declared at top of function. */

int classify(int x)
{
    if (x < 0) return -1;
    if (x == 0) return 0;
    return 1;
}

int sum_to_n(int n)
{
    int sum = 0;
    int i;
    for (i = 1; i <= n; i++) {
        sum += i;
    }
    return sum;
}

int dot_product(const int *a, const int *b, int len)
{
    int total = 0;
    int i;
    for (i = 0; i < len; i++) {
        total += a[i] * b[i];
    }
    return total;
}
