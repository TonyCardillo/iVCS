/* Same as fixture.c except sum_to_n uses < instead of <= — a classic
 * decomp.me one-character difference that produces a small but real
 * codegen change. classify() and dot_product() are unchanged, so the
 * diff should pinpoint sum_to_n at <100% with the other two at 100%. */

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
    for (i = 1; i < n; i++) {   /* <-- changed: was <= */
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
