#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

#define F 16384 // = 1 << 14

int
int2fp (int n) {
    return (n * F);
}

int
fp2int (int x) {
    return (x / F);
}

int
fp2int_nearest (int x) {
    if (x >= 0) {
        return ((x + F / 2) / F);
    }
    return ((x - F / 2) / F);
}

int
fp_add_fp (int x, int y) {
    return (x + y);
}

int
fp_sub_fp (int x, int y) {
    return (x - y);
}

int fp_add_int (int x, int n) {
    return (x + int2fp(n));
}

int
fp_sub_int (int x, int n) {
    return (x - int2fp(n));
}

int
fp_mul_fp (int x, int y) {
    return (((int64_t) x) * y / F);
}

int
fp_mul_int (int x, int n) {
    return (x * n);
}

int
fp_div_fp (int x, int y) {
    return (((int64_t) x) * F / y);
}

int
fp_div_int (int x, int n) {
    return (x / n);
}

#endif
