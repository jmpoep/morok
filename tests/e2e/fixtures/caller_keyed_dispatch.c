// SPDX-License-Identifier: MIT
//
// Workload for caller-keyed-dispatch post-link sealing tests.  The callees use
// external linkage so optimized LLVM IR keeps plain C-convention call edges;
// CKD intentionally skips internal fastcc edges for ABI safety.

#include <stdint.h>
#include <stdio.h>

static volatile uint64_t sink;

__attribute__((noinline, used, visibility("default"))) uint64_t
ckd_mix(uint64_t x, uint64_t y) {
    x ^= 0x9e3779b97f4a7c15ULL;
    x += (y << 7) | (y >> 57);
    x *= 0x94d049bb133111ebULL;
    return x ^ (x >> 29);
}

__attribute__((noinline, used, visibility("default"))) uint64_t
ckd_fold(uint64_t x) {
    x ^= 0xd1b54a32d192ed03ULL;
    x *= 0xbf58476d1ce4e5b9ULL;
    return x ^ (x >> 31);
}

int main(void) {
    uint64_t acc = 0xcbf29ce484222325ULL;
    for (uint64_t i = 1; i <= 32; ++i)
        acc = ckd_fold(ckd_mix(acc, i));
    sink = acc;
    printf("ckd_integrity=%016llx\n", (unsigned long long)sink);
    return sink == 0 ? 2 : 0;
}
