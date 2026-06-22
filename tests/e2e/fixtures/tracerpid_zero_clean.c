// SPDX-License-Identifier: MIT
//
// Clean-run regression for Linux TracerPid enforcement.  The sealed payload is
// keyed by the runtime seal; an unsafe TracerPid fold dirties that seal and
// makes this hash diverge on otherwise clean executions.

#include <stdint.h>
#include <stdio.h>

#if defined(__APPLE__)
#define MOROK_SEALED_SECTION __attribute__((section("__DATA,.morok.sealed")))
#elif defined(__GNUC__) || defined(__clang__)
#define MOROK_SEALED_SECTION __attribute__((section(".morok.sealed")))
#else
#define MOROK_SEALED_SECTION
#endif

#if defined(__clang__)
#define MOROK_NOOPT __attribute__((noinline, optnone))
#else
#define MOROK_NOOPT __attribute__((noinline))
#endif

static const unsigned char sealed_payload[8] MOROK_SEALED_SECTION = "seal-ok!";

MOROK_NOOPT static uint32_t payload_hash(void) {
    uint32_t h = 0x811c9dc5U;
    h = (h ^ sealed_payload[0]) * 16777619U;
    h = (h ^ sealed_payload[1]) * 16777619U;
    h = (h ^ sealed_payload[2]) * 16777619U;
    h = (h ^ sealed_payload[3]) * 16777619U;
    h = (h ^ sealed_payload[4]) * 16777619U;
    h = (h ^ sealed_payload[5]) * 16777619U;
    h = (h ^ sealed_payload[6]) * 16777619U;
    h = (h ^ sealed_payload[7]) * 16777619U;
    return h;
}

int main(void) {
    uint32_t h = payload_hash();
    printf("tracerpid_seal=%08x\n", h);
    return h == 0xdbe66928U ? 0 : 7;
}
