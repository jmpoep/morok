#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Regression for issue #41: cross_build.sh must default to Morok's entropy-seeded
# mode (seed 0) so helper-produced binaries get per-build polymorphism, instead
# of a fixed nonzero seed that makes every rebuild byte-comparable and
# fingerprintable.  An explicit --seed / SEED= must still pin a reproducible seed.
set -euo pipefail

script="${1:?usage: cross_build_seed.sh <path-to-cross_build.sh>}"

fail() { echo "FAIL: $*"; exit 1; }

# Default: entropy-seeded (0).
got="$("$script" --emit-seed)"
[ "$got" = "0" ] || fail "default seed is '$got', expected 0 (entropy mode)"

# Explicit --seed overrides (reproducible build).
got="$("$script" --seed 12345 --emit-seed)"
[ "$got" = "12345" ] || fail "--seed override is '$got', expected 12345"

# SEED= environment override also works.
got="$(SEED=99 "$script" --emit-seed)"
[ "$got" = "99" ] || fail "SEED= override is '$got', expected 99"

echo "PASS: cross_build defaults to entropy seed and honors overrides"
