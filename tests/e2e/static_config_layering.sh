#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Regression for issue #42: the static-link derived config must stay valid TOML
# even when the source --config already declares [passes.function_call_obfuscate],
# and it must preserve the other pass settings.  The old code blindly appended a
# second [passes.function_call_obfuscate] table, producing a duplicate-table TOML
# error; the plugin then ignored the whole config and (with no preset fallback)
# built a completely unprotected static binary.
set -euo pipefail

script="${1:?usage: static_config_layering.sh <path-to-cross_build.sh>}"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

# A source config that ALREADY sets function_call_obfuscate (the case that broke
# the old append), plus another pass section that must survive.
src="$workdir/in.toml"
cat >"$src" <<'TOML'
[global]
preset = "max"

[passes.function_call_obfuscate]
enabled = true

[passes.platform_runtime]
minimize_imports = true
static_link_expected = false

[passes.string_encryption]
probability = 100
TOML

out="$workdir/derived.toml"
"$script" --emit-static-config "$src" "max" "$out"

fail() { echo "FAIL: $*"; echo "--- derived config ---"; cat "$out"; exit 1; }

# Exactly one function_call_obfuscate table: no duplicate -> valid TOML.
n="$(grep -c '^\[passes\.function_call_obfuscate\]' "$out" || true)"
[ "$n" -eq 1 ] || fail "expected exactly 1 function_call_obfuscate table, got $n"

# FCO is forced off, and the stale enabled=true did not survive.
grep -q '^enabled = false' "$out" || fail "function_call_obfuscate not disabled"
grep -q '^enabled = true' "$out" && fail "stale function_call_obfuscate enabled=true survived"

# Static-link policy is forced on inside the existing platform_runtime table
# without duplicating that table or preserving a stale false value.
n_platform="$(grep -c '^\[passes\.platform_runtime\]' "$out" || true)"
[ "$n_platform" -eq 1 ] || fail "expected exactly 1 platform_runtime table, got $n_platform"
grep -q '^minimize_imports = true' "$out" || fail "platform_runtime keys dropped"
grep -q '^static_link_expected = true' "$out" || fail "static link flag not forced"
grep -q '^static_link_expected = false' "$out" && fail "stale static_link_expected=false survived"

# The other settings (the actual protections) are preserved.
grep -q '^\[passes\.string_encryption\]' "$out" || fail "string_encryption section dropped"
grep -q '^preset = "max"' "$out" || fail "global preset dropped"

# The no-config path must still produce a valid preset-based config.
out2="$workdir/derived_preset.toml"
"$script" --emit-static-config "" "high" "$out2"
grep -q '^preset = "high"' "$out2" || fail "preset path lost the preset"
n2="$(grep -c '^\[passes\.function_call_obfuscate\]' "$out2" || true)"
[ "$n2" -eq 1 ] || fail "preset path produced $n2 function_call_obfuscate tables"
grep -q '^\[passes\.platform_runtime\]' "$out2" || fail "preset path lost platform_runtime section"
grep -q '^static_link_expected = true' "$out2" || fail "preset path did not force static link flag"

echo "PASS: static config layering stays valid and protective"
