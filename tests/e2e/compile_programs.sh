#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Compile every sample program clean and through the Morok plugin. This is a
# build-surface gate, not a behavioral differential runner: several programs
# intentionally exercise syscalls, sockets, threading, or input paths that are
# not suitable for one generic runtime oracle.
#
# Usage:
#   compile_programs.sh <clang> <clang++> <plugin> <sdk> <program-dir> <preset|config.toml> [seed]
set -uo pipefail

CLANG="$1"
CLANGXX="$2"
PLUGIN="$3"
SDK="$4"
PROGRAM_DIR="$5"
CONFIG_OR_PRESET="$6"
SEED="${7:-1234}"

if [ -z "$SDK" ] && command -v xcrun >/dev/null 2>&1; then
  SDK="$(xcrun --show-sdk-path 2>/dev/null || true)"
fi

SYSROOT=()
[ -n "$SDK" ] && SYSROOT=(-isysroot "$SDK")

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

failures=0
total=0

compile_one() {
  local src="$1"
  local mode="$2"
  local out="$3"
  local log="$4"
  local cc=()
  local std=()

  case "$src" in
    *.cpp)
      cc=("$CLANGXX")
      std=(-std=c++23)
      ;;
    *)
      cc=("$CLANG")
      std=(-std=c11)
      ;;
  esac

  if [ "$mode" = "obf" ]; then
    local morok_config=()
    if [ -f "$CONFIG_OR_PRESET" ]; then
      morok_config=(-mllvm -morok-config="$CONFIG_OR_PRESET")
    else
      morok_config=(-mllvm -morok-preset="$CONFIG_OR_PRESET")
    fi
    "${cc[@]}" "${SYSROOT[@]}" -O2 "${std[@]}" \
      -fpass-plugin="$PLUGIN" \
      -mllvm -morok "${morok_config[@]}" -mllvm -morok-seed="$SEED" \
      "$src" -o "$out" >"$log" 2>&1
  else
    "${cc[@]}" "${SYSROOT[@]}" -O2 "${std[@]}" \
      "$src" -o "$out" >"$log" 2>&1
  fi
}

while IFS= read -r src; do
  total=$((total + 1))
  base="$(basename "$src")"
  stem="${base%.*}"
  ref="$TMP/${stem}.ref"
  obf="$TMP/${stem}.obf"
  clean_log="$TMP/${stem}.clean.log"
  obf_log="$TMP/${stem}.obf.log"

  if ! compile_one "$src" clean "$ref" "$clean_log"; then
    echo "FAIL clean $src" >&2
    tail -80 "$clean_log" >&2
    failures=$((failures + 1))
    continue
  fi

  if ! compile_one "$src" obf "$obf" "$obf_log"; then
    echo "FAIL morok/$CONFIG_OR_PRESET $src" >&2
    tail -120 "$obf_log" >&2
    failures=$((failures + 1))
    continue
  fi

  echo "OK $src"
done < <(find "$PROGRAM_DIR" -maxdepth 1 -type f \( -name '*.c' -o -name '*.cpp' \) | sort)

if [ "$total" -eq 0 ]; then
  echo "FAIL no programs found in $PROGRAM_DIR" >&2
  exit 1
fi

if [ "$failures" -ne 0 ]; then
  echo "FAIL programs=$total failures=$failures config=$CONFIG_OR_PRESET seed=$SEED" >&2
  exit 1
fi

echo "OK programs=$total config=$CONFIG_OR_PRESET seed=$SEED"
