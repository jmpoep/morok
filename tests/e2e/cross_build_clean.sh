#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Regression for issue #116: --clean must not be able to delete arbitrary local
# directories through OUT_DIR values such as '.', '..', $HOME, symlink escapes,
# or absolute paths outside the build tree.
set -euo pipefail

script="${1:?usage: cross_build_clean.sh <path-to-cross_build.sh>}"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

fail() { echo "FAIL: $*"; exit 1; }

build="$workdir/build"
home="$workdir/home"
outside="$workdir/outside"
mkdir -p "$build" "$home" "$outside"

expect_refused() {
  local name="$1" out_dir="$2" log="$workdir/$1.log"
  if BUILD_DIR="$build" HOME="$home" "$script" \
      --clean --out-dir "$out_dir" --check-clean-dir >"$log" 2>&1; then
    cat "$log"
    fail "$name: unsafe clean target was accepted"
  fi
  grep -q 'refusing to --clean' "$log" ||
    fail "$name: refusal did not explain --clean safety"
}

safe="$build/cross"
got="$(BUILD_DIR="$build" "$script" \
  --clean --out-dir "$safe" --check-clean-dir)"
case "$got" in
  */build/cross) ;;
  *) fail "safe build descendant resolved to unexpected path: $got" ;;
esac

expect_refused "repo-root" "."
expect_refused "parent-workspace" ".."
expect_refused "home" "$home"
expect_refused "absolute-outside" "$outside"
expect_refused "build-dir-itself" "$build"
expect_refused "parent-of-child" "$build/cross/.."

ln -s "$home" "$build/escape"
expect_refused "symlink-escape" "$build/escape"

echo "PASS: cross_build --clean refuses unsafe output directories"
