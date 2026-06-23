#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Regression: cross_build.sh must use host-aware defaults. Linux hosts should not
# try to build macOS artifacts or load a Mach-O plugin by default.
set -euo pipefail

script="${1:?usage: cross_build_platform_defaults.sh <path-to-cross_build.sh>}"

fail() { echo "FAIL: $*"; exit 1; }

got="$("$script" --emit-platform-defaults)"
host="$(printf '%s\n' "$got" | awk -F= '$1 == "host" { print $2 }')"
linux="$(printf '%s\n' "$got" | awk -F= '$1 == "linux" { print $2 }')"
macos="$(printf '%s\n' "$got" | awk -F= '$1 == "macos" { print $2 }')"
plugin="$(printf '%s\n' "$got" | awk -F= '$1 == "plugin" { print $2 }')"

[ "$linux" = "1" ] || fail "default linux build flag is '$linux', expected 1"

case "$host" in
  Darwin)
    [ "$macos" = "1" ] || fail "Darwin default macOS build flag is '$macos', expected 1"
    case "$plugin" in
      *.dylib) ;;
      *) fail "Darwin default plugin is '$plugin', expected .dylib suffix" ;;
    esac
    ;;
  *)
    [ "$macos" = "0" ] || fail "$host default macOS build flag is '$macos', expected 0"
    case "$plugin" in
      *.so) ;;
      *) fail "$host default plugin is '$plugin', expected .so suffix" ;;
    esac
    ;;
esac

echo "PASS: cross_build uses host-aware platform defaults"
