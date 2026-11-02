#!/usr/bin/env sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
target=${CARGO_TARGET_DIR:-"$root/target"}
case "$target" in /*) ;; *) target="$root/$target" ;; esac
cc -std=c11 -Wall -Wextra -Werror -I"$root/contracts/abi" \
  "$root/crates/vp-codec-ffi/tests/abi.c" -L"$target/debug" \
  -Wl,-rpath,"$target/debug" -lvp_product_codec_ffi -o "$target/codec-abi-harness"
"$target/codec-abi-harness"
