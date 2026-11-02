#!/usr/bin/env bash
# Pure codec build only: no guest execution, installation, signing or publication.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
export CARGO_HOME="$ROOT/.toolchains/cargo" RUSTUP_HOME="$ROOT/.toolchains/rustup"
export PATH="$CARGO_HOME/bin:$PATH"
export CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-"$ROOT/.local-cache/product-core-target"}
TARGET=${1:-x86_64-linux-android}
NDK="$ROOT/.toolchains/android/ndk/28.2.13676358/toolchains/llvm/prebuilt/linux-x86_64/bin"
case "$TARGET" in
 x86_64-linux-android) COMPILER=x86_64-linux-android26-clang; UPPER=X86_64_LINUX_ANDROID; LOWER=x86_64_linux_android;;
 aarch64-linux-android) COMPILER=aarch64-linux-android26-clang; UPPER=AARCH64_LINUX_ANDROID; LOWER=aarch64_linux_android;;
 *) echo 'Unsupported target; choose x86_64-linux-android or aarch64-linux-android' >&2; exit 2;;
esac
[[ -x "$NDK/$COMPILER" ]]
export "CARGO_TARGET_${UPPER}_LINKER=$NDK/$COMPILER"
export "CC_${LOWER}=$NDK/$COMPILER" "AR_${LOWER}=$NDK/llvm-ar"
cd "$ROOT"
cargo build --offline --locked -p vp-product-codec-ffi --lib --target "$TARGET"
LIB="$CARGO_TARGET_DIR/$TARGET/debug/libvp_product_codec_ffi.so"
"$NDK/llvm-readelf" -h "$LIB"
"$NDK/llvm-readelf" -d "$LIB" | grep NEEDED
"$NDK/llvm-nm" --dynamic --defined-only "$LIB" | grep ' vp_codec_'
sha256sum "$LIB"
