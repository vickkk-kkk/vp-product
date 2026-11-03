#!/bin/sh
# Build the pinned vp_core Android adapter only; no installation or publishing.
set -eu
if [ "$#" -ne 1 ]; then echo "Usage: $0 OUTPUT_DIRECTORY" >&2; exit 2; fi
: "${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to an existing Android NDK}"
: "${VP_CORE_UPSTREAM:?Set VP_CORE_UPSTREAM to the clean pinned upstream checkout}"
case "$(uname -s)" in
    Darwin) host=darwin-x86_64 ;;
    Linux) host=linux-x86_64 ;;
    *) echo "Unsupported build host" >&2; exit 2 ;;
esac
dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
root=$(CDPATH= cd -- "$dir/../../.." && pwd -P)
tools="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$host/bin"
linker="$tools/aarch64-linux-android26-clang"
for tool in "$linker" "$tools/llvm-ar" "$tools/llvm-readelf" "$tools/llvm-nm"; do
    [ -x "$tool" ] || { echo "Missing NDK tool: $tool" >&2; exit 2; }
done
command -v cargo >/dev/null
command -v rustc >/dev/null
command -v python3 >/dev/null
[ -f "$root/integration/vp_core/crates/vp-core/Cargo.toml" ] || {
    echo "Pinned integration/vp_core is absent; prepare and verify it first." >&2; exit 2;
}
python3 "$root/tools/core/core_pipeline.py" check --root "$root" --upstream "$VP_CORE_UPSTREAM"
mkdir -p "$1"
out=$(CDPATH= cd -- "$1" && pwd -P)
result="$out/libvp_product_core_adapter.so"
[ ! -e "$result" ] || { echo "Output already exists; choose an empty output directory." >&2; exit 2; }
work=$(mktemp -d "${TMPDIR:-/tmp}/vp-core-arm64.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
export CARGO_TARGET_DIR="$work/target"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$linker"
export CC_aarch64_linux_android="$linker"
export AR_aarch64_linux_android="$tools/llvm-ar"
export CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0
export VP_VERIFIED_TOOLCHAIN="$(rustc --version)"
cd "$root"
set -- build --locked --release -p vp-product-core-adapter --lib --features mobile-ffi --target aarch64-linux-android
if [ "${VP_CARGO_OFFLINE:-0}" = 1 ]; then set -- "$@" --offline; fi
cargo "$@"
lib="$CARGO_TARGET_DIR/aarch64-linux-android/release/libvp_product_core_adapter.so"
"$tools/llvm-readelf" -h "$lib" | grep -Eq 'Machine:.*AArch64' || { echo "Adapter is not AArch64" >&2; exit 1; }
for symbol in vp_adapter_abi_info vp_adapter_validate_connect vp_adapter_create vp_adapter_request vp_adapter_next_event vp_adapter_destroy vp_adapter_bytes_free; do
    "$tools/llvm-nm" -D --defined-only "$lib" | grep -Eq "[[:space:]]$symbol$" || { echo "Missing ABI symbol: $symbol" >&2; exit 1; }
done
cp "$lib" "$result"
if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$result"; else sha256sum "$result"; fi
echo "Built $result. A successful build does not establish VPN interoperability."
