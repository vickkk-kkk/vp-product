#!/usr/bin/env python3
"""Fail when a clean product checkout omits the Android runtime host."""
from pathlib import Path
import sys

root = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else Path(__file__).resolve().parents[4]
host = root / "flutter/packages/vp_runtime_android/android/src/main"
required = [host / "cpp/vp_android_host.cpp"]
required.extend(host / "kotlin/org/vp/product/runtime" / name for name in (
    "VpVpnService.kt", "NativeRuntime.kt", "NotificationPublication.kt", "RuntimeIdentity.kt",
))
missing = [str(path.relative_to(root)) for path in required if not path.is_file()]
if missing:
    print("Missing Android runtime sources:\n" + "\n".join(missing), file=sys.stderr)
    sys.exit(1)
print("Android runtime host sources present; compilation and device testing still required.")
