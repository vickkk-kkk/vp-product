#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"
mkdir -p flutter/evidence
flutter/tools/sdk.sh dart format --output=none --set-exit-if-changed flutter/apps flutter/packages | tee flutter/evidence/format-final.log
for project in packages/vp_contracts packages/vp_design_system packages/vp_runtime_platform packages/vp_api_client packages/vp_features apps/vp_admin; do
  name=${project##*/}
  (cd "flutter/$project" && ../../tools/sdk.sh analyze --no-pub) 2>&1 | tee "flutter/evidence/analyze-$name.log"
  if find "flutter/$project/test" -name '*_test.dart' -print -quit 2>/dev/null | grep -q .; then
    (cd "flutter/$project" && ../../tools/sdk.sh test --no-pub --reporter expanded) 2>&1 | tee "flutter/evidence/test-$name.log"
  fi
done
(cd flutter/apps/vp_admin && ../../tools/sdk.sh build web --release --no-pub --no-web-resources-cdn --pwa-strategy=none) 2>&1 | tee flutter/evidence/build-admin-web.log
