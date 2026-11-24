#!/bin/zsh
# The app target's own tests (App/lapslock/lapslockTests), run inside the app on a simulator.
# The fourth gate beside isolation-check.sh, pre-push-scan.sh and test-check.sh, from 2.1
# (second review, R2-30): the package tests cannot run the screens' models, and the tests
# that read the app's source as text passed with its guards broken.
#
#   ./scripts/app-test-check.sh
#   APP_TEST_DESTINATION='platform=iOS Simulator,id=<udid>' ./scripts/app-test-check.sh
set -euo pipefail
cd "$(dirname "$0")/.."
destination=${APP_TEST_DESTINATION:-"platform=iOS Simulator,name=iPhone 18 Pro"}
log=$(mktemp -t app-test-check)
if xcodebuild test -project App/lapslock/lapslock.xcodeproj -scheme lapslock \
     -destination "$destination" -only-testing:lapslockTests >"$log" 2>&1; then
  ran=$(grep -E "^\s+Executed [0-9]+ tests?, with 0 failures" "$log" | tail -1 | sed -E 's/.*Executed ([0-9]+) tests?.*/\1/')
  echo "✅ app-test-check passed: ${ran:-?} app tests on $destination"
else
  grep -E " error: |Test Case .* failed|TEST FAILED" "$log" | head -20
  echo "❌ app-test-check failed. Full log: $log"
  exit 1
fi
