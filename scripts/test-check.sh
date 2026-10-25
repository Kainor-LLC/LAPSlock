#!/usr/bin/env bash
# Runs the package tests and refuses to report green unless every test bundle ran and the
# total did not fall below the floor in scripts/test-floor.
#
# Why this exists: after a toolchain upgrade a stale .build invoked eight stale bundles,
# seven of them printed nothing under the new runtime, "Build complete!" appeared, the
# command exited 0, and the pre-commit guard passed on 62 of 379 tests. A green that counts
# nothing is worse than a red. This replaces the bare swift test in the before-commit list.
#
#     ./scripts/test-check.sh            from the repository root
#     ./scripts/test-check.sh --clean    wipes LAPSlockKit/.build first; run after ANY Xcode or Swift update
#
# Exit codes: 0 every bundle reported and the floor held, 1 otherwise.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT_DIR="${SCRIPT_DIR}/../LAPSlockKit"
FLOOR_FILE="${SCRIPT_DIR}/test-floor"

if [[ "${1:-}" == "--clean" ]]; then
  echo "🧹 test-check: removing ${KIT_DIR}/.build"
  rm -rf "${KIT_DIR}/.build"
fi

expected_bundles="$(grep -c '\.testTarget(' "${KIT_DIR}/Package.swift")"
floor="$(tr -d '[:space:]' < "${FLOOR_FILE}")"

echo "🔍 test-check: expecting ${expected_bundles} bundles and at least ${floor} tests"

output="$(cd "${KIT_DIR}" && swift test 2>&1)"
status=$?

printf '%s\n' "$output" | grep -E "Tests\.xctest' (passed|failed)|error:|XCTAssert|failed \(" | tail -n 40

bundles_passed="$(printf '%s\n' "$output" | grep -c "Tests\.xctest' passed")"
bundles_failed="$(printf '%s\n' "$output" | grep -c "Tests\.xctest' failed")"

# Each bundle prints its own "Executed N tests" line right after its suite line. Summing
# those is the total; the last "Executed" line alone is one bundle, not the run.
total=0
while read -r n; do
  total=$((total + n))
done < <(printf '%s\n' "$output" | grep -A1 -E "Tests\.xctest' (passed|failed)" | grep -Eo 'Executed [0-9]+ test' | grep -Eo '[0-9]+')

problems=0
if [[ "$status" -ne 0 ]]; then
  echo "❌ swift test exited ${status}"
  problems=$((problems + 1))
fi
if [[ "$bundles_failed" -gt 0 ]]; then
  echo "❌ ${bundles_failed} bundle(s) reported failures"
  problems=$((problems + 1))
fi
if [[ "$bundles_passed" -ne "$expected_bundles" ]]; then
  echo "❌ ${bundles_passed} of ${expected_bundles} bundles reported. A stale .build is the usual cause; rerun with --clean"
  problems=$((problems + 1))
fi
if [[ "$total" -lt "$floor" ]]; then
  echo "❌ ${total} tests ran, the floor is ${floor}"
  problems=$((problems + 1))
fi

if [[ "$problems" -gt 0 ]]; then
  echo "❌ test-check FAILED"
  exit 1
fi

if [[ "$total" -gt "$floor" ]]; then
  echo "ℹ️  ${total} tests ran. Raise scripts/test-floor from ${floor} so the floor keeps up"
fi
echo "✅ test-check passed: ${bundles_passed} bundles, ${total} tests"
