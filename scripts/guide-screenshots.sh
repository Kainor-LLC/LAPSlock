#!/usr/bin/env bash
# Takes the pictures the guide on tenantkeep.app needs beyond the App Store set: Settings,
# its Actions and Permissions page, and the two confirmations. Demo data only.
#
#     ./scripts/guide-screenshots.sh <simulator udid> <output folder>
#
# Needs the same Debug build installed on a booted simulator as store-screenshots.sh, and
# works the same way: each shot relaunches the app with -LAPSlockDemo and -LAPSlockShot.
# The settings named on the launch line apply to that launch only and are not saved: the
# app lock off so the app opens, and user actions on so a person has actions to confirm.
# A confirmation is only opened. Nothing is sent, in demo data or otherwise.

set -uo pipefail

UDID="${1:?simulator udid}"
OUT="${2:?output folder}"
BUNDLE="com.kainor.lapslock"
mkdir -p "$OUT"

xcrun simctl status_bar "$UDID" override --time "9:41" --batteryState charged --batteryLevel 100 --cellularBars 4 --wifiBars 3 >/dev/null 2>&1

# name, screen, seconds to wait before the picture
shot() {
  local name="$1" screen="$2" wait="${3:-8}"
  xcrun simctl launch --terminate-running-process "$UDID" "$BUNDLE" -LAPSlockDemo -LAPSlockShot "$screen" \
    -settings.listWidthPreset balanced -settings.appLockEnabled NO -settings.userActionsEnabled YES >/dev/null
  sleep "$wait"
  xcrun simctl io "$UDID" screenshot "$OUT/$name.png" >/dev/null 2>&1 && echo "saved $name.png" || echo "FAILED $name.png"
}

shot settings settings
shot actions-settings settings-actions
shot confirm confirm 11
shot confirm-typed confirm-typed 11
