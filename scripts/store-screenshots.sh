#!/usr/bin/env bash
# Takes the App Store screenshots from a simulator, in demo data, the same way every time.
#
#     ./scripts/store-screenshots.sh <simulator udid> <output folder> [display]
#
# The optional third argument names the display to capture, for a simulator with more than
# one: the iPhone Duo's cover display is 1 and its inner display, once it is open, is 3.
#
# Needs a Debug build for the simulator already installed on a booted simulator:
#
#     xcodebuild -project App/lapslock/lapslock.xcodeproj -scheme lapslock \
#       -destination 'generic/platform=iOS Simulator' -configuration Debug build
#     xcrun simctl install <udid> <path to lapslock.app>
#
# Each shot relaunches the app with -LAPSlockDemo and -LAPSlockShot <screen>, which exist
# only in Debug builds and only open what a person would have tapped. Nothing here signs
# in to Microsoft, and nothing but demo data is ever on screen.

set -uo pipefail

UDID="${1:?simulator udid}"
OUT="${2:?output folder}"
DISPLAY_ARGS=()
if [[ -n "${3:-}" ]]; then DISPLAY_ARGS=(--display="$3"); fi
BUNDLE="com.kainor.lapslock"
mkdir -p "$OUT"

xcrun simctl status_bar "$UDID" override --time "9:41" --batteryState charged --batteryLevel 100 --cellularBars 4 --wifiBars 3 >/dev/null 2>&1
# Face ID enrolled, so a reveal can be approved below.
xcrun simctl spawn "$UDID" notifyutil -s com.apple.BiometricKit.enrollmentChanged 1 >/dev/null 2>&1
xcrun simctl spawn "$UDID" notifyutil -p com.apple.BiometricKit.enrollmentChanged >/dev/null 2>&1

# name, screen, seconds to wait before the picture
shot() {
  local name="$1" screen="$2" wait="${3:-6}"
  if [[ -n "$screen" ]]; then
    xcrun simctl launch --terminate-running-process "$UDID" "$BUNDLE" -LAPSlockDemo -LAPSlockShot "$screen" >/dev/null
  else
    xcrun simctl launch --terminate-running-process "$UDID" "$BUNDLE" -LAPSlockDemo >/dev/null
  fi
  sleep "$wait"
  if [[ "$screen" == "reveal" ]]; then
    # The reveal asked for Face ID or Touch ID; this is the matching face and finger.
    xcrun simctl spawn "$UDID" notifyutil -p com.apple.BiometricKit_Sim.pearl.match >/dev/null 2>&1
    xcrun simctl spawn "$UDID" notifyutil -p com.apple.BiometricKit_Sim.fingerTouch.match >/dev/null 2>&1
    sleep 3
  fi
  xcrun simctl io "$UDID" screenshot ${DISPLAY_ARGS[@]+"${DISPLAY_ARGS[@]}"} "$OUT/$name.png" >/dev/null 2>&1 && echo "saved $name.png" || echo "FAILED $name.png"
}

shot 01-modules ""
shot 02-devices devices
shot 03-laps-reveal reveal 7
shot 04-device device 7
shot 05-privileged-access privileged
shot 06-approvals approvals
shot 07-people people
shot 08-person person 8
shot 09-tenant-pulse pulse
shot 10-conditional-access policies
shot 11-policy policy 8
shot 12-incidents incidents
shot 13-incident incident 8
shot 14-threat-digest digest 9
shot 15-threat-digest-card digest-item 10
shot 16-email-investigation email
