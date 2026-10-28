#!/usr/bin/env bash
# Build Spec §3.1 / §13, the isolation guard.
#
# Fails (exit 1) if a module imports something that could carry a credential out of the
# app. This turns "the security boundary" from a comment into an enforced invariant.
#
# TWO BOUNDARIES ARE CHECKED, in both directions:
#
#   CredentialKit  must import Foundation + AuthKit only.
#                  It is where credentials live, so nothing that could log, transmit or
#                  persist them may enter its link graph.
#
#   PrivilegedAccessKit  must import Foundation + AuthKit only.
#                  It requests a privilege ESCALATION via PIM, so keeping it unable to reach
#                  a credential makes "activating a role cannot touch a password" a property
#                  of the link graph rather than a claim in a comment.
#
#   LicensingKit   must import Foundation + CryptoKit + Security only.
#   SubscriptionKit must import Foundation + StoreKit + LicensingKit + Observation only,
#                  and must never reach a credential, it handles money, not secrets.
#                  The free-tier meter counts EVENTS. If it ever imports CredentialKit it
#                  gains the ability to hold a credential, and the guarantee that the meter
#                  cannot see passwords stops being structural and becomes a matter of
#                  care. The reverse direction was already covered above; this closes it.
#
#   InventoryKit   must import Foundation + AuthKit only, and must not depend on
#                  CredentialKit in Package.swift. The Mac menu bar app links the
#                  inventory, so this is what keeps the code that reads a password out of
#                  the Mac binary (decision 6, OPTIMIZATION-PLAN.md step J).
#
# AND WHAT EACH APP TARGET LINKS, read from the Xcode project:
#
#   TenantKeepMac               no CredentialKit
#   OnCallWatch Watch App       WatchBridgeKit only
#   OnCallComplicationsExtension WatchBridgeKit only
#   RelayNotificationService    RelayKit only
#
# Runs on macOS and Linux with no dependencies. Wire into a CI step and a
# local pre-commit hook.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT_DIR="${SCRIPT_DIR}/../LAPSlockKit/Sources"
PACKAGE="${SCRIPT_DIR}/../LAPSlockKit/Package.swift"
PBXPROJ="${SCRIPT_DIR}/../App/lapslock/lapslock.xcodeproj/project.pbxproj"

violations=0

# check_module <name> <allowed-regex> <forbidden tokens...>
#
# Scans one module's import lines twice: once against an explicit blocklist so the failure
# message names the offender, and once against an allowlist so something nobody thought to
# blocklist still gets caught.
check_module () {
  local module="$1"; shift
  local allowed="$1"; shift
  local forbidden=("$@")

  local dir="${KIT_DIR}/${module}"
  if [[ ! -d "$dir" ]]; then
    echo "❌ isolation-check: ${module} not found at $dir"
    exit 2
  fi

  echo "🔍 isolation-check: scanning ${module} imports…"

  # Every form an import takes: plain, with attributes (@preconcurrency, @_exported,
  # @_implementationOnly, @testable) and with an access level (public, package, internal).
  local import_lines
  import_lines="$(grep -rEn '^\s*(@[A-Za-z_]+\s+)*((public|package|internal|fileprivate|private)\s+)?import\s' "$dir" || true)"

  local token hits
  for token in "${forbidden[@]}"; do
    hits="$(printf '%s\n' "$import_lines" | grep -F "$token" || true)"
    if [[ -n "$hits" ]]; then
      echo "❌ Forbidden import in ${module} ('$token'):"
      printf '   %s\n' "$hits"
      violations=$((violations + 1))
    fi
  done

  # Belt-and-suspenders: anything outside the allowlist gets flagged for review. The
  # whole module name must match, so `import XFoundation` is not taken for Foundation.
  local unexpected
  unexpected="$(printf '%s\n' "$import_lines" \
    | grep -vE "import[[:space:]]+(${allowed})[[:space:]]*\$" \
    | grep -vE 'XCTest|@testable' \
    || true)"
  if [[ -n "$unexpected" ]]; then
    echo "⚠️  isolation-check: unexpected import(s) in ${module}, review manually:"
    printf '   %s\n' "$unexpected"
    echo "   (Allowed by policy: ${allowed//|/, }. Add here only after a security review.)"
    violations=$((violations + 1))
  fi
}

# Things that could carry a secret to a server, a log, or a disk.
COMMON_FORBIDDEN=(
  "AuthKitMSAL"        # MSAL must not enter a protected link graph
  "MSAL"               # ditto, direct
  "os.log"             # logging
  "OSLog"
  "import os"          # os.Logger
  "Analytics"          # any analytics SDK by convention
  "Firebase"
  "Crashlytics"
  "Sentry"
  "Mixpanel"
  "Amplitude"
  "AppCenter"
)

check_module "CredentialKit" "Foundation|AuthKit" \
  "LicensingKit" \
  "PrivilegedAccessKit" \
  "DiagnosticsKit" \
  "${COMMON_FORBIDDEN[@]}"

# PrivilegedAccessKit requests a privilege ESCALATION. Keeping it structurally unable to
# reach a credential means "activating a role cannot touch a password" is a property of the
# link graph rather than a claim in a comment.
check_module "PrivilegedAccessKit" "Foundation|AuthKit" \
  "CredentialKit" \
  "LicensingKit" \
  "InventoryKit" \
  "${COMMON_FORBIDDEN[@]}"

# ConditionalAccessKit reads policy. A module that can see what the tenant enforces must
# not be able to see a credential, so it is capped like PrivilegedAccessKit.
check_module "ConditionalAccessKit" "Foundation|AuthKit" \
  "CredentialKit" \
  "LicensingKit" \
  "InventoryKit" \
  "PrivilegedAccessKit" \
  "${COMMON_FORBIDDEN[@]}"

# SecurityKit reads incidents and the people and devices in their evidence. Same cap: it
# must never be able to see a credential.
check_module "SecurityKit" "Foundation|AuthKit" \
  "CredentialKit" \
  "LicensingKit" \
  "InventoryKit" \
  "PrivilegedAccessKit" \
  "${COMMON_FORBIDDEN[@]}"

# ThreatDigestKit talks to hosts that are not Microsoft Graph (public CISA and MSRC
# feeds). It is capped at Foundation so it can never carry a token, a tenant id or a
# credential to them: no AuthKit, nothing of the tenant's in its link graph at all.
check_module "ThreatDigestKit" "Foundation" \
  "AuthKit" \
  "CredentialKit" \
  "LicensingKit" \
  "InventoryKit" \
  "PrivilegedAccessKit" \
  "SecurityKit" \
  "${COMMON_FORBIDDEN[@]}"

# ActionGateKit performs writes. It must never be able to see a credential, so
# CredentialKit is forbidden here, and CredentialKit's own cap keeps the other direction.
check_module "ActionGateKit" "Foundation|AuthKit|PrivilegedAccessKit" \
  "CredentialKit" \
  "LicensingKit" \
  "InventoryKit" \
  "SecurityKit" \
  "ThreatDigestKit" \
  "${COMMON_FORBIDDEN[@]}"

# DeviceActionsKit builds writes for the gate. Same rule as the gate itself, and no
# InventoryKit either, because InventoryKit links CredentialKit.
check_module "DeviceActionsKit" "Foundation|AuthKit|ActionGateKit|PrivilegedAccessKit" \
  "CredentialKit" \
  "InventoryKit" \
  "LicensingKit" \
  "SecurityKit" \
  "ThreatDigestKit" \
  "${COMMON_FORBIDDEN[@]}"

# NotificationsKit decides what reaches the lock screen. Foundation and Security only, so
# nothing from Graph, no token and no payload can reach a notification's text.
check_module "NotificationsKit" "Foundation|Security" \
  "AuthKit" \
  "CredentialKit" \
  "LicensingKit" \
  "InventoryKit" \
  "PrivilegedAccessKit" \
  "SecurityKit" \
  "SignInTriageKit" \
  "${COMMON_FORBIDDEN[@]}"

# ManagedConfigKit parses what the organization pushes. Foundation only.
check_module "ManagedConfigKit" "Foundation" \
  "AuthKit" \
  "CredentialKit" \
  "LicensingKit" \
  "InventoryKit" \
  "${COMMON_FORBIDDEN[@]}"

# UserActionsKit sends writes against people's accounts. Same rule as the gate: never a
# credential in its link graph, which is why the Temporary Access Pass is not here.
check_module "UserActionsKit" "Foundation|AuthKit|ActionGateKit|PrivilegedAccessKit" \
  "CredentialKit" \
  "InventoryKit" \
  "LicensingKit" \
  "SecurityKit" \
  "${COMMON_FORBIDDEN[@]}"

# GroupWritesKit changes who is in a group. A write module, so never a credential in its
# link graph, in either direction.
check_module "GroupWritesKit" "Foundation|AuthKit|ActionGateKit|PrivilegedAccessKit" \
  "CredentialKit" \
  "InventoryKit" \
  "LicensingKit" \
  "SecurityKit" \
  "UserActionsKit" \
  "${COMMON_FORBIDDEN[@]}"

# ApprovalsKit approves or denies other people's PIM requests. A write module that grants
# privilege to someone else, so never a credential in its link graph.
check_module "ApprovalsKit" "Foundation|AuthKit|ActionGateKit|PrivilegedAccessKit" \
  "CredentialKit" \
  "InventoryKit" \
  "LicensingKit" \
  "SecurityKit" \
  "UserActionsKit" \
  "GroupWritesKit" \
  "${COMMON_FORBIDDEN[@]}"

# WatchBridgeKit is everything that crosses to the Apple Watch. Foundation only, so nothing
# that holds or fetches a credential, a token or tenant data can be reached from it.
check_module "WatchBridgeKit" "Foundation" \
  "AuthKit" \
  "CredentialKit" \
  "PrivilegedAccessKit" \
  "ActionGateKit" \
  "LicensingKit" \
  "InventoryKit" \
  "${COMMON_FORBIDDEN[@]}"

# RelayKit holds the phone's relay key and opens relayed alerts, in the app and in the
# notification extension. Foundation, CryptoKit and Security only: it never sees a token, a
# credential or tenant data beyond the alert it was sent.
check_module "RelayKit" "Foundation|CryptoKit|Security" \
  "AuthKit" \
  "CredentialKit" \
  "PrivilegedAccessKit" \
  "ActionGateKit" \
  "LicensingKit" \
  "InventoryKit" \
  "${COMMON_FORBIDDEN[@]}"

# SavedSearchKit keeps an admin's saved searches on the device. Foundation only: it can
# hold a sign-in address someone typed, and must never be able to reach a token, a
# credential or Graph.
check_module "SavedSearchKit" "Foundation" \
  "AuthKit" \
  "CredentialKit" \
  "PrivilegedAccessKit" \
  "ActionGateKit" \
  "LicensingKit" \
  "InventoryKit" \
  "${COMMON_FORBIDDEN[@]}"

# TenantPulseKit reads tenant state. Same cap: it must never be able to see a credential.
check_module "TenantPulseKit" "Foundation|AuthKit" \
  "CredentialKit" \
  "LicensingKit" \
  "InventoryKit" \
  "PrivilegedAccessKit" \
  "${COMMON_FORBIDDEN[@]}"

# SignInTriageKit reads the sign-in log. Same cap.
check_module "SignInTriageKit" "Foundation|AuthKit" \
  "CredentialKit" \
  "LicensingKit" \
  "InventoryKit" \
  "PrivilegedAccessKit" \
  "${COMMON_FORBIDDEN[@]}"

check_module "LicensingKit" "Foundation|CryptoKit|Security" \
  "CredentialKit" \
  "InventoryKit" \
  "DiagnosticsKit" \
  "PrivilegedAccessKit" \
  "${COMMON_FORBIDDEN[@]}"

# SubscriptionKit handles MONEY. It must never be able to see a credential: an Apple
# receipt and a local administrator password have no business in the same link graph, and
# a payments SDK is exactly the kind of dependency that grows telemetry over time.
check_module "SubscriptionKit" "Foundation|StoreKit|LicensingKit|Observation" \
  "CredentialKit" \
  "InventoryKit" \
  "PrivilegedAccessKit" \
  "${COMMON_FORBIDDEN[@]}"

# The inventory: what the device list and the Mac menu bar app are built from. Capped so
# that neither can contain the code that reads a credential.
check_module "InventoryKit" "Foundation|AuthKit" \
  "CredentialKit" \
  "LicensingKit" \
  "PrivilegedAccessKit" \
  "${COMMON_FORBIDDEN[@]}"

# check_package_deps <target> <forbidden dependencies...>
#
# An import is not the only way into a link graph: a dependency in Package.swift links the
# module whether or not a file imports it.
check_package_deps () {
  local target="$1"; shift
  local declaration
  declaration="$(awk -v t="$target" '
    index($0, ".target(name: \"" t "\"") { on = 1 }
    on { print }
    on && /\)[[:space:]]*,?[[:space:]]*$/ { exit }
  ' "$PACKAGE")"
  if [[ -z "$declaration" ]]; then
    echo "❌ isolation-check: target ${target} not found in Package.swift"
    exit 2
  fi
  echo "🔍 isolation-check: checking ${target}'s Package.swift dependencies…"
  local dep
  for dep in "$@"; do
    if printf '%s\n' "$declaration" | grep -qF "\"${dep}\""; then
      echo "❌ ${target} depends on ${dep} in Package.swift"
      violations=$((violations + 1))
    fi
  done
}

check_package_deps "InventoryKit" "CredentialKit" "LicensingKit" "PrivilegedAccessKit"

# target_products <app target>: the package products an app target links, one a line, from
# its packageProductDependencies in the Xcode project.
target_products () {
  awk -v t="$1" '
    index($0, "/* " t " */ = {") { block = 1; native = 0; next }
    block && /isa = PBXNativeTarget;/ { native = 1 }
    block && native && /packageProductDependencies = \(/ { list = 1; next }
    list && /\);/ { exit }
    list {
      s = $0
      sub(/^[^*]*\/\* /, "", s)
      sub(/ \*\/.*$/, "", s)
      print s
    }
    block && /^\t\t\};/ { block = 0 }
  ' "$PBXPROJ"
}

# check_target_links <app target> <mode> <products...>
#   mode "only": the target may link these products and nothing else.
#   mode "never": the target must link none of these.
check_target_links () {
  local target="$1"; shift
  local mode="$1"; shift
  local linked
  linked="$(target_products "$target")"
  if ! grep -q "/\* ${target} \*/ = {" "$PBXPROJ"; then
    echo "❌ isolation-check: app target ${target} not found in the Xcode project"
    exit 2
  fi
  # Every one of these targets links at least one kit. Reading none means the project's
  # format moved under this parser, and passing would be a check that checks nothing.
  if [[ -z "$linked" ]]; then
    echo "❌ isolation-check: read no package products for ${target}; the project format may have changed"
    exit 2
  fi
  echo "🔍 isolation-check: checking what ${target} links…"
  local product
  if [[ "$mode" == "only" ]]; then
    while IFS= read -r product; do
      [[ -z "$product" ]] && continue
      local allowed=0 want
      for want in "$@"; do [[ "$product" == "$want" ]] && allowed=1; done
      if [[ "$allowed" -eq 0 ]]; then
        echo "❌ ${target} links ${product}; it may link only: $*"
        violations=$((violations + 1))
      fi
    done <<< "$linked"
  else
    for product in "$@"; do
      if printf '%s\n' "$linked" | grep -qx "$product"; then
        echo "❌ ${target} links ${product}, which it must never link"
        violations=$((violations + 1))
      fi
    done
  fi
}

check_target_links "TenantKeepMac" never "CredentialKit"
check_target_links "OnCallWatch Watch App" only "WatchBridgeKit"
check_target_links "OnCallComplicationsExtension" only "WatchBridgeKit"
check_target_links "RelayNotificationService" only "RelayKit"

if [[ "$violations" -gt 0 ]]; then
  echo ""
  echo "❌ isolation-check FAILED: $violations issue(s)."
  echo "   CredentialKit must stay isolated, and LicensingKit must never reach it (Spec §3.1)."
  exit 1
fi

echo "✅ isolation-check passed: CredentialKit imports only Foundation + AuthKit,"
echo "   LicensingKit cannot reach CredentialKit, and PrivilegedAccessKit, which requests"
echo "   privilege escalation, cannot reach a credential. The inventory and the Mac menu"
echo "   bar app cannot reach one either, and the watch and the notification extension"
echo "   link only their own kits."
