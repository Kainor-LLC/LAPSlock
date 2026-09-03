#!/usr/bin/env bash
# Build Spec §3.1 / §13 — the isolation guard.
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
#   SubscriptionKit must import Foundation + StoreKit + LicensingKit only, and must
#                  never reach a credential — it handles money, not secrets.
#                  The free-tier meter counts EVENTS. If it ever imports CredentialKit it
#                  gains the ability to hold a credential, and the guarantee that the meter
#                  cannot see passwords stops being structural and becomes a matter of
#                  care. The reverse direction was already covered above; this closes it.
#
# Runs on macOS and Linux with no dependencies. Wire into a CI step and a
# local pre-commit hook.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT_DIR="${SCRIPT_DIR}/../LAPSlockKit/Sources"

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

  local import_lines
  import_lines="$(grep -rEn '^\s*(import|@_implementationOnly import)\s' "$dir" || true)"

  local token hits
  for token in "${forbidden[@]}"; do
    hits="$(printf '%s\n' "$import_lines" | grep -F "$token" || true)"
    if [[ -n "$hits" ]]; then
      echo "❌ Forbidden import in ${module} ('$token'):"
      printf '   %s\n' "$hits"
      violations=$((violations + 1))
    fi
  done

  # Belt-and-suspenders: anything outside the allowlist gets flagged for review.
  local unexpected
  unexpected="$(printf '%s\n' "$import_lines" \
    | grep -vE "(${allowed})\$" \
    | grep -vE 'XCTest|@testable' \
    || true)"
  if [[ -n "$unexpected" ]]; then
    echo "⚠️  isolation-check: unexpected import(s) in ${module} — review manually:"
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

check_module "LicensingKit" "Foundation|CryptoKit|Security" \
  "CredentialKit" \
  "InventoryKit" \
  "DiagnosticsKit" \
  "PrivilegedAccessKit" \
  "${COMMON_FORBIDDEN[@]}"

# SubscriptionKit handles MONEY. It must never be able to see a credential: an Apple
# receipt and a local administrator password have no business in the same link graph, and
# a payments SDK is exactly the kind of dependency that grows telemetry over time.
check_module "SubscriptionKit" "Foundation|StoreKit|LicensingKit" \
  "CredentialKit" \
  "InventoryKit" \
  "PrivilegedAccessKit" \
  "${COMMON_FORBIDDEN[@]}"

if [[ "$violations" -gt 0 ]]; then
  echo ""
  echo "❌ isolation-check FAILED: $violations issue(s)."
  echo "   CredentialKit must stay isolated, and LicensingKit must never reach it (Spec §3.1)."
  exit 1
fi

echo "✅ isolation-check passed: CredentialKit imports only Foundation + AuthKit,"
echo "   LicensingKit cannot reach CredentialKit, and PrivilegedAccessKit — which requests"
echo "   privilege escalation — cannot reach a credential."
