#!/usr/bin/env bash
# Build Spec §3.1 / §13 — the isolation guard.
#
# Fails (exit 1) if CredentialKit imports any module that could exfiltrate a
# credential: the licensing layer, any analytics SDK, or any logging framework.
# This turns "the security boundary" from a comment into an enforced invariant.
#
# Runs on macOS and Linux with no dependencies. Wire into a CI step and a
# local pre-commit hook.

set -euo pipefail

# Resolve repo-relative path to the credential module.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRED_DIR="${SCRIPT_DIR}/../PitLAPSKit/Sources/CredentialKit"

if [[ ! -d "$CRED_DIR" ]]; then
  echo "❌ isolation-check: CredentialKit not found at $CRED_DIR"
  exit 2
fi

# Modules/frameworks CredentialKit must never import.
FORBIDDEN=(
  "LicensingKit"       # backend/licensing — could carry a secret to a server
  "AuthKitMSAL"        # MSAL must not enter the credential link graph
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

echo "🔍 isolation-check: scanning CredentialKit imports…"
violations=0

# Collect actual import lines once.
IMPORT_LINES="$(grep -rEn '^\s*(import|@_implementationOnly import)\s' "$CRED_DIR" || true)"

for token in "${FORBIDDEN[@]}"; do
  # Match the token as an imported name on an import line.
  hits="$(printf '%s\n' "$IMPORT_LINES" | grep -F "$token" || true)"
  if [[ -n "$hits" ]]; then
    echo "❌ Forbidden import in CredentialKit ('$token'):"
    printf '   %s\n' "$hits"
    violations=$((violations + 1))
  fi
done

# Belt-and-suspenders: the only imports we expect are Foundation and AuthKit.
UNEXPECTED="$(printf '%s\n' "$IMPORT_LINES" \
  | grep -vE '(Foundation|AuthKit)$' \
  | grep -vE 'XCTest|@testable' \
  || true)"
if [[ -n "$UNEXPECTED" ]]; then
  echo "⚠️  isolation-check: unexpected import(s) in CredentialKit — review manually:"
  printf '   %s\n' "$UNEXPECTED"
  echo "   (Allowed by policy: Foundation, AuthKit. Add here only after a security review.)"
  violations=$((violations + 1))
fi

if [[ "$violations" -gt 0 ]]; then
  echo ""
  echo "❌ isolation-check FAILED: $violations issue(s). CredentialKit must stay isolated (Spec §3.1)."
  exit 1
fi

echo "✅ isolation-check passed: CredentialKit imports only Foundation + AuthKit."
