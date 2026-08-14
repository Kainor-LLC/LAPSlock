#!/usr/bin/env bash
# Pre-push sensitive-data scan for a PUBLIC repository.
#
# This repo is public and credentials-adjacent, so the cost of leaking the wrong
# string is high. Run this before every push:
#
#     ./scripts/pre-push-scan.sh
#
# It scans the working tree AND the full git history (history matters because a
# committed secret stays retrievable even after you delete the line in a later commit).
#
# Exit codes: 0 = clean, 1 = findings to review.
#
# NOTE: this is a heuristic, not a guarantee. It catches the categories we know about.
# Review anything it flags rather than assuming a hit is a false positive.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$REPO_ROOT"

findings=0

hr() { printf '%s\n' "------------------------------------------------------------"; }

# $1 = category label, $2..$n = regex patterns
scan() {
  local label="$1"; shift
  local pattern
  local hit_any=0

  for pattern in "$@"; do
    # Working tree (skip .git, binaries, and this script itself)
    local wt
    wt="$(grep -rniIE "$pattern" . \
          --exclude-dir=.git \
          --exclude-dir=DerivedData \
          --exclude-dir=.build \
          --exclude="pre-push-scan.sh" 2>/dev/null || true)"

    # Git history (all blobs ever committed)
    local hist
    hist="$(git grep -niIE "$pattern" $(git rev-list --all 2>/dev/null) -- 2>/dev/null \
            | grep -v "pre-push-scan.sh" || true)"

    if [[ -n "$wt" || -n "$hist" ]]; then
      if [[ "$hit_any" -eq 0 ]]; then
        echo "❌ $label"
        hit_any=1
      fi
      [[ -n "$wt" ]]   && printf '   [working tree] %s\n' "$wt"
      [[ -n "$hist" ]] && printf '   [history]      %s\n' "$hist"
    fi
  done

  if [[ "$hit_any" -eq 1 ]]; then
    findings=$((findings + 1))
  else
    echo "✅ $label"
  fi
}

echo "🔍 Scanning $(basename "$REPO_ROOT") for data that should not be public"
hr

# --- Employer / customer tenant identifiers -------------------------------------
# Publishing a customer's (or employer's) internal identifiers under the LLC's name
# is both a trust problem and, with ALFP as a prospective customer, a business one.
scan "Employer domain / names" \
  'american[-_ ]?life' \
  '\bALFP\b'

scan "Employer email addresses" \
  '[A-Za-z0-9._%+-]+@american-life\.com' \
  'cjohnson@'

scan "Employer tenant / device GUIDs seen in testing" \
  '5dd02ad7-b1a9-486d-a7c6-07b9bf31fa80' \
  'a4389337-d506-4e9f-a031-946147ce92ba' \
  '6645cc00-ddc3-454e-b411-c61598702480' \
  '7860fc9c-ee80-4acd-bcf8-a3909dd8bb9a' \
  'b59908c9-4f14-4472-acfc-c6a4de89c69b' \
  'a63752c9-14b7-4a82-85c1-98f41c3009e6' \
  'a9858c77-dfef-4a46-8ada-b164ffe26b2e' \
  'bd367e9e-2f43-490d-92d0-67c7bc9bb842'

scan "Device names / serial numbers" \
  'MBA-[A-Z0-9]{8,}' \
  '\b(M3GPL9Q0K0|DJGJMHY9HJ|K0H1W4FW3L|LGWQ4R509P|DHDW5CQPH4|D6XJX1G967)\b'

# --- Personal / business PII ---------------------------------------------------
# connor@kainor.com is INTENTIONALLY public (contact address on the site), so it is
# deliberately not flagged here.
scan "Business/personal PII (EIN, DUNS, home address, phone)" \
  '\b42-?2704736\b' \
  '18731[[:space:]]+Ocheltree' \
  '402-?499-?0272' \
  '\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b'

# --- Secrets -------------------------------------------------------------------
# The app is a public client with no secret by design, so ANY hit here is serious.
scan "Credential-shaped strings" \
  '(client[_-]?secret|api[_-]?key|private[_-]?key)[[:space:]]*[:=]' \
  'BEGIN (RSA|OPENSSH|PRIVATE) KEY' \
  'gh[pousr]_[A-Za-z0-9]{16,}' \
  'passwordBase64[[:space:]]*[:=][[:space:]]*"[A-Za-z0-9+/]{8,}'

scan "Bearer tokens / JWTs" \
  'eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}' \
  'Bearer[[:space:]]+[A-Za-z0-9._-]{40,}'

# --- Build artifacts that shouldn't be tracked ---------------------------------
hr
tracked_junk="$(git ls-files | grep -E '(DerivedData/|\.build/|xcuserdata/|\.DS_Store$)' || true)"
if [[ -n "$tracked_junk" ]]; then
  echo "❌ Tracked build artifacts / junk files:"
  printf '   %s\n' "$tracked_junk"
  findings=$((findings + 1))
else
  echo "✅ No tracked build artifacts"
fi

# --- Website files still present (a deletion would take kainor.com down) --------
if [[ -f docs/index.html && -f docs/CNAME ]]; then
  echo "✅ Website files intact (docs/index.html, docs/CNAME)"
else
  echo "❌ Website files MISSING from docs/ — pushing would break kainor.com"
  findings=$((findings + 1))
fi

hr
if [[ "$findings" -gt 0 ]]; then
  echo "❌ $findings category/categories need review before pushing."
  echo "   If a hit is genuinely fine (e.g. an example value), leave it and note why."
  echo "   If it is real data: remove it, and if it is already COMMITTED, tell me —"
  echo "   deleting the line is not enough once it is in history."
  exit 1
fi

echo "✅ Clean. Safe to push."
exit 0
