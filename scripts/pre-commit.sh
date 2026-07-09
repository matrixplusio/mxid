#!/usr/bin/env bash
# Pre-commit gate. Fast checks only — pushes the heavy stuff (web build, smoke)
# to CI. Designed to stay under ~10 s on warm caches.
#
# Skip with: SKIP_VERIFY=1 git commit ...  (use sparingly; CI still runs full verify).
set -euo pipefail

if [[ "${SKIP_VERIFY:-0}" == "1" ]]; then
  echo "SKIP_VERIFY=1 set, skipping pre-commit verify"
  exit 0
fi

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

# Only run Go gates when Go files / go.mod actually changed.
staged="$(git diff --cached --name-only --diff-filter=ACM)"
if echo "$staged" | grep -qE '\.go$|^go\.(mod|sum)$'; then
  make verify-mod verify-vet verify-build verify-gormtags
fi

# verify-exports is dirt cheap; run if any web/ file changed.
if echo "$staged" | grep -qE '^web/'; then
  make verify-exports
fi

echo "✓ pre-commit OK"
