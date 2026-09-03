#!/usr/bin/env bash
# Refuse to publish anything that should not leave the private workspace.
#
# PLAN.md reached this directory once through a careless rsync. It was untracked and
# caught before it went anywhere, but the check is cheaper than the vigilance.
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
cd "$here"
status=0

for f in PLAN.md .env config.yaml; do
  if git ls-files --error-unmatch "$f" >/dev/null 2>&1; then
    echo "FAIL tracked file that must not be published: $f"; status=1
  fi
done

# Identifiers belonging to the private workspace rather than to this repository.
# This script is excluded because it necessarily contains the patterns it looks for,
# which is how its first run failed.
mine=":(exclude)tools/check-publishable.sh"
private=$(git grep -n -I -i -E 'addis market|nexel|trojans\.dsu|@gmail\.com' -- . "$mine" || true)
if [ -n "$private" ]; then
  echo "FAIL private identifiers in tracked files:"; echo "$private"; status=1
fi

leaks=$(git grep -n -I -E '(api[_-]?key|secret)[[:space:]]*[:=][[:space:]]*["'"'"'][A-Za-z0-9_-]{16,}' -- . "$mine" || true)
if [ -n "$leaks" ]; then
  echo "FAIL possible credential in tracked files:"; echo "$leaks"; status=1
fi

[ "$status" -eq 0 ] && echo "ok  nothing unpublishable in tracked files"
exit "$status"
