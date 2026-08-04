#!/bin/sh
set -eu

range=${1:-}
if [ -z "$range" ]; then
  echo "usage: scripts/check-dco.sh <git-range>" >&2
  exit 2
fi

failed=0
for commit in $(git rev-list "$range"); do
  if ! git show -s --format=%B "$commit" | grep -Eqi '^Signed-off-by: .+ <[^>]+>$'; then
    echo "missing DCO sign-off: $commit" >&2
    failed=1
  fi
done

exit "$failed"
