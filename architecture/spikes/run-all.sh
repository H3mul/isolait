#!/bin/sh
# Builds the image once, runs every spike's run.sh, exits non-zero if the build or any spike failed.
cd "$(dirname "$0")" || exit 2
sh _common/build.sh || exit 2
rc=0
for r in [0-9]*/run.sh; do
  echo "=== $(dirname "$r")"; sh "$r" || { echo ">>> FAILED: $r"; rc=1; }
done
exit $rc
