#!/bin/sh
# Runs every spike's run.sh, prints a summary, exits non-zero if any spike failed.
cd "$(dirname "$0")"; rc=0
for r in [0-9]*/run.sh; do
  echo "=== $(dirname "$r")"; sh "$r" || { echo ">>> FAILED: $r"; rc=1; }
done
exit $rc
