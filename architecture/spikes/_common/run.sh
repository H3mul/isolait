#!/bin/sh
# Usage (from a spike's run.sh): . ../_common/run.sh; spike_run [extra docker flags...]
# Builds the shared image and runs the spike's test.sh inside it. Exit code = test.sh's.
spike_run() {
  d=$(cd "$(dirname "$0")" && pwd); c=$d/../_common
  docker build -q -t isolait-spike "$c" >/dev/null || exit 2
  docker run --rm \
    --security-opt seccomp=unconfined --security-opt apparmor=unconfined \
    --security-opt systempaths=unconfined \
    -v "$d:/spike/case:ro" "$@" isolait-spike bash /spike/case/test.sh
}
