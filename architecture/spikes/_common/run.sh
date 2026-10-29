#!/bin/sh
# Usage (from a spike's run.sh): . ../_common/run.sh; spike_run [extra docker flags...]
# Runs the spike's test.sh in the prebuilt image (build it with _common/build.sh). Exit code = test.sh's.
spike_run() {
  d=$(cd "$(dirname "$0")" && pwd)
  docker image inspect isolait-spike >/dev/null 2>&1 || {
    echo "image isolait-spike missing: run architecture/spikes/_common/build.sh first" >&2; exit 2; }
  docker run --rm \
    --security-opt seccomp=unconfined --security-opt apparmor=unconfined \
    --security-opt systempaths=unconfined \
    -v "$d:/spike/case:ro" "$@" isolait-spike bash /spike/case/test.sh
}
