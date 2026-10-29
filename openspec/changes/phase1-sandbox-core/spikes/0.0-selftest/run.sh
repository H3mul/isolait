#!/bin/sh
. "$(dirname "$0")/../_common/run.sh"
spike_run ${SELFTEST_FAIL:+-e SELFTEST_FAIL=1}
