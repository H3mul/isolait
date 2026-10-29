#!/bin/bash
# Proves the harness: unprivileged userns works under the container flags, and the helpers map to exit codes.
. /spike/lib.sh
check "userns-unshare" unshare -Urm true
check "bwrap-runs" bwrap --unshare-user --ro-bind / / true
skip "demo-skip" "SKIP is reported, not counted as PASS"
[ -n "$SELFTEST_FAIL" ] && fail "demo-fail" "forced by SELFTEST_FAIL"
finish
