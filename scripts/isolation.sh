#!/usr/bin/env bash
# The isolation regression gate (task 8.2). Runs the tests that guard the sandbox's core guarantees (no
# capabilities, no mounts, no host paths, no unapproved network, no control-socket access, no nested user
# namespaces) and FAILS if any of them was skipped: a gate that skips on a host without user namespaces would
# pass while checking nothing.
set -uo pipefail
cd "$(dirname "$0")/.."

PATTERN='TestIsolationRegressionSuite|TestBaselineIsolation|TestNestedUsernsOptIn|TestSandboxCannotReach|TestSandboxCannotChangeItsNetwork|TestHotMountRefusals|TestPortGrantDoesNotReachNonLoopbackHostServices|TestStartVerificationAbortsOnMisconfiguration|TestCanaryNestedUsernsBlocked'
EXPECTED=9

log=$(mktemp)
trap 'rm -f "$log"' EXIT
go test -tags security -count=1 -v -run "$PATTERN" ./... 2>&1 | tee "$log"
status=${PIPESTATUS[0]}
passed=$(grep -c -- '^--- PASS' "$log")
skipped=$(grep -c -- '^--- SKIP' "$log")
echo "isolation gate: $passed passed, $skipped skipped (expected at least $EXPECTED passed, none skipped)"
if [ "$status" -ne 0 ]; then echo "isolation gate: FAILED"; exit 1; fi
if [ "$skipped" -ne 0 ]; then echo "isolation gate: tests were skipped; this host cannot run the gate"; exit 1; fi
if [ "$passed" -lt "$EXPECTED" ]; then echo "isolation gate: fewer tests ran than expected; was one renamed?"; exit 1; fi
