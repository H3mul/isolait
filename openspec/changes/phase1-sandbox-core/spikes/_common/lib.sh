# Sourced by test.sh. One result line per criterion; exit 1 on any FAIL, else 0.
# Usage: pass "name" | fail "name" "why" | skip "name" "why" ; end with: finish
_fails=0
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1${2:+: $2}"; _fails=$((_fails + 1)); }
skip() { echo "SKIP $1${2:+: $2}"; }
# check "name" cmd...  -> PASS if cmd exits 0
check() { local n=$1; shift; if "$@" >/dev/null 2>&1; then pass "$n"; else fail "$n" "exit $?"; fi; }
# poll "name" seconds cmd... -> PASS once cmd succeeds (no fixed sleeps)
poll() { local n=$1 t=$(( $2 * 10 )); shift 2; while [ $t -gt 0 ]; do "$@" >/dev/null 2>&1 && { pass "$n"; return; }; t=$((t-1)); sleep 0.1; done; fail "$n" "timeout"; }
finish() { exit $(( _fails > 0 )); }
