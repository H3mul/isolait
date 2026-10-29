#!/bin/bash
. /spike/fixture.sh
# /workspaces in the sandbox is a slave of the broker's stage/ (receives, never sends).
sandbox_start "$SBX_LIB"'
  grep " /workspaces " /proc/self/mountinfo > /out/mi
  mkdir /workspaces/z && mount -t tmpfs tmpfs /workspaces/z && touch /workspaces/z/leak
  touch /out/done
'
wait_file "$W/out/done" || fail "sandbox-ran" "sandbox script did not finish"
sandbox_wait
grep -q ' master:' "$W/out/mi" && ! grep -q ' shared:' "$W/out/mi" && pass "workspaces-is-slave" || fail "workspaces-is-slave" "$(cat "$W/out/mi")"
[ ! -e "$W/stage/z/leak" ] && pass "sandbox-mounts-do-not-propagate-back" || fail "sandbox-mounts-do-not-propagate-back" "leaked to broker"
finish
