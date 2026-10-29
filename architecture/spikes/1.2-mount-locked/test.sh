#!/bin/bash
. /spike/fixture.sh
# A ro mount propagated into the sandbox cannot be remounted rw there, and unmount propagates.
mount --bind "$W/src/ro" "$W/src/ro" && mount -o remount,ro,bind "$W/src/ro"   # ro in the broker
sandbox_start "$SBX_LIB"'
  touch /out/ready
  swait /workspaces/b/f || exit 1
  grep -q "^CapEff:.*[1-9a-f]" /proc/self/status && touch /out/has-caps          # control: caps are present
  mount -o remount,rw,bind /workspaces/b 2>/dev/null && touch /out/remount-ok
  touch /workspaces/b/x 2>/dev/null && touch /out/write-ok
  touch /out/probed
  sgone /workspaces/b/f && touch /out/gone
'
wait_file "$W/out/ready" || fail "sandbox-started" "no ready marker"
mkdir "$W/stage/b" && mount --bind "$W/src/ro" "$W/stage/b"
wait_file "$W/out/probed" 10 || fail "sandbox-probed" "sandbox never saw the mount"
umount "$W/stage/b"
sandbox_wait
[ -e "$W/out/has-caps" ] && pass "control-sandbox-has-caps" || fail "control-sandbox-has-caps" "denial would prove nothing"
[ ! -e "$W/out/remount-ok" ] && pass "remount-rw-denied" || fail "remount-rw-denied" "sandbox remounted rw"
[ ! -e "$W/out/write-ok" ] && [ ! -e "$W/src/ro/x" ] && pass "write-to-ro-denied" || fail "write-to-ro-denied"
[ -e "$W/out/gone" ] && pass "unmount-propagates" || fail "unmount-propagates" "mount still visible after broker umount"
finish
