#!/bin/bash
. /spike/fixture.sh
# An empty ro bind layered over <workspace>/.isolait inside a propagated workspace mount:
# appears empty and unwritable in the sandbox, survives hot-adding a sibling, unmounts with its parent.
mkdir -p "$W/src/rw/.isolait" "$W/empty" "$W/src/other"
echo secret > "$W/src/rw/.isolait/config"; echo x > "$W/src/other/f"
mount --bind "$W/empty" "$W/empty" && mount -o remount,ro,bind "$W/empty"

sandbox_start "$SBX_LIB"'
  touch /out/ready
  swait /workspaces/ws/f || exit 1
  swait /workspaces/ws/.isolait && touch /out/mask-dir-exists
  sgone /workspaces/ws/.isolait/config   # wait for the mask to be layered
  [ -z "$(ls -A /workspaces/ws/.isolait)" ] && touch /out/mask-empty
  touch /workspaces/ws/.isolait/x 2>/dev/null || touch /out/mask-ro
  touch /out/step1
  swait /workspaces/other/f
  [ -z "$(ls -A /workspaces/ws/.isolait)" ] && touch /out/mask-survives-add
  touch /out/step2
  sgone /workspaces/ws/f && touch /out/ws-gone
  [ -z "$(ls -A /workspaces/ws 2>/dev/null)" ] && touch /out/ws-empty-after
  grep -q " /workspaces/ws" /proc/self/mountinfo || touch /out/no-leftover-mounts
  touch /out/step3
'
wait_file "$W/out/ready" || fail "sandbox-started"
mkdir "$W/stage/ws" "$W/stage/other"
mount --bind "$W/src/rw" "$W/stage/ws" && mount --bind "$W/empty" "$W/stage/ws/.isolait"
wait_file "$W/out/step1" 10 || fail "step1"
mount --bind "$W/src/other" "$W/stage/other"
wait_file "$W/out/step2" 10 || fail "step2"
# A plain umount of the parent should be refused while the mask is stacked on it: the product needs umount -R.
umount "$W/stage/ws" 2>/dev/null && plain=ok || plain=busy
umount -R "$W/stage/ws" 2>/dev/null
wait_file "$W/out/step3" 10 || fail "step3"
sandbox_wait

chk() { [ -e "$W/out/$1" ] && pass "$2" || fail "$2"; }
chk mask-dir-exists "mask-dir-present"
chk mask-empty "mask-appears-empty"
chk mask-ro "mask-not-writable"
[ "$(cat "$W/src/rw/.isolait/config")" = secret ] && pass "host-file-untouched" || fail "host-file-untouched"
chk mask-survives-add "mask-survives-hot-add"
chk ws-gone "parent-unmount-propagates"
chk no-leftover-mounts "no-leftover-sandbox-mounts"
echo "INFO plain umount of parent with stacked mask: $plain (product must use recursive unmount if busy)"
finish
