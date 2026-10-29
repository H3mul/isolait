#!/bin/bash
. /spike/fixture.sh
# open_tree(CLONE) + mount_setattr(RDONLY|NOSUID|NODEV) + move_mount yields a mount that is never
# writable from the first instant it is visible, and is non-recursive.
go build -o "$W/probe" /spike/case/probe.go || { fail "probe-builds"; finish; }
mkdir "$W/src/rw/sub" && mount -t tmpfs tmpfs "$W/src/rw/sub" && echo hidden > "$W/src/rw/sub/h"   # a host submount

# run <name> <attach cmd...>: sandbox hammers writes while the mount appears; results in $W/out/<name>.*
run() {
  local n=$1; shift
  mkdir "$W/stage/$n"
  sandbox_start "$SBX_LIB"'
    n='"$n"'; i=0
    while [ ! -e /out/$n.stop ]; do
      if [ -e /workspaces/$n/f ]; then
        touch /out/$n.seen
        touch /workspaces/$n/w 2>/dev/null && touch /out/$n.rwwindow
        i=$((i+1)); [ $i -gt 200 ] && touch /out/$n.stop
      fi
    done
    grep " /workspaces/$n " /proc/self/mountinfo > /out/$n.mi
    ls -A /workspaces/$n/sub > /out/$n.sub 2>&1
    touch /out/$n.done
  '
  sleep 0.3   # let the writer spin on the not-yet-mounted dir; not a sync point for correctness
  "$@"
  wait_file "$W/out/$n.done" 20 || fail "$n-sandbox-finished"
  sandbox_wait
}

run clone "$W/probe" "$W/src/rw" "$W/stage/clone" ro
[ -e "$W/out/clone.seen" ] && pass "clone-visible" || fail "clone-visible"
[ ! -e "$W/out/clone.rwwindow" ] && [ ! -e "$W/src/rw/w" ] && pass "clone-never-writable" || fail "clone-never-writable" "a write succeeded"
grep -q ' ro,nosuid,nodev' "$W/out/clone.mi" && pass "clone-flags-ro-nosuid-nodev" || fail "clone-flags-ro-nosuid-nodev" "$(cat "$W/out/clone.mi")"
[ -z "$(cat "$W/out/clone.sub")" ] && pass "clone-non-recursive-submount-hidden" || fail "clone-non-recursive-submount-hidden" "$(cat "$W/out/clone.sub")"

# Control: bind then remount,ro. The flag change is not propagated, so the sandbox sees a writable mount.
# Expected to show a write window; if it does not, the clone result above proves less than it seems.
cp -r "$W/src/ro" "$W/src/ctl"
run ctl sh -c "mount --bind $W/src/ctl $W/stage/ctl && mount -o remount,ro,bind $W/stage/ctl"
[ -e "$W/out/ctl.rwwindow" ] && pass "control-bind-remount-has-write-window" || skip "control-bind-remount-has-write-window" "no window observed; kernel propagated the remount or the race was missed"
finish
