#!/bin/bash
. /spike/fixture.sh
# A mount made by the broker into stage/ after the sandbox started appears in the sandbox.
sandbox_start "$SBX_LIB"'
  touch /out/ready
  swait /workspaces/a/f && cat /workspaces/a/f > /out/seen
'
wait_file "$W/out/ready" || fail "sandbox-started" "no ready marker"
mkdir "$W/stage/a" && mount --bind "$W/src/rw" "$W/stage/a"
sandbox_wait
[ "$(cat "$W/out/seen" 2>/dev/null)" = data ] && pass "hot-mount-visible-in-sandbox" || fail "hot-mount-visible-in-sandbox" "file not seen"
finish
