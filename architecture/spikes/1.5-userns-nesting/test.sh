#!/bin/bash
. /spike/fixture.sh
# bwrap --disable-userns blocks nested user namespaces even though the sandbox itself is already
# nested inside the broker's userns.
probe='unshare -U true 2>/dev/null && touch /out/$T.nested-ok; touch /out/$T.done'

T=ctl SBX_EXTRA="" sandbox_start "T=ctl; $probe"; sandbox_wait
[ -e "$W/out/ctl.nested-ok" ] && pass "control-nested-userns-allowed-by-default" || fail "control-nested-userns-allowed-by-default" "probe cannot detect a block"

T=dis SBX_EXTRA="--disable-userns" sandbox_start "T=dis; $probe"; sandbox_wait
[ -e "$W/out/dis.done" ] && pass "disable-userns-sandbox-starts-under-broker" || fail "disable-userns-sandbox-starts-under-broker" "bwrap refused (see stderr above)"
[ -e "$W/out/dis.done" ] && [ ! -e "$W/out/dis.nested-ok" ] && pass "nested-userns-blocked" || fail "nested-userns-blocked" "unshare -U succeeded"
finish
