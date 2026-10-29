#!/bin/bash
. /spike/fixture.sh
# netd model for port grants: a locked thread setns'es into the sandbox netns, listens on its
# loopback, and forwards accepted connections to host 127.0.0.1 (dialed from the original netns).
go build -o "$W/probe" /spike/case/probe.go || { fail "probe-builds"; finish; }
mkdir "$W/www" && echo hello-from-host > "$W/www/hello"
python3 -m http.server 9100 --bind 127.0.0.1 --directory "$W/www" >/dev/null 2>&1 &
HTTP=$!
# fetch <port>: HTTP GET over bash /dev/tcp; prints the body, fails if the connect fails
FETCH='fetch() { exec 4<>/dev/tcp/127.0.0.1/$1 || return 1; printf "GET /hello HTTP/1.0\r\n\r\n" >&4; tail -n1 <&4; exec 4>&-; }'

SBX_EXTRA="--unshare-net --info-fd 3" sandbox_start "$SBX_LIB"$'\n'"$FETCH"$'\n''
  touch /out/ready
  swait /out/listen-up || exit 1
  fetch 8080 > /out/via-grant 2>/dev/null
  fetch 9100 > /out/direct 2>/dev/null && touch /out/direct-ok     # host loopback must be unreachable
  touch /out/step1
  swait /out/closed || exit 1
  fetch 8080 > /out/after-close 2>/dev/null && touch /out/after-close-ok
  touch /out/done
'
wait_file "$W/out/ready" || fail "sandbox-started"
pid=$(sandbox_child_pid) || fail "child-pid" "no --info-fd output"

"$W/probe" "/proc/$pid/ns/net" 8080 127.0.0.1:9100 > "$W/probe.out" 2>"$W/probe.err" &
PROBE=$!
wait_file "$W/probe.out" 5; poll "listener-created-in-sandbox-netns" 5 grep -q listening "$W/probe.out" || cat "$W/probe.err"

# The listener lives in the sandbox netns only: the host side must not see port 8080.
(exec 5<>/dev/tcp/127.0.0.1/8080) 2>/dev/null && fail "listener-not-on-host-loopback" "host connect to 8080 succeeded" || pass "listener-not-on-host-loopback"

touch "$W/out/listen-up"
wait_file "$W/out/step1" 10 || fail "step1"
[ "$(cat "$W/out/via-grant" 2>/dev/null)" = hello-from-host ] && pass "sandbox-reaches-host-service-via-grant" || fail "sandbox-reaches-host-service-via-grant" "got: $(cat "$W/out/via-grant" 2>/dev/null)"
[ -e "$W/out/step1" ] && [ ! -e "$W/out/direct-ok" ] && pass "host-loopback-unreachable-without-grant" || fail "host-loopback-unreachable-without-grant"

kill -USR1 "$PROBE"; poll "grant-closed" 5 grep -q closed "$W/probe.out"
touch "$W/out/closed"
wait_file "$W/out/done" 10 || fail "done"
[ -e "$W/out/done" ] && [ ! -e "$W/out/after-close-ok" ] && pass "connect-refused-after-close" || fail "connect-refused-after-close"
kill "$PROBE" "$HTTP" 2>/dev/null
sandbox_wait
finish
