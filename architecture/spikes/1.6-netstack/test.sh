#!/bin/bash
# mknod needs real container root, so it happens before fixture.sh re-execs into the broker userns.
[ -c /dev/net/tun ] || { mkdir -p /dev/net && mknod /dev/net/tun c 10 200 2>/dev/null; }
. /spike/fixture.sh
# Gate for design Decision 5: gVisor netstack behind a TAP in the sandbox netns, vs pasta.
# Local fixtures replace the internet: guest 203.0.113.10 (TEST-NET-3) is remapped by netd to 127.0.0.1.
FIX=203.0.113.10
MIN_MBIT=500      # median iperf3 throughput through netstack
MAX_ADDED_US=1000 # median added p50 round trip vs direct loopback
RUNS=5

# --- build (also the "gVisor builds under Go 1.27" criterion) --------------------------------
cp -r /spike/case/probe "$W/probe-src" && cp /spike/case/pingpong.py /spike/case/fixtures.py "$W/out/"
( cd "$W/probe-src" && go build -o "$W/netd" . ) 2>"$W/build.err" \
  && pass "gvisor-builds-with-$(go env GOVERSION)" || { fail "gvisor-builds" "$(head -5 "$W/build.err")"; finish; }

# --- TUN availability -------------------------------------------------------------------------
if ! python3 -c 'import os; os.close(os.open("/dev/net/tun", os.O_RDWR))' 2>/dev/null; then
  skip "tun-available" "/dev/net/tun unusable here (run.sh passes --device-cgroup-rule; host needs the tun driver, see README)"
  skip "netstack-matrix-and-benchmarks" "requires TUN"
  finish
fi
pass "tun-available"

# --- fixtures ---------------------------------------------------------------------------------
python3 "$W/out/fixtures.py" & FIXP=$!
iperf3 -s -B 127.0.0.1 >/dev/null 2>&1 & IPERF=$!
mkdir -p "$W/git" && git init -q --bare -b main "$W/git/repo.git" \
  && git clone -q "$W/git/repo.git" "$W/wc" 2>/dev/null && ( cd "$W/wc" && echo hi > f && git add f \
  && git -c user.name=s -c user.email=s@s commit -qm init && git push -q origin HEAD:refs/heads/main )
git daemon --reuseaddr --base-path="$W/git" --export-all --listen=127.0.0.1 --port=9418 >/dev/null 2>&1 & GITP=$!
echo "nameserver 10.0.2.2" > "$W/resolv.conf"
sleep 0.5  # fixture servers binding; no readiness signal available for all four

# --- sandbox with its own netns; guest runs jobs on request ------------------------------------
SBX_EXTRA="--unshare-net --info-fd 3 --dir /etc --ro-bind $W/resolv.conf /etc/resolv.conf \
  --ro-bind /etc/nsswitch.conf /etc/nsswitch.conf --ro-bind /etc/passwd /etc/passwd --ro-bind /etc/group /etc/group \
  --tmpfs /tmp --setenv HOME /tmp" sandbox_start '
  touch /out/ready
  while [ ! -e /out/quit ]; do
    if [ -e /out/job.go ]; then
      rm /out/job.go; bash /out/job.sh > /out/job.out 2>&1; echo $? > /out/job.rc; touch /out/job.done
    fi
    sleep 0.05
  done'
wait_file "$W/out/ready" || fail "sandbox-started"
PID=$(sandbox_child_pid); NS=/proc/$PID/ns/net
# guest <job-script-text>: runs in the sandbox, leaves stdout in $W/out/job.out and exit code in job.rc
guest() { rm -f "$W/out/job.done"; printf '%s\n' "$1" > "$W/out/job.sh"; touch "$W/out/job.go"; wait_file "$W/out/job.done" "${2:-30}"; }

stop_net() { [ -n "$NETD" ] && kill "$NETD" 2>/dev/null; wait "$NETD" 2>/dev/null; NETD=; }
cleanup() { stop_net; kill $FIXP $IPERF $GITP 2>/dev/null; touch "$W/out/quit"; }
trap cleanup EXIT

# --- netstack up -------------------------------------------------------------------------------
"$W/netd" -ns "$NS" -map "$FIX=127.0.0.1" -dns 127.0.0.1:5353 > "$W/netd.out" 2>"$W/netd.err" & NETD=$!
poll "netd-tap-and-stack-up" 10 grep -q ready "$W/netd.out" || cat "$W/netd.err"
nsenter --net="$NS" sh -c 'ip addr add 10.0.2.15/24 dev tap0 && ip link set tap0 up && ip route add default via 10.0.2.2' \
  && pass "guest-interface-configured" || fail "guest-interface-configured"

# --- correctness matrix -------------------------------------------------------------------------
guest "getent hosts fixture.test"; grep -q "$FIX" "$W/out/job.out" && pass "dns-lookup-via-gateway" || fail "dns-lookup-via-gateway" "$(cat "$W/out/job.out")"
guest "curl -s -m 10 http://$FIX:9100/small | wc -c"; [ "$(cat "$W/out/job.out")" = 50000 ] && pass "tcp-http-download" || fail "tcp-http-download" "$(cat "$W/out/job.out")"
guest "curl -sN -m 10 -o /dev/null -w '%{time_starttransfer} %{time_total}' http://$FIX:9100/stream"
read -r first total < "$W/out/job.out"
python3 -c "import sys; sys.exit(not (float('$first') < 0.5 and float('$total') >= 0.8))" && pass "streaming-not-buffered" || fail "streaming-not-buffered" "first=$first total=$total"
guest "git clone -q git://$FIX:9418/repo.git /tmp/c && cat /tmp/c/f"; grep -q hi "$W/out/job.out" && pass "git-clone" || fail "git-clone" "$(cat "$W/out/job.out")"
# npm install is many small parallel GETs; no node/registry in this image, so this stands in for it (see README).
guest "seq 200 | xargs -P 50 -I{} curl -s -o /dev/null -w '%{http_code}\n' http://$FIX:9100/small | sort | uniq -c" 60
[ "$(tr -s ' ' < "$W/out/job.out" | tr -d '\n')" = " 200 200" ] && pass "parallel-small-requests-200x" || fail "parallel-small-requests-200x" "$(cat "$W/out/job.out")"
start=$(date +%s.%N); guest "curl -s -m 8 http://$FIX:9/; echo \$?"; el=$(python3 -c "print($(date +%s.%N)-$start)")
[ "$(tail -1 "$W/out/job.out")" = 7 ] && python3 -c "import sys; sys.exit(not $el < 2)" && pass "closed-port-is-connection-refused" || fail "closed-port-is-connection-refused" "rc=$(tail -1 "$W/out/job.out") after ${el}s"
guest "timeout 3 bash -c 'echo x > /dev/udp/$FIX/9999'; echo \$?"
kill -0 "$NETD" 2>/dev/null && pass "non-dns-udp-dropped-netd-alive" || fail "non-dns-udp-dropped-netd-alive"

# --- performance ---------------------------------------------------------------------------------
median() { python3 -c "import sys,statistics; print(int(statistics.median(float(x) for x in sys.stdin.read().split())))"; }
bench() {  # bench <target-ip> <label>
  local ip=$1 lbl=$2 th="" i
  for i in $(seq $RUNS); do guest "iperf3 -c $ip -t 3 -J" 30; th="$th $(python3 -c "import json; print(json.load(open('$W/out/job.out'))['end']['sum_received']['bits_per_second'])" 2>/dev/null)"; done
  guest "python3 /out/pingpong.py $ip 9200 2000" 60
  echo "$(echo "$th" | median) $(cat "$W/out/job.out")"
}
direct_us=$(python3 "$W/out/pingpong.py" 127.0.0.1 9200 2000)
read -r bps rtt < <(bench $FIX netstack)
mbit=$((bps / 1000000)); added=$((rtt - direct_us))
echo "METRIC netstack throughput_mbit_median=$mbit rtt_p50_us=$rtt direct_loopback_p50_us=$direct_us added_p50_us=$added runs=$RUNS"
[ "$mbit" -ge $MIN_MBIT ] && pass "netstack-throughput>=${MIN_MBIT}Mbit" || fail "netstack-throughput>=${MIN_MBIT}Mbit" "$mbit Mbit"
[ "$added" -lt $MAX_ADDED_US ] && pass "netstack-added-p50<${MAX_ADDED_US}us" || fail "netstack-added-p50<${MAX_ADDED_US}us" "${added}us"

# --- pasta comparison (informational: the fallback's numbers on the same machine) -------------------
stop_net
pasta --config-net -a 10.0.2.15 -n 24 -g 10.0.2.2 --map-host-loopback 10.0.2.2 -t none -u none -T none -U none --netns "$NS" >"$W/pasta.out" 2>&1 \
  && { read -r pbps prtt < <(bench 10.0.2.2 pasta)
       echo "METRIC pasta throughput_mbit_median=$((pbps / 1000000)) rtt_p50_us=$prtt added_p50_us=$((prtt - direct_us))"; } \
  || skip "pasta-comparison" "pasta did not attach: $(head -c 200 "$W/pasta.out")"
finish
