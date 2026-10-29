# Sourced first by broker-mount spikes (1.1, 1.2, 1.3, 1.9). Re-execs the caller inside the "broker":
# a fresh user+mount namespace, standing in for the isolait daemon. Then provides:
#   $W/stage  tmpfs, shared; the only thing bound into the sandbox (at /workspaces)
#   $W/out    scratch dir bound rw at /out in the sandbox, for sandbox -> broker results
#   $W/src/{rw,ro}  fixture sources each holding a file `f`
#   sandbox_start 'script'  run script in bwrap in the background (pid in $SBX); sandbox_wait
#   wait_file path [secs]   poll until path exists
. /spike/lib.sh
[ -n "$IN_BROKER" ] || exec unshare -Urm env IN_BROKER=1 bash "$0" "$@"

W=$(mktemp -d)
mkdir -p "$W/stage" "$W/out" "$W/src/rw" "$W/src/ro"
echo data > "$W/src/rw/f"; echo data > "$W/src/ro/f"
mount -t tmpfs tmpfs "$W/stage" && mount --make-shared "$W/stage"

# Argv proven in spike 1.3. --cap-add ALL keeps caps in the sandbox userns so that denials seen in the
# spikes come from the kernel (MNT_LOCKED, slave propagation), not from missing capabilities.
sandbox_start() {
  bwrap --unshare-user --unshare-pid --die-with-parent \
    --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
    --dev /dev --proc /proc --bind "$W/stage" /workspaces --bind "$W/out" /out \
    --cap-add ALL $SBX_EXTRA bash -c "$1" 3>"$W/info" &   # SBX_EXTRA: extra bwrap flags (word-split on purpose); fd 3 collects --info-fd JSON
  SBX=$!
}
# sandbox_child_pid: pid of the sandbox's PID 1 as seen from the broker (needs --info-fd 3 in SBX_EXTRA)
sandbox_child_pid() {
  local t=50 p
  while [ $t -gt 0 ]; do
    p=$(sed -n 's/.*"child-pid": *\([0-9]*\).*/\1/p' "$W/info" 2>/dev/null)
    [ -n "$p" ] && { echo "$p"; return 0; }
    t=$((t-1)); sleep 0.1
  done
  return 1
}
sandbox_wait() { wait "$SBX"; }
wait_file() { local t=$(( ${2:-5} * 10 )); while [ $t -gt 0 ]; do [ -e "$1" ] && return 0; t=$((t-1)); sleep 0.1; done; return 1; }
# In-sandbox helper text, prepend to sandbox scripts: swait <path> waits up to 5s for it to exist; sgone for it to vanish
SBX_LIB='swait() { for i in $(seq 50); do [ -e "$1" ] && return 0; sleep 0.1; done; return 1; }
sgone() { for i in $(seq 50); do [ -e "$1" ] || return 0; sleep 0.1; done; return 1; }'
