# 1.2 Propagated ro mounts are locked; unmount propagates

**Question:** can sandbox code remount a propagated read-only mount rw (`MNT_LOCKED`), and does a
broker `umount` remove it from the sandbox?

**Approach:** same fixture as 1.1. The sandbox keeps `--cap-add ALL` so a denial comes from the
kernel, not missing caps (criterion `control-sandbox-has-caps`). The ro source is a ro bind in the broker;
the sandbox tries `mount -o remount,rw,bind` and a write, then waits for the file to vanish after
the broker's `umount`.

**Pass:** `remount-rw-denied`, `write-to-ro-denied`, `unmount-propagates` (+ control).

**Caveat:** the ro flag here comes from a ro source mount in the broker. Whether a flag set
*after* `bind` propagates is why Decision 2 uses `mount_setattr` before `move_mount` (spike 1.4).

**Run:** `./run.sh`.

## Result (2026-10-29, WSL2 kernel 6.18, bwrap 0.13.1)
All PASS. **Verdict: GO.**
