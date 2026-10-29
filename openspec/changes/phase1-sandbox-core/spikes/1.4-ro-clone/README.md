# 1.4 Atomic ro clone: open_tree + mount_setattr + move_mount

**Question:** does the Decision 2 primitive give a mount that is never writable from its first visible
instant, with `nosuid,nodev`, and non-recursive (host submounts hidden)?

**Approach:** `probe.go` (stdlib raw syscalls, no modules) does `open_tree(OPEN_TREE_CLONE)` on an `O_PATH` fd,
`mount_setattr(RDONLY|NOSUID|NODEV)` on the detached tree, `move_mount` into `stage/clone`. A sandbox
loop hammers `touch` on the path the moment `f` appears; any success is a write window. The source has a
tmpfs submount to prove non-recursion.

**Control:** `mount --bind` then `remount,ro` into `stage/ctl`. If the sandbox can write there, the
test is able to see a window, which makes the clone result meaningful.

**Pass:** `clone-visible`, `clone-never-writable`, `clone-flags-ro-nosuid-nodev`,
`clone-non-recursive-submount-hidden`; control `control-bind-remount-has-write-window` (SKIP if the race is missed).

**Run:** `./run.sh`.

## Result (2026-10-29, WSL2 kernel 6.18, Go 1.27.3)
All PASS including the control: the bind+remount path does expose a writable mount in the sandbox, the
clone path does not. **Verdict: GO** for Decision 2.
