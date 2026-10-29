# 1.9 Masking a workspace subdirectory with a layered ro bind

**Question:** can the broker layer an empty read-only bind over `<workspace>/.isolait` inside a propagated
workspace mount so the sandbox sees it empty, with it surviving hot-add and unmounting with its parent?

**Approach:** fixture workspace `ws` holds `.isolait/config`; the broker mounts `ws` into `stage/`, then
`mount --bind <empty ro dir> stage/ws/.isolait`. The sandbox waits for the secret to disappear, checks the
directory is empty and unwritable, then a sibling mount is added, then the broker unmounts `ws`.

**Pass:** `mask-dir-present`, `mask-appears-empty`, `mask-not-writable`, `host-file-untouched`,
`mask-survives-hot-add`, `parent-unmount-propagates`, `no-leftover-sandbox-mounts`.

**Finding for the product (task 3.8/6.4):** a plain `umount` of the parent fails with EBUSY while the mask is
stacked on it (`INFO plain umount ... busy`); remove must unmount the mask first or use `umount -R`.
The spike used `umount -R`, which propagated cleanly.

**Run:** `./run.sh`.

## Result (2026-10-29, WSL2 kernel 6.18)
All PASS. **Verdict: GO** for the layered-mask mechanism in Decision 8 (reused by Phase 2 `git-rw`).
