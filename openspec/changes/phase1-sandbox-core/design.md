# Design

## Context

See proposal.md for motivation. Phase 1 starts from an empty repo. Constraints: rootless, Go, bubblewrap, no hypervisor. The original proposal's hot-plug mechanism (`nsenter` into the running sandbox) was evaluated and replaced; see Decision 1.

## Goals / Non-Goals

**Goals:**
- Instant rootless sandbox; hot-add/remove of directories and localhost ports with no agent restart.
- The sandbox never holds mount capability and never runs a privileged helper.
- All mount/unmount/port operations originate from a trusted broker outside the sandbox.

**Non-Goals:**
- `git-rw` mode, SNI/DNS/IP-pinning filtering, USB devices, unix socket mounting (Phase 2).
- Windows/WSL2-specific handling beyond "works on WSL2's Linux kernel" (Phase 4).
- Reconcile-on-change or FUSE policy filesystems (deferred beyond Phase 2).

## Decisions

### 1. Broker mount namespace with propagation (not nsenter)

```
 host (init userns/mntns)
   |
   +-- isolait broker  (re-exec'd with CLONE_NEWUSER|CLONE_NEWNS, identity uid map)
         |  full caps *inside its own userns*, sees host fs
         |  stage/ = tmpfs, shared propagation (the only thing exposed)
         |
         +-- bwrap --unshare-user --unshare-pid --unshare-net ...
               / is rslave to broker; /workspaces = bind of stage/ (stays slave)
```

Mounts made by the broker into `stage/` propagate to the sandbox; unmounts propagate likewise. The sandbox is never entered and never gains capability.

**Alternatives:**
- *nsenter + open_tree/move_mount*: source path isn't visible after `setns`, needs fd passing, puts a `CAP_SYS_ADMIN` actor inside the sandbox userns, and Go cannot `setns(CLONE_NEWUSER)` from a multithreaded runtime.
- *In-sandbox helper receiving fds*: a persistent privileged process next to the agent. Rejected.
- *FUSE view of `/workspaces`*: no mounts needed but inotify and latency suffer. Kept as a fallback only.

The broker is the same binary re-executed with `SysProcAttr.Cloneflags`, so it is born inside its namespaces and needs no `setns`.

### 2. Mount primitive: fd-based clone with atomic flags

For each add: open source with `O_PATH|O_DIRECTORY|O_NOFOLLOW`, validate by fd, `open_tree(fd, "", OPEN_TREE_CLONE|AT_EMPTY_PATH)` (not recursive), `mount_setattr` to set `NOSUID|NODEV` (plus `RDONLY` for `--ro`) on the detached tree, then `move_mount` into `stage/<name>`. Flags are set before the mount becomes visible, so a `ro` mount is never observable as writable. Plain `mount --bind` + `remount,ro` is rejected because flag changes do not propagate.

Remove: `umount` in the broker; before unmounting, scan `/proc/<pid>/{cwd,fd}` of sandbox processes to report busy users. `--force` uses lazy detach.

### 3. Deny list and naming

Reject protected paths and their ancestors by comparing resolved identities (dev+inode) rather than strings. Names default to basename; `--as` overrides; collisions are errors, never silent suffixes.

### 4. Ports: broker-held listeners in the sandbox netns

The sandbox runs in its own netns (`--unshare-net`, loopback up). To open port P, the broker locks an OS thread, `setns`es into the sandbox netns (allowed because the broker's userns is the parent and owner of that netns), creates a listening socket, and returns to its own netns. Accepted connections are dialed to host `127.0.0.1:P` in the broker's (host) netns and copied both ways. UDP uses per-flow association with idle timeout. Close = close listener and active flows.

**Alternatives:** `pasta`/`slirp4netns` (extra external dependency, more than loopback needed); veth + iptables (needs `CAP_NET_ADMIN` on the host netns, breaking rootless). Tier B (gVisor netstack) revisits this in Phase 3.

### 5. Session identity

A session has a random stable id; the name is derived from the starting directory basename and disambiguated on collision. State lives under a per-user runtime dir; the broker exposes a unix-socket control API that the CLI uses. The broker is one process per session.

### 6. Modes

Phase 1 modes are `rw` (default) and `ro`. The mount-plan code is written so a mode other than a single flag set can later be added (Phase 2 `git-rw`), without introducing an abstraction now.

## Risks / Trade-offs

- **Propagation into a child-userns mount namespace may behave differently than expected** (including `MNT_LOCKED` on propagated mounts, and bwrap making `/workspaces` private) → first tasks are spikes; fallback is Approach A (nsenter + open_tree/move_mount) behind the same internal interface.
- **Unprivileged userns disabled** (Ubuntu 24.04 AppArmor policy) → preflight check with actionable error.
- **Busy unmount** → report blockers; `--force` detaches lazily, which can leave processes with stale handles.
- **Mounted directories can contain unix sockets**, which remain connectable regardless of mounts → documented residual risk; Phase 2 socket policy.
- **Writable mounts can plant host-executed files** (git hooks, scripts) → accepted for `rw`; Phase 2 `git-rw` addresses it; `--ro` available now.
- **Host services see port-forwarded connections as local broker connections**, not as the agent → documented; no per-agent attribution.

## Migration Plan

Greenfield; nothing to migrate. Rollback is removing the binary and its runtime dir.

## Open Questions

- Exact UDP flow idle timeout and max flows (safe to tune later).
- Whether `isolait mount` should accept multiple directories in one call (additive).
