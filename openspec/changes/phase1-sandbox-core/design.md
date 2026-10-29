# Design

## Context

See proposal.md for motivation. Phase 1 starts from an empty repo. Constraints: rootless, Go, bubblewrap, no hypervisor. Two earlier ideas were evaluated and replaced: `nsenter`-into-sandbox for hot-mounting (Decision 1) and a kernel veth+iptables network tier (not rootless, so removed; all rootless outbound networking is a user-space tap path).

## Goals / Non-Goals

**Goals:**
- Two-tier configuration kept out of the sandbox.
- Instant rootless sandbox that survives terminal close; hot-add/remove of directories and localhost ports with no agent restart.
- The sandbox never holds mount capability and never runs a privileged helper.
- All mount, network and port operations originate outside the sandbox.
- A working outbound path so the agent reaches its API from day one.

**Non-Goals:**
- `git-rw`, SNI/domain filtering, USB, unix sockets, UDP (Phase 2).
- Scrollback, log replay, VT emulation (later; see Decision 4 seam).
- IPv6, ICMP.
- Windows/WSL2-specific polish beyond running on WSL2's Linux kernel (Phase 4).

## Decisions

### 1. Broker mount namespace with propagation (not nsenter)

```
 host (init userns/mntns)
   |
   +-- isolait daemon/broker (re-exec'd with CLONE_NEWUSER|CLONE_NEWNS, identity uid map)
         |  full caps inside its own userns, sees host fs
         |  stage/ = tmpfs, made shared  (the only thing exposed to the sandbox)
         |
         +-- bwrap --unshare-user --unshare-pid --unshare-net --disable-userns ...
               / is rslave to broker; /workspaces = bind of stage/ (stays slave)
```

Mounts made by the broker into `stage/` propagate to the sandbox; unmounts likewise. The sandbox is never entered. Crossing the userns boundary turns the host's shared mounts into slaves in the broker, so broker mounts do not leak to the host.

**Alternatives:** *nsenter + open_tree/move_mount* (source invisible after `setns`, needs fd passing, a `CAP_SYS_ADMIN` actor inside the sandbox userns, and Go cannot `setns(CLONE_NEWUSER)`); *in-sandbox privileged helper* (rejected); *FUSE view of `/workspaces`* (inotify and latency cost; fallback only).

The broker is the same binary re-executed with `SysProcAttr.Cloneflags`, so no `setns` is needed.

### 2. Mount primitive: fd-based clone with atomic flags

Open source with `O_PATH|O_DIRECTORY|O_NOFOLLOW`, validate by fd, `open_tree(fd, "", OPEN_TREE_CLONE|AT_EMPTY_PATH)` (non-recursive), `mount_setattr` to set `NOSUID|NODEV` (plus `RDONLY` for `--ro`) on the detached tree, then `move_mount` into `stage/<name>`. Flags are set before the mount is visible, so `ro` is never observable as writable. `mount --bind` + `remount,ro` is rejected because flag changes do not propagate.

Remove: `umount` in the broker; first scan `/proc/<pid>/{cwd,fd}` of sandbox processes to report blockers. `--force` lazy-detaches.

### 3. Deny list and naming

Protected paths and their ancestors are rejected by comparing resolved identities (dev+inode), not strings. Names default to the basename; `--as` overrides; collisions are errors, never silent suffixes.

### 4. Process model: daemon, init shim, relay

```
 isolait CLI ---- unix socket (0700, runtime dir, not mounted in sandbox) ---- daemon
                                                                              |-- netd
                                                                              |-- PTY master, relay, sanitizer
                                                                              +-- bwrap sandbox
                                                                                    PID 1 = isolait init shim
```

- `isolait start` forks a daemon (setsid, survives terminal close), then attaches as a client. One daemon per session.
- **Init shim:** PID 1 in the sandbox is a subcommand of the same binary with no extra privilege. It spawns the agent and `exec`'d processes on request, each on a PTY from the broker, so the agent can exit and restart without tearing down the sandbox, and extra shells need no `setns`.
- **Relay:** the client puts the terminal in raw mode and copies bytes to and from the daemon, forwards resizes, and sends a redraw request (`SIGWINCH`) on attach. The leader key (default `Ctrl-\`) is intercepted in the client, never sent to the agent, and ignored inside bracketed paste. `leader d` detaches; `leader :` opens a one-line prompt on the bottom row (cursor saved and restored, display redrawn on close) running the same command grammar as the CLI against the current session.
- **Alt-screen:** a minimal mode sniffer tracks `?1049`/`?47` so the prompt and redraw behave for agents that use the alternate screen.
- **Sanitizer:** a small escape-sequence state machine, tolerant of sequences split across reads, drops OSC 52, title and report sequences, DCS/APC/PM and window-manipulation CSI. It is a filter, not an emulator, and narrows but does not eliminate terminal injection.
- **Scrollback seam:** all PTY output flows through one function in the daemon, so a later log tee, VT emulator or replay can be added locally. While attached, the user's terminal scrollback works because the relay does not force the alternate screen.
- **Session lifetime:** a session lives as long as its init shim. When the agent exits the session is idle; attach relaunches the agent in the same sandbox. No idle timeout in Phase 1 (Phase 2 may add an opt-in timeout that requires human confirmation to continue, as an unattended-operation restriction).

**Alternatives:** tmux as host (rejected: external dependency; a tmux server inside the sandbox would let an agent-controlled server drive a host client, e.g. `detach-client -E` runs a command in place of the client); dtach-style relay without sanitizer (rejected: raw escape sequences reach the user's terminal).

### 5. Network: netstack engine in `netd`, TCP only

```
 sandbox netns (owned by bwrap userns)
   tap0 <----- fd ----- netd (subcommand of same binary, seccomp'd, no mount authority)
                           gVisor netstack: TCP forwarder, DNS answerer
                           policy: dial-time check on resolved dest IP
                           dial in host netns --> internet
   lo   <-- listeners created by netd (port grants) --> host 127.0.0.1:P
```

- Startup order: bwrap is started with `--block-fd` and `--info-fd`; the broker learns the child pid, `netd` enters `/proc/<pid>/ns/net` (allowed: broker userns is the owner's parent), creates and configures the tap, then the sandbox is released.
- TCP forwarder: for each guest SYN, `netd` resolves policy, dials upstream, and only then completes the guest handshake, so a refused upstream is a refused guest connect rather than connect-then-reset.
- Policy is checked on the destination actually dialed, after DNS, which defeats DNS-rebinding and avoids check-then-use races. Blocked: loopback, RFC 1918, CGNAT, link-local, multicast, metadata, and the host's own addresses/gateway.
- DNS: UDP and TCP port 53 to the gateway address is answered by `netd` using the host resolver; the guest's `resolv.conf` points at the gateway. Non-DNS UDP, ICMP and IPv6 are dropped (IPv6 disabled in the netns).
- **Port grants:** guest `127.0.0.1` never leaves its netns, so a grant is a listener on the sandbox's loopback, created by a `netd` thread locked to the sandbox netns, whose accepted connections `netd` dials to host `127.0.0.1:P`. Closing a grant closes the listener and its connections. Range size has a configured cap (default 1024).
- `netd` is a separate process so a bug in packet parsing cannot reach the broker's mount authority; it has network access and `setns` but no mount capability, plus seccomp.

**Gating spike:** tap in a netns plus a netstack forwarder, measured against `pasta` with iperf3 on this machine; go if throughput is at least about 500 Mbit/s and added p50 latency is under 1 ms, and the correctness matrix (API streaming, `npm install`, `git clone`, DNS, closed-port refusal) passes. Also verify `/dev/net/tun` access and that gVisor builds under Go 1.27.

**Fallback if the spike fails:** `pasta` (hardened: `--no-map-gw`, `--map-host-loopback none`, `--map-guest-addr none`, `-t none -u none -T none -U none`) plus nft rules for private ranges, behind the same interface: a netns with an outbound path and a policy callback. Port grants are unchanged because they are listeners in either case.

### 6. Session identity and targeting

Id `<basename>-<short-hex>`; collision check at generation. A pointer file in the runtime dir records the last attached session; commands without `--sid` use it, print the target on every grant, and fail with the session list if it is stale. Inside the leader prompt the target is always the current session.

### 7. Sandbox baseline

- Filesystem: `--ro-bind` of system directories, a minimal explicit `/etc`, tmpfs `/tmp`, `--dev`/`--proc`, persistent per-agent home under the state dir.
- Binaries: system dirs plus the agent binary's symlink-resolved install root; `--inherit-path` filters host `PATH` entries to absolute, existing directories under `/usr/local`, `/opt`, `$HOME`, following symlinks and warning on dangling targets; `tools = [...]` adds explicit roots. The sandbox `PATH` is built only from mounted locations.
- Environment: empty by default; `--env KEY` forwards named variables; `--inherit-env` forwards all. `SSH_AUTH_SOCK` and similar are never implicit.
- Hardening: all caps dropped, `--new-session`, `--die-with-parent`, `--unshare-{pid,ipc,uts,cgroup,net}`, and `--disable-userns`. Nested user namespaces give unprivileged code full capabilities in a child namespace, which reaches root-only kernel paths (netfilter, mount code, overlayfs) and has been the entry for past local-privilege-escalation CVEs. Blocking them makes capability dropping meaningful. The cost: Chromium/Playwright's own sandbox, nested bwrap/podman/Nix, and Claude Code's built-in sandbox do not work inside; `--allow-userns` opts in.

### 8. Configuration tiers

```
 flags  >  <workspace>/.isolait/config  >  $XDG_CONFIG_HOME/isolait/config  >  defaults
```

- One documented file format (TOML) per tier; unknown keys are errors. Scalars override, lists extend and de-duplicate.
- Only the **starting** workspace's `.isolait` is read. Hot-added directories never contribute config.
- `.isolait` also holds per-workspace state (for example session ids started there). Global state and the per-agent home live under the XDG state directory.
- **Exclusion:** the global config dir and state/runtime dirs are on the mount deny list and never in the sandbox. A `.isolait` at the root of any mounted workspace is masked with an empty read-only bind layered over the workspace mount. This is the first sub-mount layered on a workspace mount; Phase 2 `git-rw` reuses the same mechanism. Nested `.isolait` directories are not masked (only the root is read).
- **Trust:** a freshly cloned repository can ship a hostile `.isolait/config`. The workspace tier is ignored entirely (no partial application, so no per-setting widening-versus-tightening analysis) until `isolait trust` records the file's content hash in global state; a content change revokes trust. Start prints a warning when an untrusted config was ignored. Local state files in `.isolait` are written by isolait and are not subject to trust.

### 9. Modes

Phase 1 modes are `rw` (default) and `ro`. The mount-planning code is shaped so a richer mode (Phase 2 `git-rw`) can add layered sub-mounts without an abstraction now.

## Risks / Trade-offs

- **Propagation into a child-userns mount namespace may behave differently than expected** (`MNT_LOCKED` on propagated mounts, bwrap making `/workspaces` private) → first spikes; fallback is nsenter + `open_tree`/`move_mount` behind the same interface.
- **Netstack effort and long tail** (TCP edge cases, build friction) → spike gate, `pasta` fallback, TCP-only and IPv4-only scope.
- **Terminal injection via agent output** → sanitizer, documented as narrowing rather than eliminating.
- **Prompt spoofing:** the agent can draw text resembling the prompt → grants are echoed in `isolait status` and in a log outside the PTY.
- **Hostile workspace config** → the workspace config is ignored until `isolait trust`; hot-added directories contribute no config; `.isolait` is masked from the sandbox.
- **Unprivileged userns disabled** (Ubuntu 24.04 AppArmor policy) → preflight check with actionable error.
- **Busy unmount** → report blockers; `--force` detaches lazily, which can leave processes with stale handles.
- **Mounted directories can contain unix sockets**, which stay connectable regardless of mounts → documented; Phase 2 socket policy.
- **Writable mounts can plant host-executed files** (git hooks, scripts) → accepted for `rw`; `--ro` available now; Phase 2 `git-rw`.
- **Detached sessions on WSL2** may be killed when the last terminal closes on distributions without systemd → verify; document `systemd=true` or keep-alive.
- **Host services see port-forwarded connections as local `netd` connections**, with no per-agent attribution.
- **Resource exhaustion:** large port ranges or connection floods → range cap and per-session connection limits.

## Migration Plan

Greenfield. Rollback is removing the binary, the runtime directory and the state directory.

## Open Questions

- LAN access is blocked entirely in Phase 1. Phase 2 adds subnet allowlisting, with an `allow lan` shortcut that introspects the host's private subnets.
- Exact connection limits and the range-cap default (safe to tune later).
