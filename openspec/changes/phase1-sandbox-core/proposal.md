# Proposal

## Why

AI coding agents run untrusted, prompt-injectable loops against the developer's host. Existing options are either weak (shared-kernel containers), heavy (microVMs), or too static (native sandbox profiles that force users to disable sandboxing). `isolait` needs a rootless baseline that starts instantly and can change what the agent sees *while the session runs*, without losing agent context. This change delivers that baseline.

## What Changes

- New `isolait` CLI + per-session broker daemon (Go) that starts an agent in a rootless bubblewrap sandbox.
- Session is named after the starting workspace directory; its identity is stable and independent of whether that directory remains mounted.
- Workspaces live under `/workspaces/<name>` inside the sandbox. The starting directory is mounted there at start.
- Hot-mount / hot-unmount of additional host directories at runtime, without restarting the session. Mount modes: `rw` (default) and `ro` (`--ro` opt-in).
- Hot-open / hot-close of TCP and UDP ports and port ranges, to host localhost only, without requiring host privileges.
- Mounting is performed by a broker that owns a parent user+mount namespace; the sandbox is a propagation *slave* of it and never receives mount capability. (`nsenter`-into-sandbox from the original proposal is replaced.)
- **Deferred to Phase 2:** `git-rw` mount mode (and its becoming the default), SNI/DNS/IP-pinning filtering, USB device passthrough, unix socket mounting.

## Capabilities

### New Capabilities
- `sandbox-session`: Starting, naming, tracking, inspecting and stopping a rootless sandbox session for an agent.
- `hot-mounts`: Adding and removing host directories under `/workspaces` in a running sandbox, with `rw`/`ro` modes and validation that preserves isolation.
- `network-ports`: Opening and closing localhost TCP/UDP ports and port ranges for a running sandbox, without host privileges.

### Modified Capabilities
<!-- None: no existing specs. -->

## Impact

- New Go module, `isolait` binary, cobra CLI (`start`, `status`, `mount`, `unmount`, `allow port`, `deny port`).
- Runtime dependencies: `bwrap`, Linux user namespaces enabled (preflight must detect AppArmor/sysctl restrictions), kernel with the new mount API (`open_tree`, `move_mount`, `mount_setattr`).
- `openspec/config.yaml` roadmap text needs updating (Phase 1 now includes hot-mounts and ports; `nsenter` approach replaced; `git-rw` in Phase 2). Done outside explore mode.
- Security posture: sandbox gains no new capabilities; all mount operations originate from the broker.
