# Proposal

> **Status: context capture, not yet fleshed out.** Records decisions and open threads from exploration so they are not lost. Specs, full design and tasks come later. Depends on `phase1-sandbox-core`.

## Why

Phase 1 mounts are `rw` by default, so a compromised or injected agent can plant host-executed files in a mounted workspace (git hooks, `.git/config` fsmonitor/sshCommand, `.envrc`, ignored scripts) that git review cannot show. Phase 2 adds a default mode that narrows writes to what the developer can review, and adds the access types Phase 1 deliberately left out (domain-level egress, devices, sockets).

## What Changes

- **`git-rw` mount mode**, becoming the default for mounts and the starting workspace. Modes become `git-rw` (default) | `rw` | `ro`. **BREAKING**: Phase 1's default of `rw` changes; `--rw` becomes the explicit opt-in.
- Domain/SNI/DNS/IP-pinning egress filtering, built on the Phase 1 `netd` policy engine (TCP forwarder peeks at the ClientHello before dialing). No tier switching: Phase 1 already uses netstack. UDP support is a separate open question.
- Subnet allowlisting for egress, with an `allow lan` shortcut that introspects the host's private subnets (LAN is blocked entirely in Phase 1).
- Optional idle timeout that requires human confirmation to continue, as an unattended-operation restriction (Phase 1 sessions live as long as their init).
- USB / character-device hot-plug (`/dev/ttyUSB*`).
- Unix socket hot-plug (e.g. `docker.sock`), with a warning/confirmation because it is effectively host root.

## Capabilities

### New Capabilities
- `git-rw-mounts`: Git-aware write policy for mounts. See design.md.
- `network-egress-filtering`: Domain/SNI/DNS/IP-pinning egress rules layered on Phase 1's `network-egress` (no tiers), plus CIDR/subnet allowlisting and `allow lan`.
- `device-passthrough`: Hot-plug of character/block device nodes into a running sandbox.
- `socket-passthrough`: Hot-plug of unix sockets into a running sandbox.

### Modified Capabilities
- `hot-mounts`: default mode becomes `git-rw`; new mode flags.
- `sandbox-session`: starting workspace uses the new default mode; optional idle timeout with human confirmation.

## Impact

- Adds a `git` dependency for mount planning (`git ls-files`, `rev-parse`).
- Extends the hot-mount planner with sub-mounts layered on a workspace mount.
- Extends `netd` (from Phase 1) with SNI/domain rules and DNS overrides; `miekg/dns` if needed.
- WSL2: `usbipd-win` attachment must happen before device passthrough.
- The two network/device/socket capabilities are sketches only; no decisions captured yet beyond the original proposal.
