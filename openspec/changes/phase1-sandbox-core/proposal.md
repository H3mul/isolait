# Proposal

## Why

AI coding agents run untrusted, prompt-injectable loops against the developer's host. Existing options are either weak (shared-kernel containers), heavy (microVMs), or too static (native sandbox profiles that force users to disable sandboxing). `isolait` needs a rootless baseline that starts instantly, survives terminal disconnects, and can change what the agent sees *while the session runs*, without losing agent context. This change delivers that baseline, including a working outbound path so the agent can actually reach its model API.

## What Changes

- New `isolait` CLI and per-session daemon (Go) that runs an agent in a rootless bubblewrap sandbox. The daemon survives terminal close; the CLI attaches and detaches like tmux.
- Session ids are `<workdir-basename>-<short-hex>`. Commands target the last attached session by default, or `--sid <id>`. `isolait list`, `attach`, `exec`, `stop`, `status`.
- In-terminal leader key: detach, and a command prompt accepting the same commands as the CLI, targeting the current session. Output from the agent is sanitized before reaching the user's terminal. No scrollback in this phase (the terminal's own scrollback works while attached).
- Workspaces live under `/workspaces/<name>`; the starting directory is mounted there. Hot-add / hot-remove of directories at runtime, modes `rw` (default) and `--ro`.
- Sandbox baseline: system directories read-only, minimal `/etc`, persistent per-agent sandbox home, agent binary root auto-exposed read-only, opt-in `--inherit-path` and `tools` config, clean env allowlist (`--env`, opt-in `--inherit-env`), nested user namespaces blocked (opt-in `--allow-userns`).
- Outbound network is **internet-only TCP** through a user-space engine (gVisor netstack in a `netd` subprocess). Private, link-local, loopback and metadata ranges are blocked at dial time. DNS is answered internally. Non-DNS UDP and IPv6 are not supported.
- Hot-open / hot-close of **TCP** ports and ranges to host localhost, delivered as listeners on the sandbox's loopback.
- Tiered configuration: a global config in `~/.config/isolait` and a workspace-local `.isolait` directory with local config and state. Both are strictly excluded from the sandbox (`.isolait` is masked inside every mounted workspace), and a workspace-local config is ignored entirely until the user runs `isolait trust`.
- Sessions live as long as their init process; there is no idle timeout in this phase.
- Mounting is performed by a broker owning a parent user+mount namespace; the sandbox is a propagation slave and never gets mount capability. (`nsenter`-into-sandbox from the original proposal is replaced.)
- **Deferred to Phase 2:** `git-rw` mount mode (and becoming the default), SNI/domain filtering, subnet allowlisting and `allow lan`, optional idle timeout with human confirmation, USB devices, unix socket mounting, UDP.
- **Deferred beyond Phase 2:** scrollback / log replay, VT emulation.

## Capabilities

### New Capabilities
- `sandbox-session`: Rootless sandbox baseline (filesystem, binaries, env, hardening), session identity, status and lifecycle.
- `session-attach`: Daemon-hosted sessions with attach/detach, `list`, `exec`, last-attached targeting, leader key and prompt, output sanitizing.
- `hot-mounts`: Adding and removing host directories under `/workspaces` in a running sandbox, with `rw`/`ro` modes and isolation-preserving validation.
- `network-egress`: Internet-only outbound TCP and DNS for the sandbox, with private-range blocking.
- `network-ports`: Opening and closing host-localhost TCP ports and ranges for a running sandbox.
- `configuration`: Global and workspace-local config tiers, local state, exclusion from the sandbox, and trust for workspace-local config.

### Modified Capabilities
<!-- None: no existing specs. -->

## Impact

- New Go module, `isolait` binary (daemon, `netd`, in-sandbox init shim are subcommands of the same binary), cobra CLI.
- Runtime dependencies: `bwrap` (>= 0.8 for `--disable-userns`), unprivileged user namespaces, kernel with the new mount API, `/dev/net/tun`. Build dependency: gVisor netstack. No `tmux`, `pasta` or `nft` required.
- A netstack spike gates the network engine; fallback is `pasta` behind the same netns-plus-policy seam (see design).
- `openspec/config.yaml` updated to match (nsenter replaced, no kernel network tiers, config tiers, `git-rw` in Phase 2).
- Security posture: the sandbox gains no capabilities; all mount, network and port operations originate from the broker or `netd`.
