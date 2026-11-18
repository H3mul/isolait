# isolait

Run AI coding agents (Claude Code, OpenCode, ...) in a rootless, zero-trust sandbox on Linux and WSL2. The
sandbox starts instantly, needs no root, no VM and no container runtime, and every permission the agent has is
an explicit, user-granted, revocable grant.

## Why another AI sandbox

Most sandboxes are fixed when they start: you pick the permissions, restart, and lose the agent's context. isolait
starts from a secure base (the agent sees one project directory, a private home, no host network, no secrets) and
lets you open it up as you go, while the agent keeps running: mount another directory, open a port to a local
service, change what it can reach. Every change takes effect immediately and ends with the session; nothing is
widened by default and nothing needs a restart. Grants are made by you from outside, or from the leader prompt
inside the terminal, never by the agent.

> **Status:** Phase 1 is in progress. Sessions, the sandbox baseline, resource limits, attaching a terminal to the
> agent, hot mounts, port grants and outbound network access work. Egress policy levels and home profiles are
> proposed, not built.

- [Security audit and tech stack](#security-audit-and-tech-stack)
- [What it can do](#what-it-can-do)
- [Quick start](#quick-start)
- [Tool documentation](#tool-documentation)
- [Install](#install)
- [For developers](#for-developers)

## Security audit and tech stack

The sandbox was audited from the inside with public container-escape and privilege-escalation tools (linpeas,
deepce, botb) plus hand probes, run as the agent of throwaway sessions. Last run 2026-11-18, WSL2 kernel
6.18.58.1. The tools found no capabilities, no container runtime socket, no reachable metadata service and no
kernel exploit match. The hand probes found real gaps the tools did not flag, which are open
(change `audit-findings-hardening`):

- kernel keyrings are shared with the host user, and isolait installs no seccomp filter yet;
- on WSL2, `/usr` carries the Windows driver store mount (read-only) into the sandbox.

These tools are heuristics: a clean report is not proof of safety. Tools, checksums and per-tool results:
[docs/security-tests.md](docs/security-tests.md#security-audit).

Stack: Go; user, pid, ipc, uts, cgroup and network namespaces through bubblewrap; a userspace network engine on
gVisor netstack in a separate per-session process; systemd user scopes for resource limits.

## What it can do

- **Hot mounts.** Add and remove directories (read-write or read-only) while the agent runs. Protected paths
  (home, isolait's own directories) are refused and the live mount table is verified after every change.
- **Port grants.** Let the sandbox reach one host TCP port on `127.0.0.1` (a dev server, a database), then close
  it again, without a restart.
- **Network egress.** Outbound TCP and DNS through a userspace network stack; private, loopback, metadata and
  host addresses are blocked.
- **Resource limits.** Every session runs in a systemd user scope with a process cap (default 4096) and optional
  memory and CPU caps.
- **Attach, detach and exec.** Sessions belong to a background daemon, so they survive the terminal. Detach with
  a leader key, reattach later, run a second shell in the same sandbox.

## Quick start

Install first (see [Install](#install)).

These examples are run by the test suite as written, from a script (so, not from a terminal: `start` then runs the
agent detached and does not attach; in a terminal it attaches, see [Attach, detach and exec](#attach-detach-and-exec)).
`<sid>` is the session id, `<dir>` the project directory and `<age>` how long the session has been up.

```console
$ isolait start sh
started <sid> (detached)
$ isolait list
ID     STATE     WORKSPACES  AGE
<sid>  detached  api:rw      <age>
$ isolait status <sid>
session  <sid>
state    detached
workdir  <dir>
mounts
  /workspaces/api  rw  (<dir>)
tool roots  none
ports       none
env         HOME, LANG, LOGNAME, PATH, USER
$ isolait stop <sid>
stopped <sid>
$ isolait list
no sessions running
```

Run `isolait start [agent [args...]]` in the directory you want the agent to work in; with no agent it runs `bash`
(`isolait start -d` then `isolait attach` is the way to prepare mounts and ports before running anything). Flags go
before the agent command:

| Flag | Effect |
|---|---|
| `-d`, `--detach` | Start the session without attaching to it |
| `--ro` | Mount the starting directory read-only |
| `--env NAME` | Forward this host environment variable (repeatable) |
| `--inherit-env` | Forward the whole host environment (agent sockets such as `SSH_AUTH_SOCK` are still withheld unless named with `--env`) |
| `--inherit-path` | Also expose host `PATH` directories under `/usr/local`, `/opt` and your home |
| `--allow-userns` | Allow nested user namespaces in the sandbox (weakens isolation) |

`start` refuses `/`, your home directory and any directory that contains or sits inside isolait's own config,
state or runtime directory.

## Tool documentation

### Exploring the commands

Every command prints its help when you run it without the arguments it needs (`isolait allow`, `isolait mount`, `isolait deny port`, `isolait exec` all do, with exit status 0); a wrong number of arguments or an unknown subcommand prints the usage line and the `--help` hint with exit status 1. `isolait --help` lists everything.

### Targeting a session

`attach`, `exec`, `list`, `status` and `stop` take a session id (`isolait stop <sid>`), or `--sid <sid>`. Without
either, the command acts on the most recently used session (like tmux: attaching or detaching counts, an `exec` does not);
`attach` prefers the most recently used session that nobody is attached to. `isolait list` shows the most recently used
first. With no session running the commands say `no sessions running`.

### Attach, detach and exec

Run in a terminal, `isolait start <agent>` starts the session and attaches your terminal to the agent. Sessions
belong to a background daemon, so they survive the terminal:

- **Detach** with the leader key then `d` (default leader: `Ctrl-\`). The agent keeps running and your shell is
  back, with the terminal restored. If you close the terminal instead, the session simply carries on.
- **`isolait attach [sid]`** attaches again, to the most recently used session unless you name one. It shows the agent's
  current screen at your current size: the agent is asked to repaint, and an agent that was on the alternate
  screen is put back there. One client is attached to the agent at a time.
- **`isolait exec [--sid sid] -- command [args...]`** runs a command in the session's sandbox on your terminal,
  with the same mounts, environment and restrictions as the agent: a second shell, for example
  `isolait exec -- bash`. It ends when the command ends, when you detach, or when you close the terminal.
- When the agent or the exec'd command ends, `attach` and `exec` exit with its status (128 plus the signal number
  for a killed process).

`attach` and `exec` need a terminal. There is **no scrollback**: while attached, your terminal's own scrollback
works as usual, but nothing that scrolled away is replayed when you reattach. Run `isolait attach` inside `tmux` or
`screen` if you want scrollback across sessions.

#### The leader key

| Keys | Effect |
|---|---|
| leader, `d` | Detach |
| leader, `:` | Open the prompt (below) |
| leader, leader | Send one literal leader byte to the agent |
| leader, Escape | Cancel (the Escape is sent on, so an arrow key typed next is not garbled) |
| leader, anything else | Ignored |

The leader is recognised only in real keyboard input. Your terminal is kept in bracketed-paste mode, so text you
paste is never mistaken for typed keys: a leader byte inside a paste is sent to the agent unchanged, and paste
markers reach the agent only if it asked for them. Change the key with `leader` in the [config](docs/config.md).

#### The prompt

Leader then `:` opens a one-line prompt on the bottom row and runs isolait commands against the session you are
in, with the same arguments as on the command line (`status`, `list`, `stop`, and the mount and port commands as
they arrive). Enter runs the command and shows the result on one row for a moment; Escape or Ctrl-C dismisses it.
Commands that attach, start another session or are internal are refused. On a normal screen the prompt opens on
the terminal's alternate screen, so the agent's screen is untouched when it closes; over an agent that is itself on
the alternate screen it overwrites the bottom row and asks the agent to repaint. Agent output is held while the
prompt is open and shown after it closes.


#### Terminal safety

Agent output is filtered before it reaches your terminal: clipboard writes (OSC 52), title changes, terminal
queries, device control strings and window manipulation are dropped; colours, cursor movement, hyperlinks and the
alternate screen pass. This narrows what an agent can do to your terminal; it is a filter, not a terminal
emulator, and does not claim to eliminate terminal injection. Full list: [docs/sandbox-internals.md](docs/sandbox-internals.md#terminal-safety).

### What the agent sees

The starting directory at `/workspaces/<name>` (read-write, or read-only with `--ro`), a read-only system
(`/usr`, a minimal `/etc`), a private in-memory `/tmp`, a minimal `/dev`, a persistent per-agent home under
`$XDG_STATE_HOME/isolait/homes/<agent>`, the agent's own install root read-only, and an explicit environment
(`HOME`, `USER`, `LOGNAME`, `PATH`, the locale and what you pass with `--env`). Your real home, `~/.ssh` and
every other host path are not there. Hardening: no capabilities, new user, pid, ipc, uts, cgroup and network
namespaces, nested user namespaces blocked unless `--allow-userns`. A session lives exactly as long as its agent
process. A seccomp filter denies the calls a developer's tools do not need and an attacker does (kernel keyrings,
`perf_event_open`, `bpf`, cross-process memory access, the mount family, kernel log); `io_uring` returns ENOSYS so
runtimes fall back to epoll, and `/proc/keys` is masked. `perf` and `bpftrace` do not work in a session; `ptrace`
(so `strace` and `gdb` on the agent's own processes) does. On WSL2, host mounts of other filesystems below the system directories (the Windows driver store,
`/usr/lib/wsl/lib`) are hidden behind empty read-only directories and listed as `masked` by `isolait status`; as a
result GPU compute does not work in a session. Agents installed as launcher scripts are followed; `isolait stop` ends a session and
`isolait kill-server` ends every session. The full list, launcher-script rules and startup failure behaviour are in
[docs/sandbox-internals.md](docs/sandbox-internals.md).

### Mounting more directories

While a session runs you can add and remove directories without restarting the agent. Run these from a shell,
or type them in the leader prompt:

```sh
isolait mount ../shared-lib              # at /workspaces/shared-lib, read-write
isolait mount --ro --as docs ~/notes     # at /workspaces/docs, read-only
isolait unmount docs                     # refuses while a process uses it
isolait unmount --force docs             # detach anyway
```

`isolait status` lists every mount. The agent sees a new mount immediately; a read-only mount is never visible
as writable, and every mount is `nosuid` and `nodev`. Names follow the directory's name unless you pass `--as`,
and a name that is taken is an error.

What is refused: the filesystem root, your home directory and every directory that contains it (but not
directories inside it), and isolait's own config, state and runtime directories and anything inside them or
containing them. Checks compare device and inode, so symlinks and `..` do not disguise a protected directory.
A directory whose `.isolait` is not a plain directory is refused. Otherwise a `.isolait` at the top of a mounted
directory is masked, and only the starting directory's config is ever read. Submounts on the host below the
source (other disks, network shares) are not carried into the sandbox.

After every change the sandbox's real mount table is compared with the plan; on a mismatch the new mount is
rolled back and the command fails.

Residual risks to weigh before mounting:

- A read-write mount lets the agent plant files that your own tools later run (git hooks, scripts, build
  files). Use `--ro` when it only needs to read.
- Unix sockets inside a mounted directory stay connectable from the sandbox, whatever the mount flags.
- `unmount --force` detaches lazily: a process still using the mount keeps working with stale handles.
- Mounts are made on your behalf by the session's broker; the sandbox itself can never mount anything.

### Letting the agent reach a service on your machine

The sandbox cannot reach anything on your host, including `127.0.0.1`. To let it use a dev server, database or
similar, grant the port while the session runs:

```sh
isolait allow port 5432          # sandbox 127.0.0.1:5432 -> host 127.0.0.1:5432
isolait allow port 3000-3010     # a range, at most 100 ports at once
isolait deny port 3000-3010      # closes the open ones and ends their connections
```

`isolait status` lists the open ports. These also work in the leader prompt.

- TCP only; a UDP grant is rejected. Only IPv4 `127.0.0.1` on the host is reachable: a service bound to your LAN
  address, to `::1` or to a socket file is not, and the sandbox cannot pick a different destination.
- The sandbox port is the host port. If something inside the sandbox already uses it, the grant fails.
- A grant is all or nothing: if one port in a range cannot be opened, none stay open. `deny` closes the ports of
  its range that are open and ignores the rest. Grants end with the session.
- **Attribution caveat:** to the host service the sandbox's connections look exactly like your own local ones
  (from `127.0.0.1`, as your user). It cannot tell the agent from you, so it cannot apply a different policy or
  log who connected. Grant only services you would let the agent use with your own authority; a service with no
  authentication of its own is fully open to the agent for as long as the port is granted.

### Network egress

The sandbox has its own network namespace with one interface (`tap0`, `10.0.2.15`) and nothing else: no route to
the host's interfaces, no host loopback. A userspace network stack (gVisor netstack) in a separate, hardened
per-session process (`isolait netd`, no mount authority, seccomp-filtered) connects outbound on the sandbox's behalf.

- **TCP only.** UDP other than DNS is dropped. **ICMP is dropped**, so `ping` does not work.
- **IPv4 only.** IPv6 is disabled in the sandbox; hosts are reached over their IPv4 addresses.
- **DNS** goes to the gateway `10.0.2.2`, which asks the host's resolvers (`/etc/resolv.conf` is re-read for
  every query, so a VPN or network change is followed). The sandbox never learns the real resolver addresses.
- **Blocked destinations**, checked on the resolved address at connect time (so a name that resolves to a
  private address is refused too): loopback, RFC 1918 private ranges, CGNAT, link-local, cloud metadata
  endpoints, multicast, reserved ranges and the host's own addresses. Only public addresses are reachable;
  a blocked connect fails like a refused connection (`curl` exit 7).
- There is no inbound access; the sandbox cannot be reached from the network.

Verified against the real internet: HTTPS to the model API, `git` over HTTPS and `npm install` work; see the
manual record in the OpenSpec store (`spikes/e2e.md`).

### Resource limits

Each session runs in its own systemd user scope: `limits.pids` (default 4096) bounds a fork bomb, and you can cap
`limits.memory` and `limits.cpu`. Without a systemd user manager the session still starts, and `isolait status`
shows `limits: unavailable (<reason>)`. See [docs/config.md](docs/config.md#resource-limits).

### Configuration

Global and per-workspace TOML config, and the trust model for a repository's own `.isolait/config`:
[docs/config.md](docs/config.md).

## Install

Requirements:

- Linux (or WSL2), unprivileged user namespaces enabled, kernel with the new mount API (5.12 or newer)
- [bubblewrap](https://github.com/containers/bubblewrap) 0.8 or newer (`bwrap`)
- `/dev/net/tun` (for the network engine)
- Optional: a systemd user manager, used to apply resource limits to each session

`isolait preflight` checks all of this and explains how to fix anything missing.

Build and install:

```sh
go build -o isolait .
```

Put the binary on your `PATH`, then run `isolait preflight`.

On WSL2 the sandbox works with the `tun` driver loaded; resource limits need the systemd user manager
(`systemd=true` in `/etc/wsl.conf`), otherwise sessions still start and `isolait status` shows
`limits: unavailable`.

## For developers

Specs, design, tasks and the feasibility spikes live in the `isolait` OpenSpec store (see `openspec/config.yaml`);
changes are proposed there before they are built.

Test tiers:

```sh
make test        # fast tier: units, parsers, protocol, plan (no kernel features needed)
make security    # also runs the sandbox on the real kernel (needs user namespaces and bwrap)
make canary      # only the host-assumption canaries: run after a kernel, bwrap or systemd upgrade
make isolation   # the CI gate over the sandbox's core guarantees (fails if any of its tests is skipped)
make e2e         # the whole workflow through the real binary: start, attach, mounts, ports, agent exit, prepare-then-run, stop
make mutations   # apply deliberate regressions to a scratch copy; every one must fail a test
```

[docs/security-tests.md](docs/security-tests.md) maps every security assumption validated by the feasibility
spikes to the test that guards it and the mutation that proves the test fails when the assumption breaks.
