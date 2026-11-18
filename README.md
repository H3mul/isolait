# isolait

Run AI coding agents (Claude Code, OpenCode, ...) in a rootless, zero-trust sandbox on Linux and WSL2. The
sandbox starts instantly, needs no root, no VM and no container runtime, and every permission the agent has is
an explicit, user-granted, revocable grant.

> **Status:** Phase 1 is in progress. Sessions, the sandbox baseline, resource limits, attaching a terminal to
> the agent (detach, reattach, exec, the leader prompt) and the control commands below work. Hot-mounting more
> directories, network access and port grants are the next steps, so the sandbox has no network device yet.

## Requirements

- Linux (or WSL2), unprivileged user namespaces enabled, kernel with the new mount API (5.12 or newer)
- [bubblewrap](https://github.com/containers/bubblewrap) 0.8 or newer (`bwrap`)
- `/dev/net/tun` (for the network engine)
- Optional: a systemd user manager, used to apply resource limits to each session

`isolait preflight` checks all of this and explains how to fix anything missing.

## Build

```sh
go build -o isolait .
```

## Quick start

These examples are run by the test suite as written, from a script (so, not from a terminal: `start` then creates
an *idle* session and does not attach; in a terminal it attaches, see [Attach, detach and exec](#attach-detach-and-exec)).
`<sid>` is the session id, `<dir>` the project directory and `<age>` how long the session has been up.

```console
$ isolait start sh
started <sid> (idle: the agent is started when you attach)
$ isolait list
ID     STATE  WORKSPACES  AGE
<sid>  idle   api:rw      <age>
$ isolait status <sid>
session  <sid>
state    idle
workdir  <dir>
mounts
  /workspaces/api  rw  (<dir>)
tool roots  none
ports       none
env         HOME, LOGNAME, PATH, USER
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

### Targeting a session

`attach`, `exec`, `list`, `status` and `stop` take a session id (`isolait stop <sid>`), or `--sid <sid>`. Without
either, the command acts on the last attached session; if there is none, it fails and lists the running sessions.

## Attach, detach and exec

Run in a terminal, `isolait start <agent>` starts the session and attaches your terminal to the agent. Sessions
belong to a background daemon, so they survive the terminal:

- **Detach** with the leader key then `d` (default leader: `Ctrl-\`). The agent keeps running and your shell is
  back, with the terminal restored. If you close the terminal instead, the session simply carries on.
- **`isolait attach [sid]`** attaches again, to the last attached session unless you name one. It shows the agent's
  current screen at your current size: the agent is asked to repaint, and an agent that was on the alternate
  screen is put back there. If the agent had exited, attaching starts it again in the same sandbox. One client is
  attached to the agent at a time.
- **`isolait exec [--sid sid] -- command [args...]`** runs a command in the session's sandbox on your terminal,
  with the same mounts, environment and restrictions as the agent: a second shell, for example
  `isolait exec -- bash`. It ends when the command ends, when you detach, or when you close the terminal.
- When the agent or the exec'd command ends, `attach` and `exec` exit with its status (128 plus the signal number
  for a killed process).

`attach` and `exec` need a terminal. There is **no scrollback**: while attached, your terminal's own scrollback
works as usual, but nothing that scrolled away is replayed when you reattach. Run `isolait attach` inside `tmux` or
`screen` if you want scrollback across sessions.

### The leader key

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

### The prompt

Leader then `:` opens a one-line prompt on the bottom row and runs isolait commands against the session you are
in, with the same arguments as on the command line (`status`, `list`, `stop`, and the mount and port commands as
they arrive). Enter runs the command and shows the result on one row for a moment; Escape or Ctrl-C dismisses it.
Commands that attach, start another session or are internal are refused. On a normal screen the prompt opens on
the terminal's alternate screen, so the agent's screen is untouched when it closes; over an agent that is itself on
the alternate screen it overwrites the bottom row and asks the agent to repaint. Agent output is held while the
prompt is open and shown after it closes.

### Terminal safety

Agent output is filtered before it reaches your terminal. Clipboard writes (OSC 52), window and icon title changes,
colour and other terminal queries (every OSC except hyperlinks), device control strings (DCS, such as sixel),
application and privacy strings (APC, PM, SOS), window manipulation and its reports (`CSI ... t`) and the
answerback request are dropped; colours, cursor movement, hyperlinks and the alternate screen pass unchanged.
Sequences split across reads are handled. This is a filter, not a terminal emulator: it narrows what an agent can
do to your terminal and does not claim to eliminate terminal injection.

## Mounting more directories

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

## What the sandbox contains

The agent sees only this, all built from one plan that is checked against the live mount table before anything
runs in the sandbox:

- **System directories**, read-only (`/usr` and the `/bin`, `/lib`, ... links), and a minimal `/etc`: user
  database, name-service config, hosts, timezone, linker and CA configuration.
- **A private `/tmp`** in memory, a minimal `/dev`, and `/proc` for its own processes.
- **A persistent home** for the agent under `$XDG_STATE_HOME/isolait/homes/<agent>`, mounted at your home path.
  Your real home, `~/.ssh` and every other host path are not there. A new home is seeded from `/etc/skel` (an
  embedded minimal bash setup if that has none); existing files are never overwritten. Only vanilla bash is set up
  this way: other shells start bare, and their dotfiles can be placed in `$XDG_STATE_HOME/isolait/homes/<shell>`
  (for example `homes/zsh`). Importing your own dotfiles or choosing a preferred shell is not supported yet.
- **The starting directory** at `/workspaces/<name>`, read-write (or read-only with `--ro`), as the working
  directory. Its `.isolait` directory is masked by an empty read-only layer, so a repository's isolait config
  cannot be read or changed from inside.
- **The agent itself**: its resolved install root (symlinks followed), read-only, and a `/isolait/bin/<name>`
  link so it starts by name. Host `PATH` directories are *not* visible unless you ask (`--inherit-path`, or
  `tools` in the [config](docs/config.md)); symlinks whose targets would not be mounted produce a warning.
- **An explicit environment**: only `HOME`, `USER`, `LOGNAME`, `PATH`, the locale (`LANG`, `LC_*`, default `LANG=C.UTF-8`), `COLORTERM` and the variables
  you declare. A host
  secret such as `AWS_SECRET_ACCESS_KEY` is absent unless you pass it.

Hardening: no capabilities, new user, pid, ipc, uts, cgroup and network namespaces, a new terminal session,
termination when the daemon exits, and nested user namespaces blocked unless you opt in with `--allow-userns`.
Network access is described under [Network egress](#network-egress).

Agents installed as a wrapper script (for example `/usr/sbin/claude` doing `exec /opt/claude-code/bin/claude`)
are followed: if the agent is a short `#!` text file, the absolute executables it runs (an `exec` target or a
command at the start of a line, no variables) are also exposed read-only, to a depth of 3 and at most 8 targets.
They are listed under `tool roots` in `isolait status`, and `start` prints `warning: <agent> is a launcher
script; also exposing <path>`. A target inside isolait's own directories, or one that contains your home
directory, is refused. Limits: a launcher that builds its target from a variable or reads files next to itself
(`$(dirname "$0")/../lib`) is not followed; add its install tree with `tools = ["/opt/claude-code"]` in the
[config](docs/config.md), otherwise the agent exits with status 127.

Sessions live as long as their init process. They have no idle timeout, and the agent exiting does not end the
session. `isolait stop` ends it and releases every process, mount and runtime file; the agent's persistent home
is kept.

## Letting the agent reach a service on your machine

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

## Network egress

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

## Resource limits

Each session runs in its own systemd user scope: `limits.pids` (default 4096) bounds a fork bomb, and you can cap
`limits.memory` and `limits.cpu`. Without a systemd user manager the session still starts, and `isolait status`
shows `limits: unavailable (<reason>)`. See [docs/config.md](docs/config.md#resource-limits).

## Configuration

Global and per-workspace TOML config, and the trust model for a repository's own `.isolait/config`:
[docs/config.md](docs/config.md).

## Tests

```sh
make test        # fast tier: units, parsers, protocol, plan (no kernel features needed)
make security    # also runs the sandbox on the real kernel (needs user namespaces and bwrap)
make canary      # only the host-assumption canaries: run after a kernel, bwrap or systemd upgrade
make isolation   # the CI gate over the sandbox's core guarantees (fails if any of its tests is skipped)
make e2e         # the whole workflow through the real binary: start, attach, mounts, ports, restart, stop
make mutations   # apply deliberate regressions to a scratch copy; every one must fail a test
```

[docs/security-tests.md](docs/security-tests.md) maps every security assumption validated by the feasibility
spikes to the test that guards it and the mutation that proves the test fails when the assumption breaks.

## Project

Specs, design, tasks and the feasibility spikes live in the `isolait` OpenSpec store (see `openspec/config.yaml`).
