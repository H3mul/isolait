# isolait

Run AI coding agents (Claude Code, OpenCode, ...) in a rootless, zero-trust sandbox on Linux and WSL2. The
sandbox starts instantly, needs no root, no VM and no container runtime, and every permission the agent has is
an explicit, user-granted, revocable grant.

> **Status:** Phase 1 is in progress. Sessions, the sandbox baseline, resource limits and the control commands
> below work. Attaching a terminal to the agent, hot-mounting more directories, network access and port grants
> are the next steps, so for now `start` creates an *idle* session: the sandbox is up and verified, and the agent
> is started when you attach.

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

These examples are run by the test suite as written. `<sid>` is the session id, `<dir>` the project directory
and `<age>` how long the session has been up.

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

Run `isolait start <agent> [args...]` in the directory you want the agent to work in. Flags go before the agent
command:

| Flag | Effect |
|---|---|
| `--ro` | Mount the starting directory read-only |
| `--env NAME` | Forward this host environment variable (repeatable) |
| `--inherit-env` | Forward the whole host environment (agent sockets such as `SSH_AUTH_SOCK` are still withheld unless named with `--env`) |
| `--inherit-path` | Also expose host `PATH` directories under `/usr/local`, `/opt` and your home |
| `--allow-userns` | Allow nested user namespaces in the sandbox (weakens isolation) |

`start` refuses `/`, your home directory and any directory that contains or sits inside isolait's own config,
state or runtime directory.

### Targeting a session

`list`, `status` and `stop` take a session id (`isolait stop <sid>`), or `--sid <sid>`. Without either, the
command acts on the last attached session; if there is none, it fails and lists the running sessions.

## What the sandbox contains

The agent sees only this, all built from one plan that is checked against the live mount table before anything
runs in the sandbox:

- **System directories**, read-only (`/usr` and the `/bin`, `/lib`, ... links), and a minimal `/etc`: user
  database, name-service config, hosts, timezone, linker and CA configuration.
- **A private `/tmp`** in memory, a minimal `/dev`, and `/proc` for its own processes.
- **A persistent home** for the agent under `$XDG_STATE_HOME/isolait/homes/<agent>`, mounted at your home path.
  Your real home, `~/.ssh` and every other host path are not there.
- **The starting directory** at `/workspaces/<name>`, read-write (or read-only with `--ro`), as the working
  directory. Its `.isolait` directory is masked by an empty read-only layer, so a repository's isolait config
  cannot be read or changed from inside.
- **The agent itself**: its resolved install root (symlinks followed), read-only, and a `/isolait/bin/<name>`
  link so it starts by name. Host `PATH` directories are *not* visible unless you ask (`--inherit-path`, or
  `tools` in the [config](docs/config.md)); symlinks whose targets would not be mounted produce a warning.
- **An explicit environment**: only `HOME`, `USER`, `LOGNAME`, `PATH` and the variables you declare. A host
  secret such as `AWS_SECRET_ACCESS_KEY` is absent unless you pass it.

Hardening: no capabilities, new user, pid, ipc, uts, cgroup and network namespaces, a new terminal session,
termination when the daemon exits, and nested user namespaces blocked unless you opt in with `--allow-userns`.
There is no network device yet.

Sessions live as long as their init process. They have no idle timeout, and the agent exiting does not end the
session. `isolait stop` ends it and releases every process, mount and runtime file; the agent's persistent home
is kept.

## Resource limits

Each session runs in its own systemd user scope: `limits.pids` (default 4096) bounds a fork bomb, and you can cap
`limits.memory` and `limits.cpu`. Without a systemd user manager the session still starts, and `isolait status`
shows `limits: unavailable (<reason>)`. See [docs/config.md](docs/config.md#resource-limits).

## Configuration

Global and per-workspace TOML config, and the trust model for a repository's own `.isolait/config`:
[docs/config.md](docs/config.md).

## Tests

```sh
go test ./...                    # fast tier: units, parsers, protocol, plan
go test -tags security ./...     # also runs the sandbox on the real kernel
```

[docs/security-tests.md](docs/security-tests.md) maps every security assumption validated by the feasibility
spikes to the test that guards it and the change that proves the test fails when the assumption breaks.

## Project

Specs, design, tasks and the feasibility spikes live in the `isolait` OpenSpec store (see `openspec/config.yaml`).
