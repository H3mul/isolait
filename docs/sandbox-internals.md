# What the sandbox contains, in detail

Moved out of the README. Summary: [README](../README.md#what-the-agent-sees).

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

A session lives exactly as long as its agent process: when the agent exits the session ends and releases every
process, mount, port grant and runtime file (the agent's persistent home is kept). There is no idle session and no
idle timeout. If the agent exits within 2 seconds of `start -d` (a broken launcher, a missing binary), `start`
fails with the agent's exit status and the last 2 KiB of its output and leaves nothing behind; an attached `start`
shows the output and exits with the status, as a shell would.

To prepare a session before running anything, start a shell: `isolait start -d` runs `bash`, then add mounts and
ports (`isolait mount`, `isolait allow port`), then `isolait attach` and run the agent from that shell. `tmux` also
works inside a session. `isolait stop` ends a session and `isolait kill-server` ends every session (it prints each
id, says `no sessions running` and succeeds when there are none, and fails only if a session could not be stopped).

## Terminal safety

Agent output is filtered before it reaches your terminal. Clipboard writes (OSC 52), window and icon title changes,
colour and other terminal queries (every OSC except hyperlinks), device control strings (DCS, such as sixel),
application and privacy strings (APC, PM, SOS), window manipulation and its reports (`CSI ... t`) and the
answerback request are dropped; colours, cursor movement, hyperlinks and the alternate screen pass unchanged.
Sequences split across reads are handled. This is a filter, not a terminal emulator: it narrows what an agent can
do to your terminal and does not claim to eliminate terminal injection.
