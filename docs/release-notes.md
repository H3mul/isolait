# Release notes

## Unreleased

### Hardening: syscall filter and keyring mask (audit-findings-hardening 1 and 2)

- Every session now runs under a seccomp deny list (see `internal/sandbox/seccomp.go`, one comment per group);
  `isolait status` shows `seccomp: on (<n> syscalls denied)`. Denied calls fail with EPERM, `io_uring` with ENOSYS.
  `perf` and `bpftrace` stop working inside a session by design.
- Foreign host mounts below system directories (WSL2: driver store, GPU libraries, kernel modules overlay) are hidden by an
  empty read-only directory and listed under `masked` in `isolait status`. GPU compute does not work in a session.
- `/proc/keys` and `/proc/key-users` are masked: the sandbox no longer lists the host user's kernel keys.

### Behaviour change: a session lives only while its agent runs

- Sessions no longer sit idle. When the agent (or shell) exits, the session ends and releases its mounts, ports and
  runtime files. `isolait attach` no longer restarts an agent; there is nothing to attach to after it exits.
- `isolait start -d` now starts the agent immediately (default `bash`), and fails with the agent's exit status and the last
  2 KiB of its output if it exits within 2 seconds.
- To prepare a session before running anything, start a shell and attach later: `isolait start -d`, then
  `isolait mount ...` / `isolait allow port ...`, then `isolait attach`. `tmux` works inside a session.
- Commands without `--sid` now act on the most recently used session (attach and detach count) instead of the last
  attached one. `isolait attach` prefers a session nobody is attached to. `isolait list` shows the most recently used
  first.

### Added

- `isolait start` with no agent runs `bash`; a new agent home is seeded from `/etc/skel`; `LANG`, `LC_*` and `COLORTERM`
  are passed into the sandbox (`LANG` defaults to `C.UTF-8`).
- `isolait kill-server` stops every session.
- Wrapper scripts such as `/usr/sbin/claude` (`exec /opt/claude-code/bin/claude`) are followed: the real binary is
  exposed read-only and listed under tool roots.
