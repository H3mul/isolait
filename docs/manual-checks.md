# Manual checks

Things the automated suites cannot cover because they need a real agent, a real login or a real terminal
emulator. Run them after changes to the terminal path (`internal/term`, `internal/relay`, `internal/daemon/terminals.go`)
and record the date, versions and result below each item.

## Claude Code and OpenCode through the relay (task 4.2)

In a project directory, with your usual agent installed:

1. `isolait start claude` (then the same with `opencode`). The agent's interface appears and responds.
2. Type, paste a multi-line block (it must arrive as one paste, not as separate Enter presses), use the arrow keys,
   Escape, Ctrl-C (interrupts the agent, does not leave isolait) and Tab completion.
3. Resize the terminal window: the agent redraws at the new size.
4. Leader, `d` (default `Ctrl-\` then `d`) detaches; the shell prompt returns cleanly, with no leftover alternate
   screen, mouse reporting or hidden cursor. `isolait attach` shows the agent's current screen at the current size.
5. While attached, paste text that contains the leader byte: nothing detaches.
6. Close the terminal window while attached, open a new one and `isolait attach`: the agent is still running.
7. Ask the agent to print an OSC 52 clipboard write (`printf '\033]52;c;aGk=\007'`): the clipboard is not changed.

Run by hand on 2026-11-18 with Claude Code and OpenCode (see the launcher-script section). Automated stand-ins (a shell, a scripted alternate-screen program, a pty as the terminal)
are in `internal/cli/attach_security_test.go` and `internal/relay/relay_test.go`.

## Launcher scripts: `isolait start claude` (session-ux-pickups 1.5)

`/usr/sbin/claude` is a wrapper (`exec /opt/claude-code/bin/claude "$@"`). Run `isolait start claude` in a project directory:
Claude Code's interface appears, and the start prints `warning: claude is a launcher script; also exposing /opt/claude-code/bin/claude`.

2026-11-18 (isolait at the 1.4 commit, Claude Code under `/opt/claude-code`): `isolait start -d claude` then
`isolait status` lists `/opt/claude-code/bin/claude` as a tool root and prints the warning (automated by
`sandbox.TestLauncherInSystemDirRunsInSandbox` against a wrapper in a system directory). The interactive start on a
real terminal was run by hand the same day (see below).

2026-11-18 (manual, interactive, real terminal): `isolait start claude` and `isolait start opencode` both start and
run successfully through the relay. With a DeepSeek model, the agent was able to tell it was running in a sandbox
(expected: isolait hides the host, it does not disguise itself).

## tmux inside a session (session-ux-pickups 5.5)

`isolait start` (bash), then `tmux`: it needs only the session's pty and `/tmp` (its socket is `/tmp/tmux-<uid>/default`),
so no extra mount or exposure. A second shell (`isolait exec -- bash`) reaches the same tmux server.

2026-11-18 (tmux 3.8): `daemon.TestTmuxRunsInsideASession` starts tmux as the agent, sees its command run, and reaches the
server from an exec'd shell. No gap found. Run it by hand once on a real terminal for the full-screen interface.

## Kernel information and WSL submounts (audit-findings-hardening 3.1, 3.3)

2026-11-18 (WSL2 6.18.58.1, host `kptr_restrict=0`, `dmesg_restrict=0`): from inside a session `/proc/kallsyms` shows only
zero addresses (the user is not root), `dmesg` is refused (`syslog` is denied) and `/dev/kmsg` is not present, so no
further `/proc` files are masked (`sandbox.TestKernelLogAndAddressesAreNotReadable` guards this).

On WSL2 the sandbox now shows empty read-only directories at `/usr/lib/wsl/drivers`, `/usr/lib/wsl/lib` and
`/usr/lib/modules/<kernel>`; `isolait status` lists them as `masked`. git, node, python3 and go run unchanged
(`sandbox.TestDeveloperToolsRunUnderTheFilter`). Not tried: GPU compute, which keeps its libraries in `/usr/lib/wsl/lib`
and so does not work in a session (documented in the README). Run `nvidia-smi` in a session on a GPU host to confirm.

## First full audit run (security-audit-tests 3.5)

2026-11-18 (WSL2 6.18.58.1, tools as pinned in `scripts/audit/tools.lock`: linpeas 20261117-8bfcfa5c, deepce 420b1d1ddb63,
botb 1.8.0; `make audit` from the Claude Code tool shell): 19 assertions held, 0 failed. botb's `-find-sockets` again
reported the gpg-agent sockets under `/run/user/<uid>/gnupg`: they were created during the run by linpeas's own gpg
call (absent from the pre-run listing), so they are recorded, not failed. The audit's runtime, state and config
directories were separate and removed on exit, including after Ctrl-C (checked by interrupting a run: no `/tmp/isolait-audit.*`
directory or new session remained). Caveat: the tool shell itself runs under a seccomp filter that the sandbox inherits, so
`Seccomp: 2` in the report is not proof that the filter is isolait's; `sandbox.TestSeccompDenyListInTheSession` is. Repeat the run
from a plain terminal (audit-findings-hardening 4.2).
