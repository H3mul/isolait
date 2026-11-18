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

Not yet run on a real agent. Automated stand-ins (a shell, a scripted alternate-screen program, a pty as the terminal)
are in `internal/cli/attach_security_test.go` and `internal/relay/relay_test.go`.
