# 1.8 PTY relay with SIGWINCH redraw

**Question:** does a daemon-owned PTY plus a raw-mode client relay (resize forwarding, redraw on attach)
work for inline and alt-screen TUIs, with the app surviving detach?

**Approach (deterministic):** `relay.py` is a throwaway Python prototype of the Decision 4 shape (framed
input/resize from client, raw output to client, explicit `SIGWINCH` on attach/resize, Ctrl-\ detach, output
dropped while detached). `alt.py` (draws on `?1049h`) and `inline.py` (redraws a footer line) are fake
TUIs. tmux inside the container is used only as a terminal emulator to read the screen
(`capture-pane`); it is not a product dependency.

**Pass (per app):** attach draws at 80x24, keystroke reaches the app, resize to 100x30 is forwarded and
redrawn, Ctrl-\ detaches the client, app survives, a new client at 60x20 gets a redraw at the new size.
Inline: earlier history is *not* replayed (no scrollback, as designed).

**Manual (not automated, results pasted here when run):** repeat against real agents on a terminal:
- [ ] Claude Code (inline): attach, run a prompt, resize the window, detach, reattach; UI redraws, no garbage
- [ ] OpenCode (alt-screen): same; the alternate screen is restored after detach/attach
- [ ] Bracketed paste of multi-line text is not mangled
Manual results: _not yet run_ (needs the product relay from task 4.2; this checklist is re-run there).

**Run:** `./run.sh`.

## Result (2026-10-29)
Automated part: all PASS. **Verdict: GO** for the relay model; real-agent verification is deferred to 4.2.
