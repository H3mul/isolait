# Spec Delta

## Purpose

Lets sessions outlive the terminal: users start, detach, list, reattach and operate on sessions tmux-style, and run grants from inside the session, without giving the sandboxed agent any control over the session.

## ADDED Requirements

### Requirement: Daemon-hosted sessions
The system SHALL run each session under a background daemon that survives terminal closure, and SHALL attach the invoking terminal to the agent on `isolait start`.

#### Scenario: Terminal closed
- **WHEN** the user closes the terminal attached to a session
- **THEN** the agent and sandbox keep running

#### Scenario: Start attaches
- **WHEN** the user runs `isolait start claude`
- **THEN** the terminal is attached to the agent's interface

### Requirement: Detach and attach
The system SHALL let the user detach from a session with the leader key followed by `d` and reattach later with `isolait attach <sid>`, restoring the agent's display by requesting a redraw.

#### Scenario: Detach
- **WHEN** the user presses the leader key then `d`
- **THEN** the client exits and the session keeps running

#### Scenario: Reattach
- **WHEN** the user runs `isolait attach api-a3f9`
- **THEN** the terminal shows the agent's current interface at the current terminal size

### Requirement: List sessions
The system SHALL list running sessions with id, state (attached, detached, idle), workspaces and age.

#### Scenario: List
- **WHEN** two sessions are running and one is attached
- **THEN** `isolait list` shows both with their states

### Requirement: Session targeting
The system SHALL target the last attached session for commands without `--sid`, SHALL honor `--sid <id>` otherwise, SHALL print the target id when a command grants access, and SHALL fail with the list of sessions when no target can be determined.

#### Scenario: Implicit target
- **WHEN** the user runs `isolait mount ~/shared` with no `--sid` after attaching to `api-a3f9`
- **THEN** the mount is added to `api-a3f9` and the output names that session

#### Scenario: Explicit target
- **WHEN** the user runs `isolait --sid web-1c2d mount ~/shared`
- **THEN** the mount is added to `web-1c2d`

#### Scenario: Stale last-attached
- **WHEN** the last attached session no longer exists and no `--sid` is given
- **THEN** the command fails and lists running sessions

### Requirement: Exec in a running sandbox
The system SHALL run a command inside an existing sandbox on `isolait exec`, attached to the invoking terminal, with the same restrictions as the agent.

#### Scenario: Second shell
- **WHEN** the user runs `isolait exec -- bash` from another terminal
- **THEN** a shell runs inside the sandbox seeing the same mounts and network policy

### Requirement: In-session command prompt
The system SHALL open a command prompt on the leader key followed by `:`, accepting the same commands and arguments as `isolait`, targeting the current session, and showing the result without disturbing the agent's display.

#### Scenario: Add a mount from the prompt
- **WHEN** the user presses the leader key, `:`, types `mount ~/shared` and Enter
- **THEN** the mount is added to the current session and the prompt closes with a result line

#### Scenario: Prompt dismissed
- **WHEN** the user presses Escape in the prompt
- **THEN** nothing changes and the agent's display is redrawn

### Requirement: Leader key from real input only
The system SHALL recognize the leader key only from terminal keyboard input and SHALL NOT recognize it inside bracketed paste, and the leader key SHALL be configurable with default `Ctrl-\`.

#### Scenario: Pasted leader
- **WHEN** pasted text contains the leader byte
- **THEN** it is sent to the agent unchanged and no prompt opens

### Requirement: Agent output sanitizing
The system SHALL filter the agent's output before it reaches the user's terminal, dropping clipboard-write, window-title, device-control and window-manipulation sequences, and SHALL handle sequences split across reads.

#### Scenario: Clipboard sequence
- **WHEN** the agent emits an OSC 52 clipboard write
- **THEN** it is not forwarded to the terminal

#### Scenario: Normal TUI output
- **WHEN** the agent emits ordinary colors and cursor movement
- **THEN** it is forwarded unchanged

### Requirement: Control surface unreachable from sandbox
The system SHALL keep the daemon's control interface unreachable from inside the sandbox, so sandboxed processes cannot grant, revoke or stop anything.

#### Scenario: Agent attempts self-grant
- **WHEN** a sandboxed process searches for and tries to connect to the daemon's control socket
- **THEN** no such socket is reachable
