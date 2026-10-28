# Spec Delta

## Purpose

Defines how a rootless sandbox session for an AI agent is started, named, inspected and stopped, so that all other runtime grants (mounts, ports) attach to a well-defined session.

## ADDED Requirements

### Requirement: Start a rootless session
The system SHALL start an agent command inside a sandbox without requiring root, setuid helpers, or any host capability, and SHALL refuse to start with an actionable error when unprivileged user namespaces are unavailable.

#### Scenario: Successful start
- **WHEN** an unprivileged user runs `isolait start claude` in a directory
- **THEN** the agent runs inside a sandbox and the sandbox process holds no capabilities

#### Scenario: User namespaces restricted by the host
- **WHEN** the host forbids unprivileged user namespaces (sysctl or AppArmor policy)
- **THEN** start fails before launching the agent and the error names the restriction and how to check it

### Requirement: Session naming and identity
The system SHALL name a session after the basename of its starting workspace directory and SHALL give it a stable unique id that does not depend on any mount remaining present.

#### Scenario: Session named after workspace
- **WHEN** a session is started in `/home/u/projects/api`
- **THEN** the session is named `api`

#### Scenario: Name collision
- **WHEN** a session named `api` is already running and another is started in a different directory also named `api`
- **THEN** the new session receives a distinct disambiguated name and both remain addressable

#### Scenario: Starting workspace is unmounted
- **WHEN** the starting workspace mount is removed while the session runs
- **THEN** the session keeps its name and id and continues to run

### Requirement: Starting workspace mount
The system SHALL mount the starting directory at `/workspaces/<name>` in the sandbox, read-write by default and read-only when `--ro` is given, and SHALL set that location as the agent's initial working directory.

#### Scenario: Default read-write
- **WHEN** a session is started without a mode flag
- **THEN** the agent can create and modify files in `/workspaces/<name>`

#### Scenario: Read-only start
- **WHEN** a session is started with `--ro`
- **THEN** writes to `/workspaces/<name>` fail with a read-only error

### Requirement: Isolated baseline
The system SHALL expose host system paths (`/usr`, `/lib`, `/bin` and equivalents) read-only, back `/tmp` with memory-only storage, and expose no other host paths to the sandbox beyond explicit mounts.

#### Scenario: Home directory not visible
- **WHEN** the agent lists the host home directory path inside the sandbox
- **THEN** it does not see the host user's files, including credential directories such as `~/.ssh`

#### Scenario: Ephemeral tmp
- **WHEN** the session ends
- **THEN** nothing written to `/tmp` inside the sandbox persists on the host

### Requirement: Session status
The system SHALL report, for each running session, its name, id, agent process state, current mounts with modes, and currently open ports.

#### Scenario: Status shows grants
- **WHEN** a session has an extra `ro` mount and one open port and the user runs `isolait status`
- **THEN** the output lists the starting mount, the extra mount marked `ro`, and the open port

### Requirement: Stop and cleanup
The system SHALL stop the agent and the session's broker when the session is stopped or the agent exits, and SHALL leave no mounts, namespaces or state belonging to that session behind.

#### Scenario: Agent exits
- **WHEN** the agent process exits
- **THEN** the session is removed from status and its host-side resources are released

#### Scenario: Explicit stop
- **WHEN** the user runs `isolait stop <session>`
- **THEN** the agent is terminated and the session is removed from status
