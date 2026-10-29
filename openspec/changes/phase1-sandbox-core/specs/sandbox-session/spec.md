# Spec Delta

## Purpose

Defines the rootless sandbox an agent runs in: its filesystem, binaries, environment, hardening, identity and lifecycle, so all runtime grants (mounts, ports) attach to a well-defined session.

## ADDED Requirements

### Requirement: Start a rootless session
The system SHALL start an agent command inside a sandbox without root, setuid helpers, or host capabilities, and SHALL refuse to start with an actionable error when a prerequisite is missing (unprivileged user namespaces, `bwrap`, new mount API, `/dev/net/tun`).

#### Scenario: Successful start
- **WHEN** an unprivileged user runs `isolait start claude` in a directory
- **THEN** the agent runs inside a sandbox and the sandboxed processes hold no capabilities

#### Scenario: User namespaces restricted by the host
- **WHEN** the host forbids unprivileged user namespaces (sysctl or AppArmor policy)
- **THEN** start fails before launching the agent and the error names the restriction and how to check it

### Requirement: Session identity
The system SHALL identify each session by an id of the form `<workdir-basename>-<short-hex>` generated at start, stable for the session's lifetime and independent of any mount remaining present.

#### Scenario: Id generated
- **WHEN** a session is started in `/home/u/projects/api`
- **THEN** its id has the form `api-<hex>` and is shown by `isolait list`

#### Scenario: Two sessions, same directory name
- **WHEN** two sessions are started from different directories both named `api`
- **THEN** each gets a distinct id

#### Scenario: Starting workspace unmounted
- **WHEN** the starting workspace mount is removed while the session runs
- **THEN** the session keeps its id and keeps running

### Requirement: Starting workspace mount
The system SHALL mount the starting directory at `/workspaces/<name>`, read-write by default and read-only with `--ro`, and SHALL make it the agent's initial working directory.

#### Scenario: Default read-write
- **WHEN** a session is started without a mode flag
- **THEN** the agent can create and modify files in `/workspaces/<name>`

#### Scenario: Read-only start
- **WHEN** a session is started with `--ro`
- **THEN** writes to `/workspaces/<name>` fail with a read-only error

### Requirement: Isolated filesystem baseline
The system SHALL expose host system directories read-only, a minimal `/etc` (resolver config, CA certificates, user database, name-service config, hosts), memory-backed `/tmp`, and no other host paths beyond explicit mounts.

#### Scenario: Credentials not visible
- **WHEN** the agent looks for the host home directory or `~/.ssh` inside the sandbox
- **THEN** it finds neither

#### Scenario: Ephemeral tmp
- **WHEN** the session ends
- **THEN** nothing written to `/tmp` persists on the host

### Requirement: Persistent sandbox home
The system SHALL give each agent a persistent home directory stored under isolait's state directory and mounted as the sandbox user's home, and SHALL NOT expose the host home directory.

#### Scenario: Login persists
- **WHEN** an agent stores credentials in its sandbox home and the session is restarted
- **THEN** the credentials are still present, and host `~/.claude` was never visible

### Requirement: Binary exposure
The system SHALL make available read-only the system binary directories and the resolved install root of the agent command (following symlinks), SHALL construct the sandbox `PATH` only from mounted locations, and SHALL expose additional host `PATH` directories only on `--inherit-path` or explicit `tools` configuration.

#### Scenario: Agent binary behind a symlink
- **WHEN** `claude` on the host is a symlink into a versioned install directory
- **THEN** the sandbox can run `claude` and the resolved install root is listed in `isolait status`

#### Scenario: Unlisted tool directory
- **WHEN** a host `PATH` directory is neither a system directory nor requested
- **THEN** its binaries are not visible in the sandbox

#### Scenario: Symlink escapes mounted tree
- **WHEN** a requested tool directory contains a symlink whose target is not mounted
- **THEN** start warns that the link will be dangling

### Requirement: Environment allowlist
The system SHALL start the sandbox with only explicitly declared environment variables, SHALL pass the full host environment only with `--inherit-env`, and SHALL never pass an agent-forwarding socket variable unless declared.

#### Scenario: Secrets not inherited
- **WHEN** the host has `AWS_SECRET_ACCESS_KEY` set and the session is started without `--env` or `--inherit-env`
- **THEN** the variable is absent inside the sandbox

#### Scenario: Declared variable
- **WHEN** the session is started with `--env FOO`
- **THEN** `FOO` is present in the sandbox with its host value

### Requirement: Process hardening
The system SHALL run the sandbox with all capabilities dropped, a new terminal session, private pid, ipc, uts and network namespaces, and termination when the daemon exits, and SHALL block creation of nested user namespaces unless `--allow-userns` is given.

#### Scenario: Nested userns blocked
- **WHEN** a sandbox process tries to create a user namespace
- **THEN** it fails

#### Scenario: Opt-in
- **WHEN** the session is started with `--allow-userns`
- **THEN** sandbox processes can create user namespaces

### Requirement: Agent restart and session lifetime
The system SHALL keep the sandbox, its mounts and its port grants alive when the agent process exits, report the session as idle, and relaunch the agent in the same sandbox when the user attaches. The session SHALL live as long as its init process, ending on `isolait stop`, init exit, or daemon failure, and SHALL NOT expire on an idle timeout.

#### Scenario: Agent exits
- **WHEN** the agent process exits
- **THEN** the session remains in `isolait list` as idle with its mounts intact

#### Scenario: No idle expiry
- **WHEN** a session has been idle with no attached client for a long time
- **THEN** it is still running and listed

#### Scenario: Reattach restarts agent
- **WHEN** the user attaches to an idle session
- **THEN** the agent command is started again in the same sandbox

### Requirement: Session status
The system SHALL report for each session its id, state, resolved tool roots, mounts with modes, open ports, and the environment variable names passed in.

#### Scenario: Status shows grants
- **WHEN** a session has a `--ro` mount and one open port and the user runs `isolait status`
- **THEN** the output lists the starting mount, the `ro` mount, and the open port

### Requirement: Stop and cleanup
The system SHALL terminate all sandbox processes and release all mounts, namespaces and runtime state of a session on `isolait stop` or when the session ends.

#### Scenario: Explicit stop
- **WHEN** the user runs `isolait stop api-a3f9`
- **THEN** all its processes are terminated and the session disappears from `isolait list`
