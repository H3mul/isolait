# Spec Delta

## Purpose

Defines how isolait is configured through a global tier and a workspace-local tier, where local state lives, and how both are kept out of the sandbox and out of reach of untrusted repositories.

## ADDED Requirements

### Requirement: Tiered configuration
The system SHALL read configuration from a global directory (`$XDG_CONFIG_HOME/isolait`, default `~/.config/isolait`) and from a workspace-local `.isolait` directory in the session's starting workspace, and SHALL apply precedence command-line flags, then workspace-local, then global, then built-in defaults.

#### Scenario: Local overrides global
- **WHEN** the global config sets a scalar option and the workspace-local config sets it differently
- **THEN** the workspace-local value is used

#### Scenario: Flag overrides both
- **WHEN** a command-line flag sets the same option
- **THEN** the flag value is used

#### Scenario: List options extend
- **WHEN** both tiers define a list option such as extra tool roots
- **THEN** the effective value contains the entries of both without duplicates

### Requirement: Only the starting workspace's local config applies
The system SHALL load a local config only from the starting workspace and SHALL NOT load or apply `.isolait` content from directories added later by hot-mount or from sub-directories.

#### Scenario: Hot-added workspace with its own config
- **WHEN** a directory containing `.isolait/config` is hot-mounted into a running session
- **THEN** its configuration has no effect on that session

### Requirement: Local config and state location
The system SHALL keep workspace-local configuration and per-workspace state (such as the ids of sessions started there) in the `.isolait` directory, creating it only when needed, and SHALL keep global state outside the workspace.

#### Scenario: First start
- **WHEN** a session is started in a workspace with no `.isolait` directory
- **THEN** the directory is created on demand and holds only isolait's local state

### Requirement: Isolait directories excluded from the sandbox
The system SHALL never expose the global config directory, isolait's state and runtime directories, or any `.isolait` directory to the sandbox, and SHALL mask the `.isolait` directory at the root of every mounted workspace so it appears absent or empty.

#### Scenario: Starting workspace contains .isolait
- **WHEN** the agent lists `/workspaces/<name>/.isolait`
- **THEN** it is absent or empty and writes to it have no effect on the host

#### Scenario: Hot-added workspace contains .isolait
- **WHEN** a directory with `.isolait` is mounted at runtime
- **THEN** its `.isolait` is masked the same way

#### Scenario: Mount request targets an isolait directory
- **WHEN** the user asks to mount `~/.config/isolait` or a `.isolait` directory or anything inside one
- **THEN** the request is refused

### Requirement: Untrusted workspace config is ignored
The system SHALL ignore a workspace-local config file entirely, without partial application, until the user runs `isolait trust` for that exact file content, and SHALL warn at start that an untrusted config was ignored.

#### Scenario: Cloned repository ships a config
- **WHEN** a freshly cloned workspace has `.isolait/config` and the user runs `isolait start`
- **THEN** no setting from it applies, a warning says it was ignored, and the session starts with global and default settings

#### Scenario: Trusted
- **WHEN** the user runs `isolait trust` for the current file content
- **THEN** its settings apply on the next start

#### Scenario: Modified after trust
- **WHEN** a trusted config file's content changes
- **THEN** it is ignored again until re-trusted

#### Scenario: Trust records content, not path
- **WHEN** a trusted file is replaced by a file with different content at the same path
- **THEN** the new content is not trusted

### Requirement: Validation
The system SHALL reject unknown keys and malformed values in any config file with an error that names the file and key, and SHALL NOT start a session on a config error.

#### Scenario: Unknown key
- **WHEN** a config file contains an unrecognized key
- **THEN** start fails and the error names the file and the key
