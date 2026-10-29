# Spec Delta

## Purpose

Lets a user add and remove host directories under `/workspaces` in a running sandbox, in `rw` or `ro` mode, without restarting the agent and without weakening isolation.

## ADDED Requirements

### Requirement: Hot-add a directory
The system SHALL make a host directory visible at `/workspaces/<name>` in a running session on request, read-write by default, without restarting the agent or interrupting its process.

#### Scenario: Add while agent is running
- **WHEN** the user runs `isolait mount ~/projects/shared-core` for a running session
- **THEN** `/workspaces/shared-core` appears in the sandbox, is writable, and the agent process keeps running with its context intact

#### Scenario: Read-only add
- **WHEN** the user runs `isolait mount --ro ~/projects/shared-core`
- **THEN** the directory appears at `/workspaces/shared-core` and writes to it fail with a read-only error

#### Scenario: Read-only is never observably writable
- **WHEN** a directory is added with `--ro`
- **THEN** there is no moment at which it is visible in the sandbox as writable

### Requirement: Hot-remove a directory
The system SHALL remove a mount from `/workspaces` in a running session on request, including the starting workspace, without restarting the agent.

#### Scenario: Remove an added mount
- **WHEN** the user runs `isolait unmount shared-core`
- **THEN** `/workspaces/shared-core` is no longer visible in the sandbox

#### Scenario: Switch workspaces
- **WHEN** the user unmounts the starting workspace and mounts a different directory
- **THEN** the session continues and only the new directory is visible under `/workspaces`

#### Scenario: Removal of a busy mount
- **WHEN** the user unmounts a directory that a sandbox process is using as its working directory or has open files in
- **THEN** the command fails and identifies the blocking process, unless `--force` is given

#### Scenario: Forced removal
- **WHEN** the user unmounts a busy directory with `--force`
- **THEN** the mount is detached from the sandbox view and processes holding it lose access to new lookups

### Requirement: Grant visibility
The system SHALL print the target session id when a mount is added or removed, and SHALL show current mounts and their modes in `isolait status`.

#### Scenario: Echoed target
- **WHEN** the user runs `isolait mount ~/shared` while two sessions exist
- **THEN** the output names the session that received the mount

### Requirement: Mount naming
The system SHALL place each mount at `/workspaces/<name>` where `<name>` defaults to the source directory's basename, MAY be overridden with `--as`, and SHALL reject names that are empty, contain `/`, or equal `.` or `..`.

#### Scenario: Name collision
- **WHEN** the requested name is already in use under `/workspaces`
- **THEN** the add fails with an error naming the conflict and no mount is created

#### Scenario: Invalid name
- **WHEN** `--as ../etc` is given
- **THEN** the add fails and no mount is created

### Requirement: Source validation
The system SHALL validate the source as a directory by the identity of the opened object, not by a path string checked earlier, and SHALL reject sources that are not directories.

#### Scenario: Symlink swapped after check
- **WHEN** the source path is replaced by a symlink between validation and mounting
- **THEN** the mount is made from the object that was validated, or the add fails; never from the swapped target

#### Scenario: Source is a file
- **WHEN** the source path is a regular file
- **THEN** the add fails with a not-a-directory error

### Requirement: Protected-path deny list
The system SHALL refuse to mount `/`, the user's home directory, any ancestor of a protected path, and protected paths themselves, including credential directories (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config`), `/proc`, `/sys`, `/dev`, `/run`, isolait's state and global config directories, and any `.isolait` directory.

#### Scenario: Mounting home
- **WHEN** the user asks to mount `$HOME`
- **THEN** the add is refused with an error explaining that it contains protected paths

#### Scenario: Mounting a protected path
- **WHEN** the user asks to mount `~/.ssh`
- **THEN** the add is refused

### Requirement: Isolait directory masked in mounts
The system SHALL mask a `.isolait` directory at the root of every mounted directory, so that it appears absent or empty inside the sandbox and the sandbox cannot read or change it.

#### Scenario: Added directory contains .isolait
- **WHEN** a directory containing `.isolait` is added with `isolait mount`
- **THEN** `.isolait` is absent or empty at `/workspaces/<name>/.isolait`

### Requirement: Non-recursive mounts
The system SHALL expose only the requested directory's own filesystem, and SHALL NOT expose other filesystems mounted beneath it on the host.

#### Scenario: Host submount under source
- **WHEN** a host filesystem or bind mount (for example a secrets mount) exists beneath the source directory
- **THEN** that submount's contents are not visible inside the sandbox

### Requirement: Hardened mount flags
The system SHALL mount every directory with `nosuid` and `nodev`, and SHALL ensure the sandbox cannot remount a mount read-write, change its flags, or create new mounts.

#### Scenario: Remount attempt
- **WHEN** a process in the sandbox tries to remount a `ro` mount as read-write
- **THEN** the attempt fails

#### Scenario: Device node in mounted directory
- **WHEN** a mounted host directory contains a device node
- **THEN** opening it from the sandbox does not grant device access

### Requirement: Mount safety against the sandbox
The system SHALL perform all mount and unmount operations from outside the sandbox, and SHALL NOT give any process inside the sandbox mount capability.

#### Scenario: Agent tries to mount
- **WHEN** a process in the sandbox attempts `mount`
- **THEN** it fails with a permission error
