# Spec Delta

## Purpose

Lets a user open and close access from a running sandbox to host localhost TCP and UDP ports and port ranges, while the sandbox stays network-isolated by default and no host privileges are required.

## ADDED Requirements

### Requirement: Network deny by default
The system SHALL start sessions with no network access to the host or to external networks, other than ports explicitly opened.

#### Scenario: Unopened localhost port
- **WHEN** the agent connects to `127.0.0.1:8080` and no grant exists
- **THEN** the connection fails

#### Scenario: External address
- **WHEN** the agent connects to an external address
- **THEN** the connection fails

### Requirement: Open a port at runtime
The system SHALL let the user open a single TCP or UDP port on host localhost for a running session, without restarting the agent and without root.

#### Scenario: Open TCP port
- **WHEN** the user runs `isolait allow port 8080` and a host service listens on `127.0.0.1:8080`
- **THEN** the agent can connect to `127.0.0.1:8080` and reach that service

#### Scenario: Open UDP port
- **WHEN** the user runs `isolait allow port 5353/udp`
- **THEN** UDP traffic to host `127.0.0.1:5353` from the sandbox is delivered

#### Scenario: Protocol default
- **WHEN** no protocol is given
- **THEN** the port is opened for TCP only

### Requirement: Open a port range
The system SHALL let the user open a contiguous range of ports in one command, and SHALL reject ranges that are inverted or outside 1-65535.

#### Scenario: Range
- **WHEN** the user runs `isolait allow port 3000-3010`
- **THEN** all ports 3000 through 3010 are reachable and no others

#### Scenario: Invalid range
- **WHEN** the user runs `isolait allow port 3010-3000`
- **THEN** the command fails and nothing is opened

### Requirement: Close a port at runtime
The system SHALL let the user close a previously opened port or range, and existing connections on it SHALL be terminated.

#### Scenario: Close port
- **WHEN** the user runs `isolait deny port 8080` after opening it
- **THEN** new connections to it fail and established connections are closed

#### Scenario: Close part of a range
- **WHEN** a range 3000-3010 is open and the user closes 3005
- **THEN** 3005 is closed and the remaining ports in the range stay open

### Requirement: Localhost scope only
The system SHALL scope opened ports to the host loopback interface only, and SHALL NOT forward traffic to other host addresses or the wider network.

#### Scenario: Non-loopback target
- **WHEN** a host service listens only on a non-loopback address
- **THEN** opening its port does not make it reachable from the sandbox

### Requirement: Rootless operation
The system SHALL provide port access without root, setuid binaries, or capabilities in the host network namespace.

#### Scenario: Unprivileged user
- **WHEN** a user with no elevated privileges opens a port
- **THEN** the operation succeeds without a privilege prompt

### Requirement: Port state visibility
The system SHALL show open ports and ranges, with protocol, in `isolait status`.

#### Scenario: Listed ports
- **WHEN** ports 8080/tcp and 3000-3010/tcp are open
- **THEN** `isolait status` lists both
