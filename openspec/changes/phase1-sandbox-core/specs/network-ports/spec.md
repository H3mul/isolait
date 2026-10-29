# Spec Delta

## Purpose

Lets a user open and close access from a running sandbox to TCP ports on the host's loopback, as `localhost:<port>` inside the sandbox, while every other host service stays unreachable and no host privileges are required.

## ADDED Requirements

### Requirement: Open a TCP port at runtime
The system SHALL let the user open a single host-loopback TCP port for a running session, reachable inside the sandbox at `127.0.0.1:<port>`, without restarting the agent and without root.

#### Scenario: Open port
- **WHEN** the user runs `isolait allow port 8080` and a host service listens on `127.0.0.1:8080`
- **THEN** the agent can connect to `127.0.0.1:8080` inside the sandbox and reach that service

#### Scenario: No grant
- **WHEN** no grant exists for port 8080
- **THEN** a connection to `127.0.0.1:8080` inside the sandbox is refused

### Requirement: Open a port range
The system SHALL let the user open a contiguous range in one command, SHALL reject inverted ranges and ports outside 1-65535, and SHALL reject ranges larger than the configured maximum.

#### Scenario: Range
- **WHEN** the user runs `isolait allow port 3000-3010`
- **THEN** ports 3000 through 3010 are reachable and no others

#### Scenario: Invalid range
- **WHEN** the user runs `isolait allow port 3010-3000`
- **THEN** the command fails and nothing is opened

#### Scenario: Oversized range
- **WHEN** the requested range exceeds the maximum size
- **THEN** the command fails with the limit named

### Requirement: Close a port at runtime
The system SHALL let the user close an opened port or range, and established connections on it SHALL be terminated.

#### Scenario: Close port
- **WHEN** the user runs `isolait deny port 8080` after opening it
- **THEN** new connections fail and established connections are closed

#### Scenario: Close part of a range
- **WHEN** range 3000-3010 is open and the user closes 3005
- **THEN** 3005 is closed and the other ports in the range stay open

### Requirement: Loopback scope only
The system SHALL connect granted ports only to the host's loopback interface and SHALL NOT forward to other host addresses or networks.

#### Scenario: Service bound to LAN address only
- **WHEN** a host service listens only on a non-loopback address
- **THEN** opening its port does not make it reachable from the sandbox

### Requirement: TCP only
The system SHALL support only TCP port grants and SHALL reject UDP grants with an error stating that UDP is unsupported.

#### Scenario: UDP grant
- **WHEN** the user runs `isolait allow port 5353/udp`
- **THEN** the command fails with an unsupported-protocol error and nothing is opened

### Requirement: Rootless operation
The system SHALL provide port access without root, setuid binaries, or capabilities in the host network namespace.

#### Scenario: Unprivileged user
- **WHEN** an unprivileged user opens a port
- **THEN** the operation succeeds without a privilege prompt

### Requirement: Port state visibility
The system SHALL show open ports and ranges in `isolait status` and print the target session id when granting or revoking.

#### Scenario: Listed ports
- **WHEN** port 8080 and range 3000-3010 are open
- **THEN** `isolait status` lists both
