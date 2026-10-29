# Spec Delta

## Purpose

Gives the sandboxed agent outbound internet access over TCP (so it can reach its model API and fetch dependencies) while denying access to the host, the local network and metadata services, enforced outside the sandbox.

## ADDED Requirements

### Requirement: Outbound TCP to the internet
The system SHALL allow sandboxed processes to make outbound TCP connections to public internet addresses over IPv4 without any host privilege.

#### Scenario: API reachable
- **WHEN** the agent connects to a public HTTPS endpoint
- **THEN** the connection succeeds

#### Scenario: Large transfer
- **WHEN** the sandbox downloads a package archive from a public host
- **THEN** the transfer completes without errors

### Requirement: Private and local ranges blocked
The system SHALL refuse connections whose destination, after name resolution, is loopback, private (RFC 1918), carrier-grade NAT, link-local, multicast or cloud-metadata address space, including the host's own addresses and the host gateway.

#### Scenario: LAN address
- **WHEN** the agent connects to `192.168.1.1`
- **THEN** the connection fails

#### Scenario: Metadata endpoint
- **WHEN** the agent connects to `169.254.169.254`
- **THEN** the connection fails

#### Scenario: Name resolving to a private address
- **WHEN** the agent connects to a hostname whose DNS answer is a private address
- **THEN** the connection fails

#### Scenario: Host address
- **WHEN** the agent connects to the host's LAN IP on a listening port
- **THEN** the connection fails

### Requirement: DNS resolution
The system SHALL answer the sandbox's DNS queries (UDP and TCP port 53 to the configured resolver address) using the host's resolver, without exposing the host resolver address to the sandbox.

#### Scenario: Name lookup
- **WHEN** the agent resolves `api.anthropic.com`
- **THEN** it receives the host-resolved public addresses

### Requirement: Connection semantics
The system SHALL report connection failure to the sandboxed process as a refused or unreachable error rather than a successful connect followed by a reset.

#### Scenario: Closed remote port
- **WHEN** the agent connects to a public address and port that refuses connections
- **THEN** the connect call fails with connection refused

### Requirement: Unsupported traffic dropped
The system SHALL drop IPv6, ICMP and UDP other than DNS, and SHALL state this limitation in documentation.

#### Scenario: UDP service
- **WHEN** the agent sends a non-DNS UDP datagram
- **THEN** it is not delivered

#### Scenario: QUIC client
- **WHEN** an HTTP/3-capable client cannot use UDP
- **THEN** it falls back to TCP and the request succeeds

### Requirement: Enforcement outside the sandbox
The system SHALL enforce network policy in a process outside the sandbox that sandboxed code cannot signal, reconfigure or bypass, and SHALL give the sandbox no network device other than the managed one.

#### Scenario: Agent tries to alter routing
- **WHEN** a sandboxed process attempts to change interfaces, routes or firewall rules
- **THEN** the attempt fails with a permission error

### Requirement: Isolation from host networking
The system SHALL NOT share the host network namespace with the sandbox.

#### Scenario: Host loopback service
- **WHEN** a host service listens on `127.0.0.1:5432` and no port grant exists
- **THEN** the sandbox cannot connect to it by any address
