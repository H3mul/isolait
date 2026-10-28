# Tasks

## 1. Feasibility spikes (shell, no repo code)

- [ ] 1.1 Spike: with `unshare -Urm` + `bwrap`, verify a mount made in the broker ns under a shared `stage/` appears inside the bwrap sandbox; record results in `docs/spikes/mount-propagation.md`
- [ ] 1.2 Spike: verify the sandbox cannot remount a propagated mount rw (`MNT_LOCKED`), and that unmount propagates; record in the same doc
- [ ] 1.3 Spike: verify bwrap keeps `/workspaces` as a slave bind (or find the needed flag/wrapper); record in the same doc
- [ ] 1.4 Spike: verify `open_tree` + `mount_setattr(RDONLY)` + `move_mount` yields a never-writable ro mount; record in the same doc
- [ ] 1.5 Spike: verify a broker thread can `setns` into the sandbox netns, listen, and forward to host loopback; record in the same doc
- [ ] 1.6 Decide go/no-go for design Decision 1; if no-go, update design.md to the nsenter fallback before continuing

## 2. Project scaffold and preflight

- [ ] 2.1 Create Go module, cobra root command and `isolait version`; verify `go build ./... && ./isolait version` works
- [ ] 2.2 Implement preflight (bwrap present, unprivileged userns allowed, kernel new-mount-API support) with actionable errors; verify with unit tests faking each failure

## 3. Sandbox session

- [ ] 3.1 Re-exec the binary as broker with `CLONE_NEWUSER|CLONE_NEWNS` and identity uid map; verify via integration test that broker sees the host fs and has caps only in its own ns
- [ ] 3.2 Launch bwrap sandbox from the broker with ro system paths, tmpfs `/tmp`, no home, dropped caps, `--unshare-net`; verify integration test: no `~/.ssh` visible, `mount` fails, `/tmp` not persisted
- [ ] 3.3 Mount starting dir at `/workspaces/<name>` (rw default, `--ro` opt-in), set cwd; verify rw/ro integration tests
- [ ] 3.4 Session id, name derivation and collision handling, runtime state dir; verify unit tests
- [ ] 3.5 Broker control socket API and CLI `start`, `status`, `stop`; verify status lists mounts and ports, stop and agent-exit clean up all resources
- [ ] 3.6 Document session commands in `README.md` and verify examples run as written

## 4. Hot mounts

- [ ] 4.1 Implement fd-based source validation and the protected-path deny list (dev+inode); verify unit tests for symlink swap, file source, home/ancestor/protected paths
- [ ] 4.2 Implement mount name rules and collision errors; verify unit tests
- [ ] 4.3 Implement add: non-recursive `open_tree`, `mount_setattr` (nosuid, nodev, ro), `move_mount` into stage; verify integration tests: visible while agent runs, ro never observable as writable, host submounts hidden, device nodes unusable
- [ ] 4.4 Implement remove with busy-process detection and `--force` lazy detach; verify integration tests for busy, forced and workspace-switch flows
- [ ] 4.5 Wire CLI `mount [--ro] [--as]` and `unmount [--force]`; verify end to end against a running session
- [ ] 4.6 Document mount commands and residual risks in `README.md` and verify examples run as written

## 5. Network ports

- [ ] 5.1 Implement port/range parsing and validation (`8080`, `5353/udp`, `3000-3010`); verify unit tests including inverted and out-of-range
- [ ] 5.2 Implement TCP forwarding via broker-held listeners in the sandbox netns to host loopback; verify integration test: reachable only after allow, closed ports refuse
- [ ] 5.3 Implement UDP forwarding with per-flow association and idle timeout; verify integration test with a UDP echo service
- [ ] 5.4 Implement close (single and partial-range) terminating active connections; verify integration tests
- [ ] 5.5 Wire CLI `allow port` / `deny port` and port display in `status`; verify end to end
- [ ] 5.6 Document port commands and attribution caveat in `README.md` and verify examples run as written

## 6. Integration

- [ ] 6.1 End-to-end script: start a session, add and remove mounts, open and close a port, stop; verify it passes on native Linux and on WSL2
- [ ] 6.2 Isolation regression checks (no capabilities, no mount, no host paths, no unapproved network); verify they pass in CI

## Workflow follow-up

- Update `openspec/config.yaml` roadmap text (Phase 1 scope, nsenter replaced, `git-rw` in Phase 2).
- Create the Phase 2 change for `git-rw`, SNI/DNS filtering, USB and socket mounting.
- Archive this change after review.
