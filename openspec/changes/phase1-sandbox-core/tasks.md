# Tasks

## 1. Feasibility spikes (documented, reproducible, containerised; no product code)

Process, applied to every spike:
- Layout: `architecture/spikes/<task#>-<slug>/` holds `README.md` (question, approach, pass/fail criteria, how to run, recorded result with date, kernel and tool versions, verdict, and the design fallback if it fails), `run.sh` (host entry point: builds the image and runs the container) and `test.sh` (runs inside the container, prints one `PASS|FAIL <criterion>` line per criterion, exits non-zero on any FAIL). The spike for task `1.N` lives in `1.N-<slug>`; tasks that share a topic still get their own directory and cross-link.
- Environment: everything runs in Docker. Shared base image in `architecture/spikes/_common/` (pinned Debian digest, bwrap, iproute2, util-linux, iperf3, Go 1.27 via pinned toolchain image). Containers run `--security-opt seccomp=unconfined --security-opt apparmor=unconfined --security-opt systempaths=unconfined` (Docker's default profile blocks `unshare`, `mount` and `open_tree`, and masks `/proc`), never `--privileged`, so a pass shows the feature needs no more than unprivileged userns. Each `run.sh` states any extra flag (for example `--device /dev/net/tun`) and why.
- Determinism: pinned image digests and Go module versions; no network except where a spike's question is the network (1.6, 1.7), and then only to a local fixture container, not the internet; fixed inputs, no sleeps for synchronisation (poll with a timeout). Benchmarks (1.6) record raw numbers as JSON, run N=5 and compare the median against a threshold declared in the README.
- Honest verdicts: a criterion that cannot run on this host (for example `/dev/net/tun` is absent here) reports `SKIP <reason>`, never PASS; the README records the host kernel/WSL2 status and what is still unverified.
- Index: `architecture/spikes/README.md` lists every spike with its verdict (GO / NO-GO / PARTIAL), date and the command to rerun; `make -C architecture/spikes all` (or `./run-all.sh`) reruns the lot.

- [x] 1.0 Spike harness: `_common/Dockerfile`, `_common/lib.sh` (`pass`/`fail`/`skip` helpers and the exit-code rule), `architecture/spikes/README.md` index and `run-all.sh`; verify with a trivial self-test spike that PASS, FAIL and SKIP map to exit codes and that the image builds from a clean cache
- [x] 1.1 `1.1-mount-propagation`: with `unshare -Urm` + `bwrap` in the container, a mount made in the broker ns under a shared `stage/` appears in the sandbox; criteria, run and result in its README
- [x] 1.2 `1.2-mount-locked`: the sandbox cannot remount a propagated mount rw (`MNT_LOCKED`) and unmount propagates; reuses 1.1's fixture via `_common`
- [x] 1.3 `1.3-bwrap-slave`: bwrap keeps `/workspaces` as a slave bind (or find the flag/wrapper); record the exact bwrap argv that works
- [ ] 1.4 `1.4-ro-clone`: `open_tree` + `mount_setattr(RDONLY)` + `move_mount` yields a never-writable ro mount (tiny Go probe, a writer goroutine polls during attach to prove no rw window)
- [ ] 1.5 `1.5-userns-nesting`: `--disable-userns` works under the broker's extra userns nesting; a nested `unshare -U` inside the sandbox must fail
- [ ] 1.6 `1.6-netstack`: tap in a sandbox netns driven by gVisor netstack (TCP forward + DNS) vs `pasta`, with a local fixture server container instead of the internet; iperf3 throughput and latency, pass at >= 500 Mbit/s and added p50 < 1 ms; correctness matrix (streaming HTTP, a local npm registry and git server for `npm install`/`git clone`, DNS, closed-port refusal); `/dev/net/tun` availability (SKIP with reason if absent) and the gVisor build under Go 1.27 (pinned module version)
- [ ] 1.7 `1.7-netns-listener`: a locked thread can `setns` into the sandbox netns, listen on loopback, and forward to host loopback; Go probe plus an assertion that the connection reaches the host-side fixture
- [ ] 1.8 `1.8-pty-relay`: PTY relay with `SIGWINCH` redraw. Deterministic part: scripted fake TUIs (an inline one and an alt-screen one emitting `?1049h`) driven through the relay under a PTY in the container, asserting the final screen via a pty screen-scrape. Manual part: a checklist in the README for Claude Code and OpenCode, with results pasted in and marked as manual
- [ ] 1.9 `1.9-mask-submount`: an empty ro bind layered over a propagated workspace mount shows empty in the sandbox, survives hot-add of a sibling, and unmounts cleanly with its parent
- [ ] 1.10 Go/no-go for design Decisions 1 and 5 from the index verdicts; if either fails, update `design.md` to its fallback before continuing, and note any SKIPped criteria as accepted risk or follow-up

## 2. Project scaffold and preflight

- [ ] 2.1 Create Go module, cobra root command and `isolait version`; verify `go build ./... && ./isolait version`
- [ ] 2.2 Implement preflight (bwrap >= 0.8, unprivileged userns, new mount API, `/dev/net/tun`) with actionable errors; verify unit tests faking each failure
- [ ] 2.3 Config loader: global and workspace tiers, precedence, list extension, validation errors naming file and key; verify table-driven unit tests
- [ ] 2.4 `isolait trust`: content-hash trust store in global state; an untrusted workspace config is ignored entirely with a warning, a content change revokes trust; verify unit tests including a hostile cloned-repo config
- [ ] 2.5 Document the config tiers, keys and trust model in `docs/config.md`; verify every documented key is accepted by the loader

## 3. Session core (daemon, sandbox, baseline)

- [ ] 3.1 Re-exec the binary as broker with `CLONE_NEWUSER|CLONE_NEWNS` and identity uid map; verify integration test: broker sees the host fs, has caps only in its own ns
- [ ] 3.2 Session id generation, runtime and state dirs, control socket (0700, not mounted in sandbox); verify unit tests for id format and collisions
- [ ] 3.3 Launch bwrap with ro system dirs, minimal `/etc`, tmpfs `/tmp`, persistent per-agent home, dropped caps, `--new-session`, `--die-with-parent`, `--unshare-*`, `--disable-userns` (opt-out `--allow-userns`); verify integration test: no `~/.ssh`, `mount` fails, userns creation fails, `/tmp` not persisted
- [ ] 3.4 Environment allowlist (`--env`, `--inherit-env`); verify integration test: host secret absent by default
- [ ] 3.5 Binary exposure: system dirs, symlink-resolved agent root, `--inherit-path` filtering with dangling-link warnings, `tools` config, sandbox `PATH` from mounted dirs; verify tests with a symlinked agent binary
- [ ] 3.6 Init shim as PID 1 spawning processes on request via PTY fds; verify an agent can be exited and respawned in the same sandbox without losing mounts
- [ ] 3.7 Mount the starting directory at `/workspaces/<name>` (rw default, `--ro`), set cwd; verify rw and ro integration tests
- [ ] 3.8 `list`, `status`, `stop` and idle-session handling (sessions live as long as init, no idle timeout); verify cleanup of all mounts, namespaces and state
- [ ] 3.10 Mask the root `.isolait` in the starting workspace and keep the global config, state and runtime dirs out of the sandbox; verify integration test that the agent cannot read or write them
- [ ] 3.9 Document session commands and baseline in `README.md`; verify examples run as written

## 4. Terminal: attach, detach, exec, prompt

- [ ] 4.1 PTY ownership in the daemon with a single output path (scrollback seam); verify unit test that all output flows through it
- [ ] 4.2 Client raw-mode relay with resize forwarding and redraw on attach; verify on Claude Code and an alt-screen agent
- [ ] 4.3 Output sanitizer state machine (OSC 52, title/report, DCS/APC/PM, window-manipulation CSI, split sequences); verify table-driven unit tests including split reads and benign sequences
- [ ] 4.4 Leader key handling (default `Ctrl-\`, configurable, ignored in bracketed paste) and detach; verify tests and manual detach/attach
- [ ] 4.5 `start`/`attach` daemon flow, `isolait exec`, last-attached pointer, `--sid`, grant echo, stale-target error; verify integration tests
- [ ] 4.6 Leader prompt on the bottom row running the CLI command grammar for the current session, with alt-screen-aware redraw; verify manual and scripted tests
- [ ] 4.7 Document attach, detach, exec and the prompt (including "no scrollback; run attach inside tmux/screen if wanted") in `README.md`; verify examples

## 5. Network egress (netd)

- [ ] 5.1 `netd` subcommand with seccomp, started by the broker, no mount authority; verify it cannot mount and the broker cannot be signaled by sandbox code
- [ ] 5.2 Netns bring-up: bwrap `--block-fd`/`--info-fd`, tap creation and configuration before release; verify the guest sees only the managed interface, IPv6 disabled
- [ ] 5.3 TCP forwarder with dial-before-handshake semantics; verify refused upstream yields connection-refused
- [ ] 5.4 DNS answerer using the host resolver (UDP and TCP/53); verify name lookups; non-DNS UDP, ICMP and IPv6 dropped
- [ ] 5.5 Dial-time destination policy blocking loopback, private, CGNAT, link-local, multicast, metadata, host addresses; verify tests including names resolving to private addresses
- [ ] 5.6 Milestone: agent started via `isolait start` reaches its API and completes a task end to end; verify manually and record in `architecture/spikes/e2e.md`
- [ ] 5.7 Document egress behavior and limitations (TCP only, IPv4 only, no ICMP) in `README.md`; verify examples

## 6. Hot mounts

- [ ] 6.1 fd-based source validation and protected-path deny list (dev+inode); verify unit tests for symlink swap, file source, home/ancestor/protected paths
- [ ] 6.2 Mount name rules and collision errors; verify unit tests
- [ ] 6.3 Add: non-recursive `open_tree`, `mount_setattr` (nosuid, nodev, ro), `move_mount` into stage; verify integration tests: visible while the agent runs, ro never observable as writable, host submounts hidden, device nodes unusable, remount fails
- [ ] 6.4 Remove with busy-process detection and `--force`; verify busy, forced and workspace-switch flows
- [ ] 6.7 Mask `.isolait` in hot-added directories and refuse mounting isolait directories; verify integration and unit tests
- [ ] 6.5 CLI `mount [--ro] [--as]` and `unmount [--force]`, available from the leader prompt; verify end to end
- [ ] 6.6 Document mount commands and residual risks in `README.md`; verify examples

## 7. Network ports

- [ ] 7.1 Port and range parsing and validation (`8080`, `3000-3010`, UDP rejected, range cap); verify unit tests
- [ ] 7.2 Listeners on the sandbox loopback created by `netd` and forwarded to host `127.0.0.1`; verify integration test: reachable only after allow, refused otherwise, non-loopback host services unreachable
- [ ] 7.3 Close single and partial ranges, terminating connections; verify tests
- [ ] 7.4 CLI `allow port` / `deny port`, status display, grant echo; verify end to end
- [ ] 7.5 Document ports and the attribution caveat in `README.md`; verify examples

## 8. Integration

- [ ] 8.1 End-to-end script: start, detach, attach, exec, add and remove mounts, open and close a port, agent restart, stop; verify it passes on native Linux and WSL2
- [ ] 8.2 Isolation regression suite (no caps, no mount, no host paths, no unapproved network, no control-socket access, no nested userns); verify in CI, including the sysctl step needed for restricted-userns runners

## Workflow follow-up

- (done) `openspec/config.yaml` updated for the Phase 1 and Phase 2 decisions.
- Create the real Phase 2 specs and tasks from `phase2-git-rw-and-devices`.
- Archive this change after review.
