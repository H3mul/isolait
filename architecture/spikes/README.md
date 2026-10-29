# Spikes

Reproducible feasibility spikes for `phase1-sandbox-core`. Process is defined in
`openspec/changes/phase1-sandbox-core/tasks.md` (group 1).

Build the shared image once: `./_common/build.sh` (slow on first run; extra args go to `docker build`).
Each spike: `<task#>-<slug>/{README.md,run.sh,test.sh}`. `./<dir>/run.sh` runs `test.sh` in that
prebuilt image (exit 2 if it is missing); output is `PASS|FAIL|SKIP <criterion>`, exit 1 on any FAIL.
`./run-all.sh` builds, then runs all of them.

Containers use `seccomp=unconfined apparmor=unconfined systempaths=unconfined`, not `--privileged`.
Reproducibility: pass pinned digests via `--build-arg` (see `_common/Dockerfile`).

## Index

| Spike | Verdict | Date | Rerun |
|-------|---------|------|-------|
| 0.0-selftest (harness) | GO | 2026-10-29 | `./0.0-selftest/run.sh` |
| 1.1-mount-propagation | GO | 2026-10-29 | `./1.1-mount-propagation/run.sh` |
| 1.2-mount-locked | GO | 2026-10-29 | `./1.2-mount-locked/run.sh` |
| 1.3-bwrap-slave | GO | 2026-10-29 | `./1.3-bwrap-slave/run.sh` |
| 1.4-ro-clone | GO | 2026-10-29 | `./1.4-ro-clone/run.sh` |
| 1.5-userns-nesting | GO | 2026-10-29 | `./1.5-userns-nesting/run.sh` |
| 1.6-netstack | GO (netstack ~1.5 Gbit/s, +230 us; pasta ~13 Gbit/s) | 2026-10-29 | `./1.6-netstack/run.sh` |
| 1.7-netns-listener | GO | 2026-10-29 | `./1.7-netns-listener/run.sh` |
| 1.8-pty-relay | GO (automated); real agents deferred to 4.2 | 2026-10-29 | `./1.8-pty-relay/run.sh` |
| 1.9-mask-submount | GO | 2026-10-29 | `./1.9-mask-submount/run.sh` |

## Go/no-go (task 1.10)

- **Decision 1 (broker mount namespace with propagation): GO.** 1.1-1.5 and 1.9 pass: propagation, locked ro
  mounts, slave bind, atomic ro clone, `--disable-userns` under nesting, layered masks.
- **Decision 5 (netstack engine, TCP only): GO.** 1.6 passes both gates and the correctness matrix; 1.7
  validates the port-grant model. The `pasta` fallback is not needed; it stays documented in design.md.
- No design.md fallback is triggered. Carried forward, not blocking:
  - Unmounting a workspace with a stacked mask needs mask-first or recursive unmount (1.9).
  - netstack is ~8x slower than pasta on bulk throughput; offload/queue tuning is available if it matters (1.6).
  - Real `npm install` and real Claude Code/OpenCode relay checks happen in 5.6 and 4.2.
  - Running the spikes needs a Docker daemon, the host `tun` driver for 1.6, and network access once for the gVisor module.
