# Spikes

Reproducible feasibility spikes for `phase1-sandbox-core`. Process is defined in
`openspec/changes/phase1-sandbox-core/tasks.md` (group 1).

Each spike: `<task#>-<slug>/{README.md,run.sh,test.sh}`. `./<dir>/run.sh` builds the shared
image (`_common/`) and runs `test.sh` in a container; output is `PASS|FAIL|SKIP <criterion>`,
exit 1 on any FAIL. `./run-all.sh` runs all of them.

Containers use `seccomp=unconfined apparmor=unconfined systempaths=unconfined`, not `--privileged`.
Reproducibility: pass pinned digests via `--build-arg` (see `_common/Dockerfile`).

## Index

| Spike | Verdict | Date | Rerun |
|-------|---------|------|-------|
| 0.0-selftest (harness) | GO | 2026-10-29 | `./0.0-selftest/run.sh` |
| 1.1-mount-propagation | GO | 2026-10-29 | `./1.1-mount-propagation/run.sh` |
| 1.2-mount-locked | GO | 2026-10-29 | `./1.2-mount-locked/run.sh` |
| 1.3-bwrap-slave | GO | 2026-10-29 | `./1.3-bwrap-slave/run.sh` |
