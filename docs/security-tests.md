# Security regression tests

Each row ties an assumption validated by a feasibility spike (in the openspec store, `phase1-sandbox-core/spikes`
and `sandbox-hardening/spikes`) to the Go test that guards it in this repository, and to the mutation that proves
the test fails when the assumption is broken. Rule: a task that implements a spike-validated mechanism adds its
row and its test in the same change.

## Running

| Command | What it runs | When |
|---|---|---|
| `make check` | `gofmt` and `go vet` (both tiers) | every change |
| `make test` | **fast tier** under `-race`: units, parsers, protocol, plan; no kernel features | every change |
| `make security` | fast tier plus the **security tier** (`-tags security`): the real sandbox on the real kernel; tests `t.Skip` with a reason when a host feature is missing, never pass vacuously | every change where user namespaces work; CI |
| `make canary` | only the **host-assumption canaries** (`internal/canary`) | after a kernel, bwrap or systemd upgrade, and in CI |
| `make mutations` | applies every mutation below to a scratch copy and requires a test to fail | when you touch a guard test or a guarded line; before a release |

CI (`.github/workflows/ci.yml`) runs `make check`, `make test`, `make security` and `make canary`; it lifts Ubuntu
24.04's AppArmor userns restriction for the test run only. The workflow has not run on GitHub yet.

**Canaries** are small tests of the kernel, bwrap and systemd behaviours the design depends on. They use bwrap and
the mount primitive directly and almost none of the product, so an upgrade that changes a behaviour fails them even
when no isolait code changed. **Mutations** (`scripts/mutations.py`) are deliberate regressions; the runner fails
on a survivor, on a target string that no longer exists in the source, and on a mutation that does not compile.

**Rule:** a task that implements a spike-validated mechanism adds its matrix row, its test and, where a guarded
line exists, its mutation in the same change.

## Matrix

| Spike | Assumption | Design decision | Guard test | Mutation that must fail it | Tier |
|---|---|---|---|---|---|
| 1.1 | The broker is uid 0 with `CAP_SYS_ADMIN` inside its own user namespace only: sees the host fs, can mount, owns the caller's files, cannot change host state, and its mounts never reach the host | Decision 1 (broker mount namespace) | `broker.TestBrokerNamespace` | drop `CLONE_NEWNS` or the uid map (verified: tests fail) | security |
| 1.1 | The broker recipe has not drifted: caller mapped to uid/gid 0 (bwrap refuses to run with capabilities unless uid 0), no ambient caps, setgroups denied, own session | Decision 1 | `broker.TestCommandRecipe` | change any recipe field (verified: drop `CLONE_NEWNS`) | fast |
| hardening D5 | Every mount argument is rendered from one `plan.Plan`; nothing else builds bwrap mount flags, so the plan used by the mountinfo check cannot drift from what is mounted | Mount plan as single source (`sandbox-hardening` Decision 5) | `plan.TestNoMountArgumentsOutsidePlan` | add a file containing `"--bind"` outside `internal/plan` (verified: test fails naming the file) | fast |
| hardening D5 | The plan renders the exact argv, only real mounts are mount entries, bad paths and shadowing entries are rejected | Decision 5 | `plan.TestArgsRenderExactly`, `plan.TestAddRejects` | change an argument mapping in `Plan.Args` | fast |
| 1.5 | Nested user namespaces are blocked in the sandbox even under the broker's own nesting; the control run with `--allow-userns` can create one, so the denial is not vacuous | Decision 7 (hardening) | `sandbox.TestBaselineIsolation`, `sandbox.TestNestedUsernsOptIn` | drop `--disable-userns` (verified: `userns = "allowed"`) | security |
| 1.3 | The baseline sandbox: no capabilities, private PID namespace with the init command as PID 1, no network device except loopback, host home and secrets invisible, mount denied, host uid/gid preserved, agent home persists | Decision 7 | `sandbox.TestBaselineIsolation` | drop `--unshare-net` (verified: `nics = 12`) | security |
| hardening | Hardening flags are all present and `--allow-userns` is the only thing that removes `--disable-userns` | Decision 7 | `sandbox.TestHardeningFlags` | drop any flag (verified: `--disable-userns`, `--unshare-net`, `--clearenv`) | fast |
| hardening | Environment allowlist: host secrets absent by default, declared names pass, `--inherit-env` still drops agent sockets unless named | Decision 7 | `sandbox.TestBuildEnv`, `sandbox.TestEnvAllowlistInSandbox` | make `BuildEnv` forward the host environment by default | fast + security |
| 1.3 | `/tmp` is memory-backed: nothing written in one session is visible in the next | Decision 7 | `sandbox.TestTmpDoesNotPersistAcrossSessions` | bind a host directory at `/tmp` | security |
| hardening D5 | The baseline plan exposes only system dirs, minimal `/etc` and the two writable binds (agent home, stage); never the host home, `/`, `/root` or `/run` | Decision 5 | `sandbox.TestBaselinePlanExposesOnlyWhatItShould` | add a bind of `$HOME` to `BuildPlan` | fast |
| 1.4 | A workspace is a non-recursive clone made with `open_tree` + `mount_setattr` + `move_mount`: `nosuid`, `nodev`, read-only from its first visible instant, host submounts not carried along | Decision 2 (fd-based atomic clone) | `mounts.TestWorkspaceMountPrimitive` | drop the `RDONLY` attr; add `AT_RECURSIVE` (verified: both fail) | security |
| 1.9 | The `.isolait` directory at a workspace root is masked by an empty read-only layer; the host copy is untouched; a symlinked or non-directory `.isolait` is refused and nothing stays mounted; a failed mask rolls the workspace back; lazy unmount removes a workspace with its mask stacked on it | Decision 8 (config exclusion) | `mounts.TestWorkspaceMountPrimitive` | skip the mask (verified: six assertions fail) | security |
| 1.1, 1.3 | The starting directory appears at `/workspaces/<name>`, rw by default and ro with `--ro`, is the working directory, and its `.isolait` is empty and unwritable from inside while the host copy is unchanged | Spec: Starting workspace mount | `sandbox.TestStartingWorkspace` | mount the workspace without the mask or ro flag | security |
| hardening | Config, state and runtime dirs are never in the plan, nor an ancestor of a planned bind (only the one per-agent home and the stage inside them) | Decision 8 | `sandbox.TestIsolaitDirsNeverExposed` | bind `$XDG_STATE_HOME/isolait` instead of the per-agent home | fast |
| hardening | Only the system dirs, the agent's resolved install root, explicit `tools` and (opt-in) filtered host PATH entries are exposed; a generic `bin` launcher dir is never bound wholesale; symlinks to unmounted targets warn | Spec: Binary exposure | `sandbox.TestAgentBehindSymlink`, `TestAgentInGenericBinDirBindsOnlyTheFile`, `TestInheritPathFilter`, `TestToolsRootsAndDedupe`, `TestDanglingLinksWarn` | make `--inherit-path` unconditional (verified: five assertions fail, incl. `/opt` dirs on this host) | fast |
| hardening | End to end on the real kernel: an agent behind a symlink runs by name, the launcher dir and unrequested PATH dirs are invisible, `--inherit-path` exposes only the allowed one | Spec: Binary exposure | `sandbox.TestBinaryExposure` | never expose the agent's install root (verified: agent no longer runs) | security |
| 1.3 | The init shim is PID 1 in the sandbox; the agent can exit and be started again with mounts, `/tmp` and workspaces intact; orphans are reaped (no zombies); a fast exit is always attributed and reported after "started" | Decision 4 (init shim) | `sandbox.TestInitShimLifecycle`, `initshim.TestManyFastExits`, `initshim.TestRespawnInSameShim` | disable the reaper (verified: exit never reported, test fails after 10 s) | security + fast |
| hardening | A shim that is not PID 1 never broadcasts `kill(-1)`; shutdown from the test shim leaves an unrelated process alive | Decision 4 | `initshim.TestShutdownLeavesUnrelatedProcessesAlone` | call `kill(-1, SIGKILL)` unconditionally in `killAll` (would kill the user's session; the test guards it) | fast |
| hardening | The shim ends when the daemon's control socket closes, and shutdown kills its children; bad requests do not kill it | Decision 4 | `initshim.TestShimEndsWhenDaemonDisappears`, `TestShutdownKillsChildren`, `TestBadRequestsDoNotKillTheShim` | ignore EOF on the control socket | fast |
| hardening D5 | A healthy sandbox's live mountinfo matches its plan exactly: every planned mount with the right filesystem, device, source path and flags (nosuid, nodev, ro where planned), host submounts under bwrap's recursive binds accounted for, `/dev` children allowed, nothing unplanned or stacked | Decision 5 (start-time verification) | `mountcheck.TestHealthySandboxMatchesItsPlan`, `sandbox.TestLaunchVerifiesAllBindKinds`, `sandbox.TestInitShimLifecycle` | change a comparison rule in `Compare` | fast + security |
| hardening D5 | Every kind of mismatch is reported: injected bind, missing mount, `ro` omitted, `nosuid` omitted, wrong source dir on the right device, wrong filesystem, dropped or writable host submount, stacked mount, unknown `/dev` child, `--ro` workspace that is writable, writable mask | Decision 5 | `mountcheck.TestMismatchesAreReported`, `TestWorkspaceAndMaskEntries` | skip any one check | fast |
| hardening D5 | A start whose mounts differ from the plan is aborted before any process runs, with a diff | Decision 5 | `sandbox.TestStartVerificationAbortsOnMisconfiguration` | skip `mountcheck.Verify` in `Launch` (verified: the process that must never run ran) | security |
| hardening | A session's whole lifecycle on the real kernel: Launch verifies mounts and answers `ping`; `status` shows idle, the workspace, only declared env *names* and no secrets; `stop` returns quickly with the daemon process, every sandbox process, all mounts (nothing leaks into the host mount namespace) and the runtime dir gone; the per-agent home persists | Spec: Stop and cleanup; Session status | `daemon.TestSessionLifecycle` | stop removing the runtime dir in `Run` (verified: stop takes 15 s and the test fails) | security |
| 1.3 | Killing the daemon takes the sandbox with it (`--die-with-parent`) and `list` removes the leftover directory; a failed start leaves no process or mount | Spec: Agent restart and session lifetime | `daemon.TestDaemonKilledTakesTheSandboxWithIt`, `TestFailedStartLeavesNothingRunning` | drop `--die-with-parent` | security |
| hardening | Control-channel hygiene: target resolution never accepts path-like ids, stale sessions are removed but a start in progress is not, an unresponsive daemon is killed and cleaned up, two sessions are independent | Spec: Session targeting; List sessions | `daemon.TestResolveTarget`, `TestListRemovesStaleKeepsStarting`, `TestStopKillsAnUnresponsiveDaemon`, `TestTwoSessionsAreIndependent`, `cli.TestListStatusStop` | accept `../` in `ResolveTarget` | fast + security |
| hardening | `start` refuses `/`, the home directory and any directory that contains or sits inside isolait's config, state or runtime directory (string-based until the dev+inode deny list in 6.1) | Decision 3 / Decision 8 | `cli.TestCheckWorkdir` | drop the `related` check | fast |
| S1 | The session's `limits.pids` bounds a fork bomb inside the sandbox; the uncapped control run proves the bomb is real (400 processes), the capped run holds at most the cap and the shell reports refused forks | Decision 4 (resource limits) | `sandbox.TestForkBombIsBoundedByTheSessionScope` | run the scope without `TasksMax` (verified: 402 processes held) | security |
| S1 | The daemon starts inside `isolait-<sid>.scope` with the configured `TasksMax`, `MemoryMax` and `CPUQuota`, `status` reports usage, and the scope disappears on stop | Decision 4 | `daemon.TestLimitsAppliedThroughScope`, `daemon.TestScopeArgs`, `daemon.TestReadUsage` | drop a `-p` property from `ScopeArgs` | fast + security |
| S1 | Without a systemd user manager (or when the scope fails) the session still starts and `status` says why limits are unavailable; with `limits.required` the start is refused | Decision 4 | `daemon.TestLimitsUnavailableIsVisibleAndNotFatal`, `daemon.TestRequiredLimitsRefuseToStartWithoutSystemd`, `config.TestLimitsDefaultsMergeAndValidation` | silently ignore a failed scope | fast + security |
| 1.8 | The output sanitizer drops every OSC except OSC 8 (clipboard writes, titles, colour queries), all DCS/APC/PM/SOS strings, every `CSI ... t` and ENQ; consumes bracketed-paste toggles; forwards colours, cursor movement, hyperlinks and the alternate screen unchanged; sequences split at any byte boundary give the same output; random mixed streams never forward a forbidden sequence; over-long sequences are bounded | Decision 4 (sanitizer) | `term.TestSanitizeTable`, `TestSplitReadsGiveTheSameOutput`, `TestRandomStreamsNeverLeakForbiddenSequences`, `TestModesAreTracked`, `TestOverlongSequencesAreBounded` | M23 to M27 | fast |

## Host-assumption canaries

| Spike | Host behaviour | Canary | Control that proves it can fail | Tier |
|---|---|---|---|---|
| tools | bwrap is at least 0.8 and still documents every flag the sandbox argv uses (`--disable-userns`, `--as-pid-1`, `--info-fd`, `--block-fd`, `--unshare-cgroup-try`, `--uid`, `--gid`, ...) | `canary.TestCanaryBwrapFeatures` | n/a: it reads the tool | security |
| 1.1, 1.3 | A mount the broker makes under the stage appears in the sandbox; the sandbox's `/workspaces` is a slave (nothing leaks back, nothing is shared); an unmount reaches the sandbox | `canary.TestCanaryMountPropagation` | n/a: propagation is the positive result | security |
| 1.2 | Even with capabilities the sandbox cannot remount a propagated read-only mount read-write (`MNT_LOCKED`) | `canary.TestCanaryMountsAreLocked` | n/a | security |
| 1.4 | An `open_tree` + `mount_setattr` + `move_mount` clone is never writable from its first visible instant | `canary.TestCanaryReadOnlyCloneIsNeverWritable` | `mount --bind` + `remount,ro` lets all 300 writes through (verified 3 of 3) | security |
| 1.5 | Nested user namespaces are blockable with `--disable-userns` under the broker's own nesting, even with capabilities | `canary.TestCanaryNestedUsernsBlocked` | the same probe without the flag reports the nested userns allowed (the test asserts this control) | security |
| 1.6, 1.7 | A tap device can be created in a private network namespace and stays invisible outside it | `canary.TestCanaryTapInPrivateNetns` | skips without `/dev/net/tun` | security |
| S1 | A systemd user scope applies `TasksMax` and `MemoryMax`, keeps a process that forked away from its launcher, and `cgroup.kill` is writable by the user and removes it | `canary.TestCanaryCgroupScope` | skips without a user manager | security |

## Mutations (`make mutations`)

Each mutation is applied by `scripts/mutations.py` to a scratch copy; the named tests must fail. Verified caught
(27 of 27) on 2026-11-17.

| Id | Regression | Must fail |
|---|---|---|
| M01 | Broker without `CLONE_NEWNS` | `broker.TestCommandRecipe`, `TestBrokerNamespace` |
| M02 | No `--disable-userns` | `sandbox.TestHardeningFlags`, `TestBaselineIsolation`, `TestNestedUsernsOptIn` |
| M03 | No `--unshare-net` | `sandbox.TestHardeningFlags`, `TestBaselineIsolation` |
| M04 | No `--die-with-parent` | `sandbox.TestHardeningFlags` |
| M05 | Environment inherited by default | `sandbox.TestBuildEnv` |
| M06 | `--inherit-path` always on | `sandbox.TestInheritPathFilter`, `TestAgentBehindSymlink` |
| M07 | Agent install root never exposed | `sandbox.TestAgentBehindSymlink`, `TestBinaryExposure` |
| M08 | Workspace clone without the read-only attribute | `mounts.TestWorkspaceMountPrimitive` |
| M09 | Recursive clone (host submounts carried along) | `mounts.TestWorkspaceMountPrimitive` |
| M10 | `.isolait` mask skipped | `mounts.TestWorkspaceMountPrimitive` |
| M11 | Mount verification skipped at launch | `sandbox.TestStartVerificationAbortsOnMisconfiguration` |
| M12 | Mount flag checks disabled | `mountcheck.TestMismatchesAreReported`, `TestWorkspaceAndMaskEntries` |
| M13 | Workspace config applied without trust | `config.TestUntrustedWorkspaceConfigIgnoredEntirely`, `TestTrustAppliesAndModificationRevokes` |
| M14 | Workspace config symlinks followed | `config.TestWorkspaceSymlinksRefused` |
| M15 | Path-like session ids accepted | `daemon.TestResolveTarget` |
| M16 | `start` workdir guard disabled | `cli.TestCheckWorkdir` |
| M17 | Runtime dir with group/other access accepted | `session.TestEnsurePrivateDirRefusals` |
| M18 | Duplicate plan destinations accepted | `plan.TestAddRejects` |
| M19 | Scope without `TasksMax` | `daemon.TestScopeArgs` |
| M20 | Memory limit never passed to the scope | `daemon.TestScopeArgs` |
| M21 | Init shim never reaps or reports exits | `initshim.TestSpawnExitCodeAndOutput` |
| M22 | Daemon leaves its runtime dir behind | `daemon.TestSessionLifecycle` |
| M23 | Every OSC forwarded (clipboard, titles) | `term.TestSanitizeTable`, `TestRandomStreamsNeverLeakForbiddenSequences` |
| M24 | `CSI ... t` window manipulation forwarded | same |
| M25 | DCS, APC, PM and SOS forwarded | same |
| M26 | Bracketed-paste toggles forwarded to the terminal | `term.TestSanitizeTable`, `TestModesAreTracked` |
| M27 | A partly received sequence is forgotten between reads | `term.TestSplitReadsGiveTheSameOutput`, `TestRandomStreamsNeverLeakForbiddenSequences` |

Not mutated on purpose: the `os.Getpid() == 1` guard before `kill(-1)` in the init shim (outside a PID namespace
it would signal every process the user owns; `initshim.TestShutdownLeavesUnrelatedProcessesAlone` guards it). Not
testable here: the control socket's peer-uid check (needs a second user; `ctl.TestPeerUIDIsChecked` covers the
credential read, and the 0700 runtime directory is the primary defence).

## Pending: assumptions whose code is not written yet

| Spike | Assumption | Design decision | Lands with | Guard test (planned) |
|---|---|---|---|---|
| 1.6 | The user-space netstack forwards TCP and answers DNS at the measured rate; the destination policy is checked on the address actually dialed, so a name that resolves to a private address, loopback, link-local or metadata range is refused (DNS rebinding); a refused upstream is a refused guest connect | Decision 5 | 5.1 to 5.5 | `netd` tests plus a security test per blocked range; mutation: skip the dial-time check |
| 1.6 | Non-DNS UDP, ICMP and IPv6 from the sandbox are dropped; the sandbox sees only the managed interface | Decision 5 | 5.2, 5.4 | security test; mutation: leave IPv6 enabled |
| 1.7 | A port grant is a listener on the sandbox loopback forwarded to host `127.0.0.1`; reachable only after `allow`, refused after `deny`, other host services unreachable | Decision 5 | 7.1 to 7.3 | security test; mutation: listen before the grant |
| 1.8 | The PTY relay redraws on attach and handles alt-screen apps (the sanitizer half is done, see the matrix) | Decision 4 | 4.2 | relay tests through a test PTY; mutation: skip the redraw |
| 1.2, 1.9 | A busy workspace is reported with its blocking processes; `--force` detaches lazily; a protected path or any ancestor is refused by dev+inode, including after a symlink swap | Decisions 2, 3 | 6.1, 6.4, 6.7 | deny-list unit tests plus a security test; mutation: compare paths as strings |
| 1.3 | The sandbox cannot reach the control socket or the runtime directory (probe from inside); no unapproved network | Decision 4 | 8.2 | the isolation regression suite |
| S2 to S4 | Landlock ceiling | `sandbox-hardening` D2 and D3 | deferred to Phase 2 | S2 to S4 spikes remain in the store; revisit triggers in the design |
