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
| 1.8 | The daemon owns the PTYs and every PTY byte (agent, unattended agent, exec) goes through one `output()` function, the seam for a future log tee or scrollback; an unattended agent is drained and never blocks on a full terminal (3 MB test); output is raw (the client sanitizes) | Decision 4 (PTY ownership, scrollback seam) | `daemon.TestAllPTYOutputFlowsThroughTheSingleOutputPath`, `TestUnattendedAgentNeverBlocksOnOutput` | M28 | fast |
| 1.8 | One client at a time per agent; attach starts the agent, reattach to a running agent restores its alternate-screen mode and asks it to repaint; an agent that exited is reported with its code and restarted by the next attach; detach keeps it running; resize reaches the terminal | Spec: Detach and attach; Agent restart | `daemon.TestAttachStartsAgentAndRelaysInput`, `TestSecondAgentClientIsRejected`, `TestDetachKeepsAgentRunningAndReattachRestoresModes`, `TestAgentExitIsReportedAndReattachRestartsIt`, `TestResizeReachesTheTerminal`, `TestRedrawFrameSignalsTheAgent` | M29, M30, M34 | fast |
| hardening | `exec` runs a new process on its own PTY in the same sandbox, resolves commands on the sandbox PATH, never outlives its client, and does not change the agent's state; hellos are validated (mode, command, TERM replaced when it is not a safe name, window size clamped) | Spec: Exec in a running sandbox | `daemon.TestExecRunsInTheSandboxAndReportsExit`, `TestExecDoesNotOutliveItsClient`, `TestExecOfAMissingCommandIsRefused`, `TestBadHellosAreRefused`, `TestTermIsSanitizedAndSizeClamped` | M31, M32, M33 | fast |
| 1.3 | On the real kernel: attach and exec reach shells inside the sandbox (cwd `/workspaces/<name>`, the fake home, the user's uid, a real tty, the requested size); a second shell sees the same mounts; **nothing in the sandbox can find or reach the daemon's control or attach sockets**; detach and reattach return to the same shell | Spec: Control surface unreachable from sandbox | `daemon.TestAttachAndExecInTheRealSandbox` | stop mounting the runtime dir into the plan (covered by `sandbox.TestIsolaitDirsNeverExposed`); drop the sandbox | security |
| hardening | The attach frame protocol: round trip of every frame type, oversized and truncated frames rejected | Decision 4 | `attach.TestFramesRoundTrip`, `TestOversizedAndTruncatedFramesAreRejected` | n/a | fast |
| 1.8 | The leader key is recognised only from real keyboard input: never inside a bracketed paste (also not when pasting into the prompt), a paste cancels a pending leader, paste markers are stripped unless the agent asked for them, a lone Escape is released by `Flush` and not delayed for ever, input split at any byte boundary gives the same decisions, random paste traffic never produces a detach or prompt | Spec: Leader key from real input only | `term.TestLeaderCommands`, `TestLeaderInsidePasteIsNeverRecognised`, `TestPasteIntoThePromptGoesToThePrompt`, `TestPasteCancelsAPendingLeader`, `TestLoneEscapeIsReleasedByFlush`, `TestSplitInputGivesTheSameEvents`, `TestRandomPastesNeverTriggerTheLeader`, `TestParseLeader` | M35 to M39 | fast |
| 1.8 | The relay sanitizes agent output before it reaches the terminal (also sequences split across frames) and forwards keyboard input; leader then d detaches; an exit frame ends it with the code; a refused attach is an error; a dropped connection or closed input ends it cleanly; paste markers are kept only for an agent that enabled bracketed paste, and the agent's own paste-mode toggle never reaches the terminal; a lone Escape reaches the agent | Decision 4 (relay) | `relay.TestOutputIsSanitizedAndInputForwarded`, `TestLeaderDetaches`, `TestExitFrameEndsTheRelayWithTheCode`, `TestRefusedAttachIsAnError`, `TestDroppedConnectionAndClosedInputEndTheRelay`, `TestPasteMarkersAreStrippedUnlessTheAgentAsked`, `TestLoneEscapeReachesTheAgent` | M40, M43, M45, M46 | fast |
| 1.8 | With a real terminal (a pty): raw mode (no local echo), bracketed paste enabled on the real terminal, the hello carries its size, window-size changes are forwarded, and on exit the terminal is restored exactly (termios) and left usable (alternate screen, mouse, cursor, colours reset) | Decision 4 (relay) | `relay.TestRealTerminalRawModePasteModeSizeAndRestore`, `pty.TestRawModeAndRestore`, `pty.TestSizeRoundTrip` | M41, M42, M44 | fast |
| 1.8 | End to end through the real binary on a real pty: `start` on a terminal attaches and the shell runs inside the sandbox (cwd, a real tty, the terminal's size); the agent's OSC 52 never reaches the terminal; leader then d detaches with status 0 and the session lists as detached; `attach` with no argument uses the last attached session and finds the shell state intact; `status` says attached; the agent's exit status propagates and the session goes idle; the next attach restarts the agent; an alternate-screen agent is restored on reattach and left cleanly on detach | Spec: Daemon-hosted sessions; Detach and attach; List sessions; Session targeting | `cli.TestStartAttachDetachReattachExit`, `cli.TestAlternateScreenAndTerminalRestoreAcrossDetach` | M47 to M50 | security |
| 1.3 | `exec` on a terminal runs in the same sandbox, propagates the exit status, needs a target (the error lists the sessions), does not start the agent, and the process dies when its client's terminal goes away; `attach` and `exec` refuse to run without a terminal | Spec: Exec in a running sandbox; Session targeting | `cli.TestExecOnATerminal`, `cli.TestAttachAndExecNeedATerminal` | M49, M51 | security |
| 1.8 | The leader prompt: on a normal screen it is an overlay on the alternate screen (closing it restores the agent's screen exactly, no repaint); over an alternate-screen app it overwrites the bottom row between a saved and restored cursor and asks the app to repaint, restoring a hidden cursor; agent output is held while it is open and shown after; what is typed in it never reaches the agent; Escape dismisses without running anything; a command's text is shown with control characters removed so it cannot inject escape sequences; with no prompt callback the key typed after the leader goes to the agent | Spec: In-session command prompt | `relay.TestPromptOnANormalScreenIsAnOverlayThatRestoresTheScreen`, `TestPromptOverAnAlternateScreenAppRepaintsIt`, `TestEscapeDismissesAndTypingGoesBackToTheAgent`, `TestPromptResultCannotInjectEscapeSequences`, `TestWithoutAPromptCallbackTheLeaderColonDoesNothing`, `TestDisplayText`, `TestEditor` | M52 to M56, M58, M59 | fast |
| 1.8 | Prompt commands run in this process with the session you are attached to as the target, with shell-style quoting; commands that attach, start another session or are internal are refused; errors and bad lines are reported as text | Spec: In-session command prompt | `cli.TestPromptRunnerTargetsTheCurrentSessionAndRefusesAttaching`, `cli.TestTokenize` | M57 | fast |
| 1.8 | End to end on a real pty: `leader :` opens the overlay, `status` shows this very session's status on one row, the prompt closes by itself, `attach` is refused, a dismissed `:stop` leaves the session running and the agent usable, and `:stop` really ends the session you are in | Spec: In-session command prompt | `cli.TestLeaderPromptInASession` | M57 | security |

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
(59 of 59) on 2026-11-17.

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
| M28 | An unattended agent is no longer drained (it would block on a full PTY) | `daemon.TestUnattendedAgentNeverBlocksOnOutput` |
| M29 | A second client can attach to an attached agent | `daemon.TestSecondAgentClientIsRejected` |
| M30 | Reattach does not restore the agent's alternate-screen mode | `daemon.TestDetachKeepsAgentRunningAndReattachRestoresModes` |
| M31 | An exec process outlives its client | `daemon.TestExecDoesNotOutliveItsClient` |
| M32 | `TERM` from the client is passed on unchecked | `daemon.TestTermIsSanitizedAndSizeClamped` |
| M33 | Window size from the client is not clamped | `daemon.TestTermIsSanitizedAndSizeClamped` |
| M34 | The exit frame is never sent | `daemon.TestAgentExitIsReportedAndReattachRestartsIt` |
| M35 | The leader key is recognised inside a bracketed paste | `term.TestLeaderInsidePasteIsNeverRecognised`, `TestRandomPastesNeverTriggerTheLeader` |
| M36 | Paste markers forwarded to an agent that did not ask for them | `term.TestLeaderInsidePasteIsNeverRecognised` |
| M37 | A held lone Escape is never released | `term.TestLoneEscapeIsReleasedByFlush` |
| M38 | Leader twice does not send a literal leader | `term.TestLeaderCommands` |
| M39 | A paste does not cancel a pending leader | `term.TestPasteCancelsAPendingLeader` |
| M40 | Agent output reaches the terminal unsanitized | `relay.TestOutputIsSanitizedAndInputForwarded` |
| M41 | Bracketed paste is not enabled on the real terminal | `relay.TestRealTerminalRawModePasteModeSizeAndRestore` |
| M42 | The terminal is not restored on exit | same |
| M43 | The agent's bracketed-paste request is not tracked | `relay.TestPasteMarkersAreStrippedUnlessTheAgentAsked` |
| M44 | Window-size changes are not forwarded | `relay.TestRealTerminalRawModePasteModeSizeAndRestore` |
| M45 | A held lone Escape is never released | `relay.TestLoneEscapeReachesTheAgent` |
| M46 | Detach is not sent to the daemon | `relay.TestLeaderDetaches` |
| M47 | The last attached session is not recorded | `cli.TestStartAttachDetachReattachExit` |
| M48 | The agent's exit status is not propagated | same |
| M49 | An exec'd process's exit status is not propagated | `cli.TestExecOnATerminal` |
| M50 | `start` on a terminal does not attach | `cli.TestStartAttachDetachReattachExit` |
| M51 | `attach` and `exec` run without a terminal | `cli.TestAttachAndExecNeedATerminal` |
| M52 | Agent output is not held while the prompt is open | `relay.TestPromptOnANormalScreenIsAnOverlayThatRestoresTheScreen` |
| M53 | The prompt never uses the alternate-screen overlay | same |
| M54 | No repaint after the prompt overwrote an alternate-screen app's bottom row | `relay.TestPromptOverAnAlternateScreenAppRepaintsIt` |
| M55 | A command's output is shown with its control characters | `relay.TestPromptResultCannotInjectEscapeSequences` |
| M56 | Escape does not dismiss the prompt | `relay.TestEditor` |
| M57 | The prompt accepts `attach`, `start`, `exec` | `cli.TestPromptRunnerTargetsTheCurrentSessionAndRefusesAttaching` |
| M58 | A hidden cursor is not restored after the prompt | `relay.TestPromptOverAnAlternateScreenAppRepaintsIt` |
| M59 | The key typed after the leader is swallowed when no prompt exists | `relay.TestWithoutAPromptCallbackTheLeaderColonDoesNothing` |

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
| 1.8 | A real Claude Code and OpenCode through the relay | Decision 4 | manual, `docs/manual-checks.md` | n/a |
| 1.2, 1.9 | A busy workspace is reported with its blocking processes; `--force` detaches lazily; a protected path or any ancestor is refused by dev+inode, including after a symlink swap | Decisions 2, 3 | 6.1, 6.4, 6.7 | deny-list unit tests plus a security test; mutation: compare paths as strings |
| 1.3 | No unapproved network from inside the sandbox (the control-surface half is done, see the matrix) | Decision 4 | 8.2 | the isolation regression suite |
| S2 to S4 | Landlock ceiling | `sandbox-hardening` D2 and D3 | deferred to Phase 2 | S2 to S4 spikes remain in the store; revisit triggers in the design |
