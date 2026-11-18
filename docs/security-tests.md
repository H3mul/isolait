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
| `make isolation` | the **isolation gate**: the curated tests for no capabilities, mounts, host paths, unapproved network, control-socket access and nested user namespaces; fails if any is skipped | CI gate; after any change to the sandbox, broker or network |
| `make e2e` | `cli.TestFullWorkflow`: start, detach, attach, exec, mounts, ports, agent restart, stop through the real binary | before a release; CI; run on WSL2 and native Linux |
| `make mutations` | applies every mutation below to a scratch copy and requires a test to fail | when you touch a guard test or a guarded line; before a release |

CI (`.github/workflows/ci.yml`) runs `make check`, `make test`, `make security`, `make canary` and, as a separate gate job, `make isolation` and `make e2e`; it lifts Ubuntu
24.04's AppArmor userns restriction for the test run only. The workflow first ran green on GitHub on 2026-11-18 (all four jobs).

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
| 1.6 | The destination policy refuses loopback, RFC 1918, carrier-grade NAT, link-local, multicast, cloud-metadata space (named as such), unspecified and reserved ranges, documentation and benchmarking ranges, the host's own addresses and the gateway, and all IPv6; an IPv4-mapped IPv6 address is judged as the IPv4 address; allowed addresses next to each blocked range stay allowed; 200,000 random addresses agree with an independent reference | Decision 5 (dial-time policy) | `netd.TestPolicyTable`, `TestPolicyAgreesWithAReferenceOnRandomAddresses`, `TestBlockedErrorNamesTheAddress` | M61 to M65 | fast |
| 1.6 | The policy also runs at dial time on the socket address actually connected, after name resolution (DNS rebinding: `localhost` resolves to loopback and is refused before any packet is sent); an unparsable address fails closed | Decision 5 | `netd.TestControlRefusesAtDialTimeAfterNameResolution`, `TestControlFailsClosedOnAnUnparsableAddress` | M60 | fast |
| 1.6 | The TCP forwarder carries 4 MiB intact both ways, forwards half-closes, dials the upstream before the guest's handshake completes (a connect with a 700 ms upstream dial takes at least that long), and a refused upstream is a refused guest connect, not connect-then-reset | Decision 5 (dial-before-handshake) | `netd.TestTCPForwardsBothWaysIntact`, `TestHalfCloseIsForwarded`, `TestRefusedUpstreamIsARefusedGuestConnect`, `TestHandshakeCompletesOnlyAfterTheUpstreamAnswered` | M66 | fast |
| 1.6 | At the engine: blocked destinations (private, metadata, CGNAT, host address, documentation) are refused without ever reaching the dialer; the gateway accepts only DNS; the connection limit holds and frees slots; the engine's own dialer enforces the policy at dial time | Decision 5; Spec: Private and local ranges blocked | `netd.TestBlockedDestinationsNeverReachTheDialer`, `TestGatewayAcceptsOnlyDNS`, `TestConnectionLimit`, `TestDefaultDialerRefusesLoopbackAtDialTime` | M67, M68, M72, M73 | fast |
| 1.6 | DNS to the gateway over UDP and TCP is answered by the host resolver (a TCP guest gets a TCP upstream), the answer comes from the gateway so the host resolver's address is never exposed, malformed messages and responses are dropped without reaching the resolver, and a name whose answer is a private address resolves but the connection to it is refused | Spec: DNS resolution; Name resolving to a private address | `netd.TestDNSOverUDPIsAnsweredByTheHostResolver`, `TestDNSOverTCPIsAnswered`, `TestMalformedDNSIsDropped`, `TestNameResolvingToAPrivateAddressIsRefused`, `TestResolvConfParsing` | M71, M74 | fast |
| 1.6 | Non-DNS UDP (to the gateway on another port, to a public address on 53 or any port) and ICMP echo are dropped and the stack never answers a ping for an address it does not own | Spec: Unsupported traffic dropped | `netd.TestNonDNSUDPIsDropped`, `TestICMPIsDropped` | M69, M70 | fast |
| 1.6 | The network engine process has no mount authority: a seccomp filter denies the mount family (`mount`, `umount2`, `pivot_root`, `chroot`, `open_tree`, `move_mount`, `fsopen`/`fsconfig`/`fsmount`/`fspick`, `mount_setattr`), swap, reboot, kexec, module loading, ptrace, cross-process memory access, `unshare` and file-handle opening, on every thread including threads created later, while `setns` stays allowed; in the broker namespace `mount` works before the filter and is `EPERM` after it | Decision 5 (`netd` has no mount capability) | `harden.TestSeccompDeniesDangerousCallsOnEveryThread`, `TestExecWithCapsAndNoMountAuthority`, `TestProgramLayout`, `TestEveryDeniedCallIsDistinctAndTheTableIsComplete` | M75, M76, M79 | fast + security |
| 1.6 | The engine process, re-executed with a reduced bounding set (this works in cgo builds, where per-thread capability changes do not), keeps exactly `CAP_NET_ADMIN` and `CAP_SYS_ADMIN` (effective, permitted and bounding), no inheritable or ambient capabilities, on every one of its threads | Decision 5 | `harden.TestExecWithCapsAndNoMountAuthority` | M77, M78 | security |
| 1.6, 1.7 | On the real kernel, through a real session: the sandbox sees only `lo` and the managed `tap0`; IPv6 is disabled (no IPv6 address anywhere); `/etc/resolv.conf` names only the gateway; a name lookup is answered by the host resolver; TCP to a public address is forwarded; an unknown name does not resolve | Spec: Outbound TCP to the internet; DNS resolution; Isolation from host networking | `daemon.TestSandboxNetworkEndToEnd` | M80, M81, M82, M86 | security |
| 1.6 | The sandbox cannot reach private, LAN, CGNAT, metadata, gateway (other than DNS) or host-loopback addresses, nor an address its own DNS answer named, nor the host's own address | Spec: Private and local ranges blocked; Isolation from host networking | `daemon.TestSandboxCannotReachPrivateLocalOrMetadataAddresses`, `netd.TestTheEnginePolicyRefusesTheHostsOwnAddresses` | M85 | security + fast |
| 1.6 | A closed upstream port is a refused connect inside the sandbox (not a connect that succeeds and then resets), quickly | Spec: Connection semantics | `daemon.TestClosedUpstreamPortIsRefusedNotAccepted` | M66 | security |
| 1.6 | The sandbox holds no network capability: bringing `tap0` down, setting an address, raw and packet sockets are all refused | Spec: Enforcement outside the sandbox | `daemon.TestSandboxCannotChangeItsNetwork` | n/a (the sandbox's capabilities are dropped; see M02/M03 family) | security |
| 1.6 | The engine process runs hardened on every thread: exactly `CAP_NET_ADMIN`+`CAP_SYS_ADMIN` (permitted, effective, bounding; nothing inheritable or ambient), `no_new_privs`, a seccomp filter; its pid does not exist inside the sandbox and a `kill -9 -1` from the sandbox leaves it and the network working | Decision 5; Spec: Enforcement outside the sandbox | `daemon.TestEngineProcessIsHardenedAndSurvivesSandboxSignals` | M83, M84 | security |
| 1.6 | A dead engine is reported by `status` (`network: down: ...`) without ending the session; an engine that fails to start (here: a bad flag) fails the whole session start with its error text and leaves no process behind | Decision 5 | `daemon.TestEngineDeathIsReportedAndDoesNotEndTheSession`, `daemon.TestFailingEngineFailsTheStartAndLeavesNothing` | n/a | security |
| 1.6 | The sandbox is held (`--block-fd`) after its namespaces exist and released only after the engine reports ready: no sandbox process runs before its network is hardened and up | Decision 5 (start order) | every daemon session test (the init shim answers only after release); `daemon.TestSandboxNetworkEndToEnd` | M86 | security |
| 1.2, 1.9 | A hot mount is visible, `.isolait` is masked, a read-only mount is never writable and cannot be remounted; a protected path or any ancestor is refused by dev+inode (also through symlinks, and a path swapped for a symlink after validation); a busy mount is reported with its processes and `--force` detaches it; a mismatch with the plan after a change is rolled back | Decisions 2, 3, 5 | `mounts.TestDenyList*`, `TestOpenSourceDescriptorIsStable`, `daemon.TestHotMount*`, `TestRemoveBusyForcedAndSwitch`, `TestUnplannedMountIsRolledBack`, `cli.TestMountAndUnmountCommands` | M87 to M94 | fast and security |
| 1.7 | A port grant is a listener on the sandbox loopback forwarded to host `127.0.0.1` only: refused before `allow` and after `deny`, live connections end on `deny`, a partial range closes only what is open, a service bound to a non-loopback host address is unreachable, UDP and oversized ranges are rejected | Decision 5 | `netd.TestParsePorts`, `TestForwardingAndClosing`, `daemon.TestPortGrant*`, `TestPortRangeGrantAndPartialClose`, `cli.TestAllowAndDenyPortCommands` | M95 to M99 | fast and security |
| 1.3, 1.5, 1.7 | The isolation gate: from inside a live session no capabilities (effective and bounding sets empty, no_new_privs), mounting fails, a nested user namespace fails, only `lo` and the managed `tap0` exist, the host home, runtime, state and the control and attach sockets are invisible, host secrets are absent, uid is the caller's | Decisions 1, 4, 7 | `daemon.TestIsolationRegressionSuite` plus the tests named in `scripts/isolation.sh` | M100 to M102 | security (gate) |
| workflow | The whole user workflow works in one sequence: start, detach, attach (agent state kept), exec, mount, port grant, agent exit and restart (mounts kept), unmount, stop leaves nothing | Spec: all | `cli.TestFullWorkflow` | n/a | security |
| netlink | The rtnetlink messages (link up, address, default route) are well formed and kernel errors are parsed | Decision 5 | `netd.TestNetlinkMessagesAreWellFormed`, `TestAckErrorParsing` | n/a | fast |

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
(102 of 102) on 2026-11-17.

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
| M47 | Attach is not recorded as use (the session's recency is not updated) | `daemon.TestAttachAndDetachRecordUseButExecDoesNot` |
| M104 | Sessions are not ordered by recency (targeting and `list` ignore it) | `daemon.TestResolveTargetFollowsTmuxSequence`, `daemon.TestListOrdersByRecency` |
| M105 | `attach` does not prefer an unattached session | `daemon.TestAttachPrefersTheNewestUnattachedSession` |
| M106 | `kill-server` stops only one of several sessions | `cli.TestKillServer`, `cli.TestKillServerEndToEnd` |
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
| M60 | The dial-time policy hook allows everything | `netd.TestControlRefusesAtDialTimeAfterNameResolution` |
| M61 | IPv4-mapped IPv6 addresses are not judged as IPv4 | `netd.TestPolicyTable` |
| M62 | The carrier-grade NAT range is cut short | `netd.TestPolicyTable`, `TestPolicyAgreesWithAReferenceOnRandomAddresses` |
| M63 | The host's own addresses are allowed | `netd.TestPolicyTable` |
| M64 | The metadata address is no longer named as such | `netd.TestPolicyTable` |
| M65 | IPv6 destinations are allowed | `netd.TestPolicyTable` |
| M66 | A refused upstream completes the guest's handshake | `netd.TestRefusedUpstreamIsARefusedGuestConnect` |
| M67 | The engine skips the policy check before dialing | `netd.TestBlockedDestinationsNeverReachTheDialer` |
| M68 | The gateway accepts TCP on any port | `netd.TestGatewayAcceptsOnlyDNS` |
| M69 | UDP to anywhere is treated as DNS | `netd.TestNonDNSUDPIsDropped` |
| M70 | ICMP is no longer dropped | `netd.TestICMPIsDropped` |
| M71 | DNS messages are not validated | `netd.TestMalformedDNSIsDropped` |
| M72 | The connection limit is not enforced | `netd.TestConnectionLimit` |
| M73 | The engine's dialer has no dial-time policy | `netd.TestDefaultDialerRefusesLoopbackAtDialTime` |
| M74 | A TCP DNS query is sent upstream over UDP | `netd.TestDNSOverTCPIsAnswered` |
| M75 | `mount` is missing from the seccomp denylist | `harden.TestExecWithCapsAndNoMountAuthority` |
| M76 | The filter is installed on the calling thread only | `harden.TestSeccompDeniesDangerousCallsOnEveryThread` |
| M77 | Inheritable capabilities survive the re-exec | `harden.TestExecWithCapsAndNoMountAuthority` |
| M78 | The bounding set is not reduced | same |
| M79 | The filter's default for denied calls is allow | `harden.TestProgramLayout`, `TestSeccompDeniesDangerousCallsOnEveryThread` |
| M80 | IPv6 is not disabled in the sandbox's netns | `daemon.TestSandboxNetworkEndToEnd` |
| M81 | The sandbox gets no default route | same |
| M82 | The sandbox's resolver is not the gateway | same |
| M83 | The engine does not install its seccomp filter | `daemon.TestEngineProcessIsHardenedAndSurvivesSandboxSignals` |
| M84 | The engine keeps its full capabilities (no re-exec with a reduced set) | same |
| M85 | The engine's policy ignores the host's own addresses | `netd.TestTheEnginePolicyRefusesTheHostsOwnAddresses` |
| M86 | The sandbox runs without a network engine | `daemon.TestSandboxNetworkEndToEnd`, `TestEngineProcessIsHardenedAndSurvivesSandboxSignals` |
| M87 | A protected directory itself can be mounted | `mounts.TestDenyList` |
| M88 | A directory containing a protected one (home's parent, `/`) can be mounted | same |
| M89 | A directory inside an excluded one (state, runtime) can be mounted | same |
| M90 | The filesystem root can be mounted | same |
| M91 | Hot mounts skip the deny list | `daemon.TestHotMountRefusals` |
| M92 | Removing a busy mount ignores the blocking processes | `daemon.TestRemoveBusyForcedAndSwitch` |
| M93 | An unplanned mount after a hot mount is not detected | `daemon.TestUnplannedMountIsRolledBack` |
| M94 | Remove leaves the mount in place | `daemon.TestRemoveBusyForcedAndSwitch` |
| M95 | The grant's listener is created in the host's network namespace, not the sandbox's | `daemon.TestPortGrantReachableOnlyAfterAllowAndRefusedAfterDeny` |
| M96 | `deny` leaves live connections open | `netd.TestForwardingAndClosing` |
| M97 | UDP notation is not recognised as UDP | `netd.TestParsePorts` |
| M98 | The per-grant port cap is off by one | same |
| M99 | Opening an open port creates a second listener | `netd.TestForwardingAndClosing` |
| M100 | The sandbox keeps its capabilities (`--cap-drop ALL` removed) | `daemon.TestIsolationRegressionSuite` |
| M101 | Nested user namespaces are allowed (`--disable-userns` dropped) | same |
| M102 | The sandbox shares the host's network namespace | same |
| M103 | Launcher scripts' targets are not exposed (a wrapper in a system directory cannot run its binary) | `sandbox.TestLauncherInSystemDirRunsInSandbox` |

Not mutated on purpose: the `os.Getpid() == 1` guard before `kill(-1)` in the init shim (outside a PID namespace
it would signal every process the user owns; `initshim.TestShutdownLeavesUnrelatedProcessesAlone` guards it). Not
testable here: the control socket's peer-uid check (needs a second user; `ctl.TestPeerUIDIsChecked` covers the
credential read, and the 0700 runtime directory is the primary defence).

## Pending: assumptions whose code is not written yet

| Spike | Assumption | Design decision | Lands with | Guard test (planned) |
|---|---|---|---|---|
| 1.6 | A real agent reaching its real API through the engine | Decision 5 | 5.6 (manual, `e2e.md`) | n/a |
| 1.8 | A real Claude Code and OpenCode through the relay | Decision 4 | manual, `docs/manual-checks.md` | n/a |
| S2 to S4 | Landlock ceiling | `sandbox-hardening` D2 and D3 | deferred to Phase 2 | S2 to S4 spikes remain in the store; revisit triggers in the design |
