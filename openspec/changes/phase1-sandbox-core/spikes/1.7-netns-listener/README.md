# 1.7 Port grant: listen in the sandbox netns, forward to host loopback

**Question:** can a locked OS thread `setns` into the sandbox netns (broker is the parent userns), create a
listener on the sandbox's loopback, and forward connections to host `127.0.0.1` dialed from the original
netns, with close-on-revoke?

**Approach:** `probe.go` does `LockOSThread` + `setns(CLONE_NEWNET)` + `net.Listen` in a goroutine that
then exits (Go terminates a thread that exits while locked, so it never serves other goroutines from the
wrong netns). Accepted connections are dialed by ordinary goroutines. `SIGUSR1` closes the listener
and its connections. The sandbox (`--unshare-net`, pid found via `--info-fd`) fetches over bash `/dev/tcp`.

**Pass:** `listener-created-in-sandbox-netns`, `listener-not-on-host-loopback`,
`sandbox-reaches-host-service-via-grant`, `host-loopback-unreachable-without-grant`, `grant-closed`,
`connect-refused-after-close`.

**Run:** `./run.sh`.

## Result (2026-10-29, WSL2 kernel 6.18)
All PASS. **Verdict: GO.** Decision 5's port-grant model (and 7.2) works as designed.
