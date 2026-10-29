# 1.3 bwrap keeps /workspaces a slave bind

**Question:** with `--bind stage /workspaces`, is the sandbox's `/workspaces` a slave (receives
broker mounts, never propagates back)? What argv works?

**Approach:** read `/proc/self/mountinfo` in the sandbox (expect `master:N`, no `shared:`), and
mount a tmpfs at `/workspaces/z` from inside, asserting it never shows in the broker's `stage/z`.

**Working argv** (no wrapper or extra flag needed), from `_common/fixture.sh`:
`bwrap --unshare-user --unshare-pid --die-with-parent --ro-bind /usr /usr --symlink usr/bin /bin
--symlink usr/lib /lib --symlink usr/lib64 /lib64 --dev /dev --proc /proc --bind <stage> /workspaces`.
The product baseline (3.3) must keep bind order such that `/workspaces` is bound from `stage/` directly.

**Pass:** `workspaces-is-slave`, `sandbox-mounts-do-not-propagate-back`.

**Run:** `./run.sh`.

## Result (2026-10-29, WSL2 kernel 6.18, bwrap 0.13.1)
All PASS. **Verdict: GO.**
