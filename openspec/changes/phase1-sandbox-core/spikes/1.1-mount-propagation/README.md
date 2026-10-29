# 1.1 Mount propagation (broker → sandbox)

**Question:** does a mount made by the broker (own user+mount ns) under a shared `stage/` appear
in an already-running bwrap sandbox, without entering the sandbox? (design Decision 1)

**Approach:** `_common/fixture.sh` re-execs the test in `unshare -Urm` (the broker), makes a tmpfs
`stage/` shared, starts bwrap with `--bind stage /workspaces`, then the broker does
`mount --bind src stage/a` after the sandbox signals ready. The sandbox polls for `/workspaces/a/f`.

**Pass:** `hot-mount-visible-in-sandbox`.

**Run:** `./run.sh` (needs Docker). **Related:** 1.2, 1.3 (same fixture), 1.9.

## Result (2026-10-29, WSL2 kernel 6.18, bwrap 0.13.1, Docker 29.9.1)
PASS. **Verdict: GO** for Decision 1's core mechanism.
