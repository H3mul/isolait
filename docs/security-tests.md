# Security regression tests

Each row ties an assumption validated by a feasibility spike (in the openspec store, `phase1-sandbox-core/spikes`
and `sandbox-hardening/spikes`) to the Go test that guards it in this repository, and to the mutation that proves
the test fails when the assumption is broken. Rule: a task that implements a spike-validated mechanism adds its
row and its test in the same change.

Tiers: **fast** tests run under `go test ./...`; **security** tests need real user namespaces and run with
`go test -tags security ./...` (they `t.Skip` with a reason when the kernel feature is missing, never pass vacuously).

| Spike | Assumption | Design decision | Guard test | Mutation that must fail it | Tier |
|---|---|---|---|---|---|
| 1.1 | The broker holds exactly `CAP_SYS_ADMIN` in its own user namespace, sees the host fs, can mount, cannot change host state, and its mounts never reach the host | Decision 1 (broker mount namespace) | `broker.TestBrokerNamespace` | drop `AmbientCaps` (verified: `CapEff=0`, mount fails) | security |
| 1.1 | The broker's namespace recipe has not drifted (identity uid/gid map, `NEWUSER\|NEWNS`, setgroups denied, ambient SYS_ADMIN only, own session) | Decision 1 | `broker.TestCommandRecipe` | change any recipe field (verified: drop `CLONE_NEWNS`) | fast |
