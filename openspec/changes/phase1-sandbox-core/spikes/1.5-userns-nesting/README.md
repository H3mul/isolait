# 1.5 `--disable-userns` under the broker's userns nesting

**Question:** the sandbox is already a user namespace inside the broker's. Does bwrap `--disable-userns`
still block `unshare -U` in the sandbox?

**Approach:** run the same probe twice, without and with `--disable-userns` (via `SBX_EXTRA`).
The first run is a control showing the probe can detect an unblocked nested userns.

**Pass:** `control-nested-userns-allowed-by-default`, `disable-userns-sandbox-starts-under-broker`, `nested-userns-blocked`.

**Run:** `./run.sh` (container needs `systempaths=unconfined`, as bwrap writes `/proc/sys/user/max_user_namespaces`).

## Result (2026-10-29, WSL2 kernel 6.18, bwrap 0.13.1)
All PASS. **Verdict: GO.** Note the product must pass `--disable-userns` after `--unshare-user`; the
spike used `--cap-add ALL`, so the block holds even with caps present.
