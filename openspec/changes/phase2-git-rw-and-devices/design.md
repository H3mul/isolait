# Design

> **Status: notes from exploration, not a finished design.** Only `git-rw` has substantive content.

## Context

Phase 1 mounts via a broker mount namespace with propagation to a slave sandbox (see `phase1-sandbox-core` design). Mount flags are per-mount, so anything finer than "directory rw/ro" needs extra mounts or a filtering filesystem.

## Goals / Non-Goals

**Goals:** make writes land only where git can show them; keep native speed and real inotify; reuse Phase 1's mount machinery.

**Non-Goals:** a security boundary against reading secrets (ignored files like `.env` stay readable); stopping edits to tracked scripts (`package.json`, `Makefile`, CI), which are covered by `git diff` review.

## Decisions

### git-rw semantics (redefined from literal "tracked only")

Literal "tracked only" is rejected: it blocks creating new files and breaks atomic writes (`sed -i`, formatters) since temp files are untracked, and it needs a FUSE filter to enforce.

```
 path state                              git-rw
 --------------------------------------  --------------------
 tracked                                 rw  (shows in git diff)
 untracked, not ignored                  rw  (shows in git status)
 ignored (.env, .envrc, node_modules)    ro  (invisible to review)
 .git/, .gitignore, .gitattributes,
 .gitmodules                             ro, immutable
```

Positioning: a **review-surface policy, not an isolation boundary**. Documentation must say so.

### Enforcement: Tier 1 static snapshot

Phase 1 already layers a ro mask over `.isolait` on workspace mounts (see `phase1-sandbox-core` design, configuration tiers). `git-rw` reuses that sub-mount mechanism for `.git`, control files and ignored paths. The layered-ro propagation spike is therefore done in Phase 1 (task 1.9).


At session start and each mount add, run `git ls-files -o -i --exclude-standard --directory` and `git rev-parse`. Mount the workspace rw, then layer ro bind mounts over `.git`, the control files, and each pre-existing ignored file/dir, using the Phase 1 mount primitive.

- Strong for paths that exist at snapshot time. Weak for paths created later (nested `.git` from `git clone`, new ignored dirs); small race window.
- The sandbox cannot write `.git`, so it cannot change the tracked set. Index and ignore rules change only on the host.
- `isolait mount refresh` re-snapshots manually.

### Consequences

- Not a git repo: `git-rw` mount is an error telling the user to choose `--rw` or `--ro`. No silent downgrade.
- Subdirectory of a repo: the repo `.git` is above the mount root and simply not visible.
- Worktrees/submodules: when `.git` is a file, resolve the real gitdir and bind it ro at `<ws>/.git` so reads work.
- No git writes in the sandbox (`add`, `commit`, `checkout`, `stash`, `rebase` fail); user commits from the host. `git status/diff/log` work with `GIT_OPTIONAL_LOCKS=0`.
- Ignored dirs like `node_modules` are ro, so installs fail in the sandbox. That fits the threat model (poisoned `postinstall`); the escape is `--rw`.

### Kill criterion

If layered ro binds over a propagated rw clone prove unreliable, or ignored-dir friction is unworkable in practice, fall back to `.git` + control files only (keeps the highest-value protection: hooks and `.git/config` run silently on host).

### Deferred beyond this change

- inotify reconcile loop (re-plan binds on `.git/index` / `.gitignore` / new `.git` entries).
- FUSE passthrough policy filesystem for fully dynamic enforcement (and literal "tracked only"). Concerns: metadata latency, host-edit inotify, dependency weight.
- Per-session scratch overlay so builds can write ignored dirs without touching the host.
- A mode that hides ignored files from reads (secrets), relevant once network egress filtering lands.

## Risks / Trade-offs

- Snapshot gap for newly created paths, mitigated only by refresh/reconcile.
- Users will hit ro `node_modules`; needs a clear error and escape hatch.
- Over-trusting the mode as a boundary; mitigated by wording.

## Open Questions

- Device / socket / SNI-filtering designs: not started. `docker.sock` needs a confirmation UX.
- Does the layered-ro approach interact badly with mount propagation on unmount of the parent workspace (spike needed).
- Exact default error text and `--rw` hint when an install fails on a ro ignored dir.
