# Environment: the `Documents/Developers` symlink, and what depends on it

**Status: no authorization is sought here, and nothing destructive has been done.**
This records what changed, what depends on it, what is at risk (nothing), and
what removing it would require. The decision is the owner's.

## What happened

macOS/iCloud moved the local `Documents` tree under
`Documents - Leonard's MacBook Pro/`, so the absolute path
`/Users/0x1e0/Documents/Developers/...` — baked into every worktree's `.git`
file and into the main repository's `.git/worktrees/*/gitdir` — stopped
resolving, and git failed with `fatal: not a git repository`.

A symlink was created at 15:11 restoring the old path:

    /Users/0x1e0/Documents/Developers
        -> /Users/0x1e0/Documents/Documents - Leonard's MacBook Pro/Developers

No files were moved to create it. It is one inode; `rm` removes it and moves
nothing.

## Original and current paths

| | path |
|---|---|
| original (pre-move, now the symlink) | `/Users/0x1e0/Documents/Developers` |
| current real location | `/Users/0x1e0/Documents/Documents - Leonard's MacBook Pro/Developers` |
| repository `.git` (authoritative) | `…/Documents - Leonard's MacBook Pro/Developers/sum/protocols/sum-chain/.git` |

## What depends on it

41 worktrees: **31 registered through the old path** and therefore through the
symlink, 4 through the real path, 6 under `/private/tmp`.

## What is at risk: nothing

This is the finding that decides the shape of the plan.

  * **No commit depends on the symlink.** Branches and objects live in the
    repository's own `.git`, which is at the REAL path. The symlink affects how
    worktree PATHS resolve, not where history is stored. 39 branches carry
    unpushed work and none of it is reachable only through the symlink.
  * **No uncommitted work depends on it either.** A scan of all 41 worktrees
    found four with a dirty tree. Three are the tracks currently running. The
    fourth, `laneA-chain`, shows 49 changes that are **all deletions** — 42,983
    lines of tracked source removed from the working tree, with the content
    committed at `2249ca8`. That is damage to recover from, not work to
    preserve.

## The separate hazard the scan surfaced

Six worktrees live under `/private/tmp`: `base-agree`, `base-final`,
`base-remote`, `base-wave2`, `laneA-chain`, `warnbase`. `/private/tmp` is reaped
by the OS. This has already happened twice to `laneA-chain` — six tracked files
earlier in this work, 49 now.

**This is unrelated to the symlink and is the more real risk of the two.** It is
survivable only because every one of those six is a detached or fully-committed
checkout whose content is in the object store. It would not be survivable for a
worktree holding uncommitted work, and no rule currently stops one being created
there.

## Removing the symlink: what it would require

Only if the owner wants the tree moved back rather than aliased.

1. **Do not `rm` it first.** Removing it breaks 31 worktrees immediately, and
   the repair below is easier run while paths still resolve.
2. Move the real tree back:
   `mv "/Users/0x1e0/Documents/Documents - Leonard's MacBook Pro/Developers" /Users/0x1e0/Documents/Developers`
   after removing the symlink in the same step — the symlink occupies the target
   name.
3. From the main repository, `git worktree repair` rewrites the pointers in both
   directions for every worktree whose path still exists.
4. Verify: every worktree resolves
   (`git -C <path> rev-parse --git-dir` for each of the 41), no branch lost
   commits (`git rev-list --count <branch> --not --remotes` unchanged per
   branch), and no worktree gained uncommitted deletions.
5. If iCloud re-nests `Documents` again, this recurs. The durable fix is to keep
   the repository outside `~/Documents` entirely, which is a larger move and is
   not proposed here.

**Alternatively, leave the symlink.** It costs nothing, all 41 worktrees
resolve, and no work depends on its removal. That is the recommendation.

## Verification performed

  * all 41 worktrees resolve (`rev-parse --git-dir` on each: 0 failures)
  * 39 branches with unpushed work enumerated; commit storage confirmed at the
    real path, independent of the symlink
  * dirty-tree scan across all 41 worktrees; the one non-agent dirty tree
    inspected file by file and found to be deletions of committed content
