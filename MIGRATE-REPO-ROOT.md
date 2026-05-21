# Repo-root rename runbook

The product, binary, crates, config, state directory, env vars, CI, docs,
and frontend have all been renamed from `nyx-agent` / `nyx-pro` to
`nyctos`. The one piece that an agent session cannot do for itself is
move the directory it is currently running inside.

Run these commands as the operator from a shell that is **not** inside
`/Users/elipeter/nyx-pro/`:

```bash
cd /Users/elipeter

# Make sure the daemon is not running. The clean-cut rename did not
# preserve the legacy binary name, so any `nyx-agent` process still
# alive is unrelated to this repo and should be killed independently
# if you want to free the loopback port.
pkill -f nyctos 2>/dev/null || true

# Stash any in-flight working-tree edits (including untracked files)
# inside the repo before the move so they survive the rename.
git -C nyx-pro stash push -u -m "pre-rename stash" 2>/dev/null || true

# Move the repo directory.
mv nyx-pro nyctos

# Re-enter and pop the stash.
cd nyctos
git stash pop 2>/dev/null || true
```

After the move, reset any IDE / shell / editor / tmux / direnv state
that hardcoded the old absolute path (`/Users/elipeter/nyx-pro/`).
Worktrees created by previous `pitboss grind` runs under
`.pitboss/grind/runs/*/worktrees/session-*` reference the old path; they
are gitignored and safe to remove (`rm -rf .pitboss/grind/runs/*/worktrees/`)
if a future grind session needs them rebuilt from scratch.

Once the move is complete, future grind sessions invoked from
`/Users/elipeter/nyctos/` will pick up slice L (final full sweep), which
removes this runbook, retires the rename prompt itself, and verifies
that `git ls-files | xargs grep` returns zero hits for any legacy
identifier in the working tree.

Until slice L runs, two intentional residues remain in the tracked
working tree:

- `.ci/banned-phrases.txt` lists `Nyx Pro` as a banned phrase so
  voice-lint will catch any regression. The voice-lint script
  explicitly excludes this file from its scan.
- `crates/nyctos/nyx_exploration.sentinel` is an out-of-band AI
  exploration log that the dynamic-verifier tests append to on every
  run. Its historical entries reference the old crate paths because
  they were written before the F-series renames landed. It is not
  source code; subsequent runs will append fresh entries against the
  current tree, and the file can be rewritten / truncated separately.
