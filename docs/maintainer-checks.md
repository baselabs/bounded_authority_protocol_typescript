# Maintainer checks

Maintainers can activate local confidential-identifier checks. Contributors can install the
same hooks without a local policy; they print an inactive notice. Public CI tests the guard
with synthetic identifiers, never the confidential inventory or its digest.

The inventory owner stores the ignored inventory at
`<git-common-dir>/info/private-identifiers`, where
`git rev-parse --path-format=absolute --git-common-dir` resolves `<git-common-dir>`.
Integrity state and an activation marker live under
`<git-common-dir>/info/private-identifier-guard/`, with activation also recorded in local Git
configuration. These files stay outside tracked worktrees and are shared by linked worktrees.
The inventory owner initializes the policy with
`python3 scripts/private_identifier_guard.py --repo "$PWD" initialize --expected-count COUNT`,
using the verified entry count, then installs with `bash scripts/install-hooks.sh`.
Routine installation validates the existing policy without accepting inventory changes.
Missing, changed, partial or unreadable policy state fails closed after activation, including
when the ignored policy directory is removed. Only explicit owner initialization accepts an
updated inventory. Never put the inventory or its digest in source, reviews, issues or CI.

Installation preserves existing hooks and refuses collisions, an alternate `core.hooksPath`,
or installation from a linked worktree. It links only the three top-level hook files.
Pre-commit checks staged paths and bytes; commit-msg checks the raw pending message, including
comments and verbose diffs. Pre-push checks outgoing commits, messages, introduced paths and
blobs, pushed refs, tags and terminal objects. New remote refs scan their full ancestry.
Automatic merge, rebase, cherry-pick and mail-application commits can skip commit checks;
pre-push is their local backstop. For deletion-only cleanup, use `git rm -- path` and a clean
explicit commit message, without confidential paths.

After the identifier guard, pre-commit runs readable, executable regular files from
`scripts/hooks/pre-commit.d/` in byte-sorted order, including hidden entries. Invalid entries,
symlinks and the first nonzero result stop the commit. A missing or empty directory is valid;
this repository supplies no extensions.

Run `python3 scripts/test_private_identifier_guard.py` for the standalone real-Git tests.
CI runs this test once in its secret-scan job.
Public CI cannot attest to confidential-term coverage. The inventory owner must confirm it;
other hosts, web edits, provider merges and bypassed hooks remain outside local enforcement.
