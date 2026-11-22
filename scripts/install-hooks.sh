#!/usr/bin/env bash
set -euo pipefail

# install-hooks.sh: install this repo's tracked git hooks into .git/hooks/.
#
# The hooks live tracked under scripts/hooks/ so they ship with the repo and are
# reviewable in PRs; git itself never tracks .git/hooks/, so a symlink is the
# install step. Idempotent: re-running preserves an already-correct symlink. An
# existing hook with any other target or content is preserved and stops installation.
#
# Why a relative symlink: the target is resolved relative to .git/hooks/, so the
# link survives the repo being moved or the worktree root changing.
#
# Bypass / removal: the hook can be bypassed per-commit with 'git commit --no-verify'
# (documented in CONTRIBUTING.md). To uninstall entirely, remove the symlink from
# .git/hooks/.

die() { printf 'install-hooks.sh: %s\n' "$*" >&2; exit 1; }

initialize_count=""
case "$#" in
  0) ;;
  2)
    [ "$1" = "--initialize-private-identifier-expectation" ] \
      || die "usage: bash scripts/install-hooks.sh [--initialize-private-identifier-expectation COUNT]"
    initialize_count="$2"
    ;;
  *) die "usage: bash scripts/install-hooks.sh [--initialize-private-identifier-expectation COUNT]" ;;
esac

repo_root="$(git rev-parse --show-toplevel 2>/dev/null)" \
  || die "not inside a git work tree"
cd "$repo_root"
git_dir="$(git rev-parse --path-format=absolute --git-dir 2>/dev/null)" \
  || die "cannot resolve the Git directory"
common_dir="$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null)" \
  || die "cannot resolve the common Git directory"
[ "$git_dir" = "$common_dir" ] \
  || die "linked worktree detected; refusing shared hook installation"
if configured_hooks="$(git config --get core.hooksPath 2>/dev/null)"; then
  [ -z "$configured_hooks" ] || die "core.hooksPath is configured; refusing to modify hooks"
else
  [ "$?" -eq 1 ] || die "cannot read core.hooksPath"
fi
hooks_dir="$(git rev-parse --path-format=absolute --git-path hooks 2>/dev/null)" \
  || die "cannot resolve the Git hooks directory"
tracked_dir="$repo_root/scripts/hooks"
mkdir -p "$hooks_dir"

# Preflight every destination before changing policy state or hooks. This avoids
# a partial installation and never overwrites a hook owned by another tool.
for src in "$tracked_dir"/*; do
  [ -f "$src" ] || continue
  name="$(basename "$src")"
  link="$hooks_dir/$name"
  relative_target="$(python3 - "$src" "$hooks_dir" <<'PY'
import os, sys
print(os.path.relpath(sys.argv[1], sys.argv[2]))
PY
)" || die "cannot compute the hook target"
  if [ -e "$link" ] || [ -L "$link" ]; then
    if [ ! -L "$link" ]; then
      die "existing hook collision for $name; preserved"
    fi
    existing_target="$(readlink "$link")" || die "cannot read the hook target"
    if [ "$existing_target" != "$relative_target" ]; then
      die "existing hook collision for $name; preserved"
    fi
  fi
done

guard="$repo_root/scripts/private_identifier_guard.py"
[ -r "$guard" ] || die "private-identifier guard unavailable"
command -v python3 >/dev/null 2>&1 || die "python3 unavailable"
# The guard resolves the shared Git directory itself: its inventory lives at
# info/private-identifiers and its integrity state at info/private-identifier-guard/.
if [ -n "$initialize_count" ]; then
  python3 "$guard" --repo "$repo_root" initialize --expected-count "$initialize_count" \
    || die "private-identifier expectation initialization failed"
else
  python3 "$guard" --repo "$repo_root" validate-policy \
    || die "private-identifier expectation validation failed"
fi

installed=0
for src in "$tracked_dir"/*; do
  [ -f "$src" ] || continue
  name="$(basename "$src")"
  link="$hooks_dir/$name"
  relative_target="$(python3 - "$src" "$hooks_dir" <<'PY'
import os, sys
print(os.path.relpath(sys.argv[1], sys.argv[2]))
PY
)" || die "cannot compute the hook target"
  chmod +x "$src"
  if [ ! -L "$link" ]; then
    ln -s "$relative_target" "$link"
  fi
  printf 'linked %s\n' "$name"
  installed=$((installed + 1))
done

if [ "$installed" -eq 0 ]; then
  die "no hooks found under $tracked_dir"
fi

printf '\n%s hook(s) installed. Bypass a single commit with: git commit --no-verify\n' "$installed"
