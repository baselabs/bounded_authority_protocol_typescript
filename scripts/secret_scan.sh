#!/usr/bin/env bash
set -euo pipefail

expected_version='8.30.1'

repo_root=$(git rev-parse --show-toplevel 2>/dev/null) || {
  echo "secret scan must run inside a Git repository" >&2
  exit 1
}
config="$repo_root/.gitleaks.toml"

require_version() {
  expected=$1
  if ! command -v gitleaks >/dev/null 2>&1; then
    echo "gitleaks $expected is required; install the official release and place it on PATH" >&2
    return 1
  fi
  actual=$(gitleaks version 2>/dev/null) || {
    echo "could not read the gitleaks version; install gitleaks $expected" >&2
    return 1
  }
  if [ "$actual" != "$expected" ]; then
    echo "gitleaks $expected is required; found $actual. Install the official $expected release." >&2
    return 1
  fi
}

run_gitleaks() {
  GIT_CONFIG_GLOBAL=/dev/null \
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_NO_REPLACE_OBJECTS=1 \
    GIT_CONFIG_COUNT=3 \
    GIT_CONFIG_KEY_0=color.ui \
    GIT_CONFIG_VALUE_0=false \
    GIT_CONFIG_KEY_1=diff.noprefix \
    GIT_CONFIG_VALUE_1=false \
    GIT_CONFIG_KEY_2=diff.mnemonicPrefix \
    GIT_CONFIG_VALUE_2=false \
    gitleaks "$@"
}

run_git_isolated() {
  GIT_CONFIG_GLOBAL=/dev/null \
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_NO_REPLACE_OBJECTS=1 \
    GIT_CONFIG_COUNT=3 \
    GIT_CONFIG_KEY_0=color.ui \
    GIT_CONFIG_VALUE_0=false \
    GIT_CONFIG_KEY_1=diff.noprefix \
    GIT_CONFIG_VALUE_1=false \
    GIT_CONFIG_KEY_2=diff.mnemonicPrefix \
    GIT_CONFIG_VALUE_2=false \
    git "$@"
}

assert_history_safe() {
  scan_root=$1
  if [ "${GIT_GRAFT_FILE+x}" = 'x' ]; then
    echo "secret history scan refuses GIT_GRAFT_FILE" >&2
    return 1
  fi
  if [ "${GIT_SHALLOW_FILE+x}" = 'x' ]; then
    echo "secret history scan refuses GIT_SHALLOW_FILE" >&2
    return 1
  fi
  if [ "${GIT_REPLACE_REF_BASE+x}" = 'x' ]; then
    echo "secret history scan refuses GIT_REPLACE_REF_BASE" >&2
    return 1
  fi
  shallow=$(git --no-replace-objects -C "$scan_root" rev-parse --is-shallow-repository)
  if [ "$shallow" != 'false' ]; then
    echo "secret history scan requires a complete, non-shallow repository" >&2
    return 1
  fi
  replace_refs=$(git --no-replace-objects -C "$scan_root" for-each-ref --format='%(refname)' refs/replace)
  if [ -n "$replace_refs" ]; then
    echo "secret history scan refuses Git replace refs" >&2
    return 1
  fi
  grafts=$(git --no-replace-objects -C "$scan_root" rev-parse --git-path info/grafts)
  case "$grafts" in
    /*) ;;
    *) grafts="$scan_root/$grafts" ;;
  esac
  if [ -s "$grafts" ]; then
    echo "secret history scan refuses Git grafts" >&2
    return 1
  fi
}

history_scan() (
  assert_history_safe "$repo_root"
  if ! run_git_isolated -C "$repo_root" log -p -U0 \
    --full-history --diff-merges=separate HEAD -- >/dev/null; then
    echo "secret history scan could not read history under the scanner's isolated Git configuration" >&2
    exit 1
  fi
  run_gitleaks git --config "$config" --redact=100 --no-banner --exit-code 42 \
    --log-opts='--full-history --diff-merges=separate HEAD' "$repo_root"
)

staged_scan() {
  run_gitleaks git --config "$config" --redact=100 --no-banner --exit-code 42 \
    --staged "$repo_root"
}

unstaged_scan() {
  run_gitleaks git --config "$config" --redact=100 --no-banner --exit-code 42 \
    --pre-commit "$repo_root"
}

run_check() (
  require_version "$expected_version"
  check_dir=$(mktemp -d "${TMPDIR:-/tmp}/bap-ts-secret-check.XXXXXX")
  trap 'rm -rf "$check_dir"' EXIT HUP INT TERM
  # A scratch copy outside the repository carries a synthetic, obviously fake key.
  mkdir "$check_dir/tree"
  cp "$config" "$check_dir/tree/.gitleaks.toml"
  python3 - "$check_dir/tree/probe.txt" <<'PYPROBE'
from pathlib import Path
import sys, hashlib
# Build the fake pattern at runtime, never write it into this repository or its history.
Path(sys.argv[1]).write_text("gh" + "p_" + hashlib.sha256(b"obviously fake scanner positive control").hexdigest()[:36] + "\n")
PYPROBE
  set +e
  run_gitleaks dir --config "$config" --redact=100 --no-banner --exit-code 42 \
    --report-format json --report-path "$check_dir/report.json" "$check_dir/tree" \
    > "$check_dir/stdout" 2> "$check_dir/stderr"
  scan_exit=$?
  set -e
  python3 - "$check_dir" "$scan_exit" <<'PYPROBE'
from pathlib import Path
import json, sys
root = Path(sys.argv[1])
if sys.argv[2] != "42":
    raise SystemExit("secret scanner missed the synthetic key or failed unexpectedly (exit " + sys.argv[2] + ")\n" + (root / "stderr").read_text())
findings = json.loads((root / "report.json").read_text())
if not any(f["RuleID"] == "github-pat" and f["File"].endswith("probe.txt") for f in findings):
    raise SystemExit("secret scanner did not identify the synthetic key")
probe = (root / "tree/probe.txt").read_text().strip()
if any(probe in (root / name).read_text() for name in ["stdout", "stderr", "report.json"]):
    raise SystemExit("scanner did not redact its output")
print("secret scan positive control: PASS (synthetic key caught and redacted)")
PYPROBE
  rm "$check_dir/tree/probe.txt"
  run_gitleaks dir --config "$config" --redact=100 --no-banner "$check_dir/tree"
  echo "secret scan restored scratch tree: PASS"
)

require_version "$expected_version"
case "${1:-local}" in
  --check) run_check ;;
  --history) history_scan ;;
  local) run_check; history_scan; staged_scan; unstaged_scan ;;
  *) echo "usage: scripts/secret_scan.sh [--check|--history]" >&2; exit 1 ;;
esac
