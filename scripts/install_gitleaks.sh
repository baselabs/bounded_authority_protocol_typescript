#!/bin/sh
set -eu

version='8.30.1'
linux_x64_sha256='551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb'

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

verify_checksum() {
  file=$1
  expected=$2
  actual=$(sha256_file "$file")
  if [ "$actual" != "$expected" ]; then
    echo "gitleaks archive checksum mismatch" >&2
    return 1
  fi
}

if [ "${1:-}" = '--check' ]; then
  check_dir=$(mktemp -d "${TMPDIR:-/tmp}/bap-gitleaks-checksum.XXXXXX")
  trap 'rm -rf "$check_dir"' EXIT HUP INT TERM
  printf 'checksum probe\n' > "$check_dir/input"
  if verify_checksum "$check_dir/input" '0000000000000000000000000000000000000000000000000000000000000000' > "$check_dir/stdout" 2> "$check_dir/stderr"; then
    echo "checksum mismatch self-check did not fail" >&2
    exit 1
  fi
  grep -q 'checksum mismatch' "$check_dir/stderr"
  echo "gitleaks checksum verification self-check passed"
  exit 0
fi

destination=${1:?"usage: scripts/install_gitleaks.sh DESTINATION_DIRECTORY"}
if [ "$(uname -s)" != 'Linux' ] || [ "$(uname -m)" != 'x86_64' ]; then
  echo "automatic gitleaks installation supports Linux x86_64 only; install gitleaks 8.30.1 from the official release" >&2
  exit 1
fi

work_dir=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/bap-gitleaks-install.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM
archive="$work_dir/gitleaks.tar.gz"
curl -fsSLo "$archive" "https://github.com/gitleaks/gitleaks/releases/download/v${version}/gitleaks_${version}_linux_x64.tar.gz"
verify_checksum "$archive" "$linux_x64_sha256"
mkdir -p "$destination"
tar -xzf "$archive" -C "$destination" gitleaks
"$destination/gitleaks" version | grep -Fx "$version" >/dev/null
echo "installed gitleaks $version"
