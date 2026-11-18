#!/bin/sh
# One parser for exact primary and optional compatibility pins in .tool-versions.
# Usage: tool-versions.sh read TOOL... | check TOOL [primary|next]
set -efu

fail() {
  printf 'tool-versions: %s\n' "$*" >&2
  exit 1
}

known_tool() {
  case "$1" in nodejs|deno|bun|python|uv) ;; *) fail "unknown tool: $1" ;; esac
}

exact_version() (
  case "$1" in ''|*[!0-9.]*|.*|*.|*..*) exit 1 ;; esac
  IFS=.
  set -- $1
  [ "$#" -eq 3 ] || exit 1
  for component do
    case "$component" in ''|*[!0-9]*|0[0-9]*) exit 1 ;; esac
  done
)

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
read_pins() {
  seen=' '
  while IFS= read -r line || [ -n "$line" ]; do
    # asdf permits comments and whitespace, but every tool has one or two exact pins.
    line=${line%%#*}
    set -- $line
    [ "$#" -gt 0 ] || continue
    [ "$#" -eq 2 ] || [ "$#" -eq 3 ] || fail 'expected TOOL X.Y.Z [X.Y.Z]'
    known_tool "$1"
    case "$seen" in *" $1 "*) fail "duplicate tool: $1" ;; esac
    seen="$seen$1 "
    exact_version "$2" || fail "$1 requires an exact X.Y.Z version: $2"
    printf '%s=%s\n' "$1" "$2"
    if [ "$#" -eq 3 ]; then
      exact_version "$3" || fail "$1 requires an exact compatibility version: $3"
      [ "$2" != "$3" ] || fail "$1 repeats its primary version as a compatibility lane"
      printf '%s-next=%s\n' "$1" "$3"
    fi
  done < "$root/.tool-versions"
}
pins=$(read_pins) || exit 1

declared() {
  while IFS='=' read -r name value; do
    if [ "$name" = "$1" ]; then
      printf '%s\n' "$value"
      return
    fi
  done <<EOF
$pins
EOF
  return 1
}

command=${1:-}
[ "$#" -gt 0 ] || fail 'expected read TOOL... or check TOOL [primary|next]'
shift
case "$command" in
  read)
    [ "$#" -gt 0 ] || fail 'read requires at least one tool'
    # Validate the complete request before writing any output.
    for tool do
      known_tool "$tool"
      declared "$tool" >/dev/null || fail "absent tool: $tool"
    done
    : "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
    for tool do
      printf '%s=%s\n' "$tool" "$(declared "$tool")" >> "$GITHUB_OUTPUT"
      if lane=$(declared "$tool-next"); then
        printf '%s-next=%s\n' "$tool" "$lane" >> "$GITHUB_OUTPUT"
      fi
    done
    ;;
  check)
    [ "$#" -ge 1 ] && [ "$#" -le 2 ] || fail 'check requires TOOL [primary|next]'
    tool=$1
    known_tool "$tool"
    case "${2:-primary}" in
      primary) pin=$tool ;;
      next) pin=$tool-next ;;
      *) fail "unknown lane: $2" ;;
    esac
    expected=$(declared "$pin") || fail "absent tool or lane: $pin"
    case "$tool" in
      nodejs) actual=$(node --version); actual=${actual#v} ;;
      deno) version=$(deno --version); set -- $version; [ "${1:-}" = deno ] || fail 'unrecognized Deno version'; actual=${2:-} ;;
      bun) actual=$(bun --version) ;;
      python) version=$(python --version); set -- $version; [ "${1:-}" = Python ] || fail 'unrecognized Python version'; actual=${2:-} ;;
      uv) version=$(uv --version); set -- $version; [ "${1:-}" = uv ] || fail 'unrecognized uv version'; actual=${2:-} ;;
    esac
    [ "$actual" = "$expected" ] || fail "$pin version mismatch: declared $expected, installed $actual"
    ;;
  *) fail "unknown command: $command" ;;
esac
