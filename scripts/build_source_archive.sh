#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ref=HEAD
output=""
tmp_archive=""

usage() {
  printf 'Usage: scripts/build_source_archive.sh --output PATH [--ref COMMIT]\n'
}

die() {
  printf 'archive error: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ -n "$tmp_archive" ] &&
     { [ -e "$tmp_archive" ] || [ -L "$tmp_archive" ]; }; then
    rm -f -- "$tmp_archive" || status=1
  fi
  exit "$status"
}

exit_on_signal() {
  case "$1" in
    HUP) signal_status=129 ;;
    INT) signal_status=130 ;;
    TERM) signal_status=143 ;;
    *) signal_status=1 ;;
  esac
  printf 'archive error: interrupted by %s\n' "$1" >&2
  exit "$signal_status"
}

trap cleanup EXIT
trap 'exit_on_signal HUP' HUP
trap 'exit_on_signal INT' INT
trap 'exit_on_signal TERM' TERM

while [ "$#" -gt 0 ]; do
  case "$1" in
    --ref)
      [ "$#" -ge 2 ] || die "--ref requires a value"
      ref=$2
      shift 2
      ;;
    --output)
      [ "$#" -ge 2 ] || die "--output requires a value"
      output=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

for command_name in awk chmod cut dirname git mktemp mv python3 rm; do
  command -v "$command_name" >/dev/null 2>&1 ||
    die "$command_name is required"
done

[ -n "$output" ] || die "--output is required"
case "$output" in
  /*) ;;
  *) output="$PWD/$output" ;;
esac
[ ! -e "$output" ] && [ ! -L "$output" ] || die "output already exists"
output_parent=$(dirname "$output")
[ -d "$output_parent" ] && [ ! -L "$output_parent" ] ||
  die "output parent must be an existing non-symlink directory"

candidate=$(git -C "$repo_root" rev-parse --verify "$ref^{commit}") ||
  die "ref is not a commit: $ref"
short=$(printf '%s' "$candidate" | cut -c1-12)
product_version=$(
  git -C "$repo_root" show "$candidate:crates/omnis-key-cli/Cargo.toml" |
    awk '
      /^\[package\][[:space:]]*$/ { in_package=1; next }
      /^\[/ { in_package=0 }
      in_package && /^[[:space:]]*version[[:space:]]*=/ {
        line=$0
        sub(/^[^=]*=[[:space:]]*"/, "", line)
        sub(/"[[:space:]]*$/, "", line)
        print line
        count++
      }
      END { if (count != 1) exit 1 }
    '
) || die "could not resolve canonical product version from candidate"
[ "$product_version" = "0.1.0" ] ||
  die "candidate product version must be 0.1.0, got $product_version"
prefix="omniscode-v${product_version}-${short}/"

tmp_archive=$(mktemp "$output_parent/.omnis-source.XXXXXX") ||
  die "could not create output temporary file"
chmod 600 "$tmp_archive" || die "could not protect output temporary file"

git -C "$repo_root" archive --format=tar --prefix="$prefix" "$candidate" |
  python3 "$repo_root/scripts/canonical_gzip.py" > "$tmp_archive"
[ -s "$tmp_archive" ] || die "archive output is empty"
mv "$tmp_archive" "$output"
tmp_archive=""
chmod 600 "$output" || die "could not set archive mode"

printf 'source archive built: commit=%s prefix=%s path=%s\n' \
  "$candidate" "$prefix" "$output"
