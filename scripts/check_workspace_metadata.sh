#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp_file=""

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ -n "$tmp_file" ] &&
     { [ -e "$tmp_file" ] || [ -L "$tmp_file" ]; }; then
    case "$tmp_file" in
      /tmp/omnis-metadata.*) rm -f -- "$tmp_file" || status=1 ;;
      *)
        printf 'metadata error: refusing unsafe cleanup path: %s\n' "$tmp_file" >&2
        status=1
        ;;
    esac
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
  printf 'metadata error: interrupted by %s\n' "$1" >&2
  exit "$signal_status"
}

trap cleanup EXIT
trap 'exit_on_signal HUP' HUP
trap 'exit_on_signal INT' INT
trap 'exit_on_signal TERM' TERM

for command_name in cargo dirname find jq mktemp rm sort; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'metadata error: %s is required\n' "$command_name" >&2
    exit 1
  }
done

tmp_file=$(mktemp /tmp/omnis-metadata.XXXXXX) || {
  printf 'metadata error: mktemp failed\n' >&2
  exit 1
}
[ -f "$tmp_file" ] && [ ! -L "$tmp_file" ] || {
  printf 'metadata error: temporary file is unsafe\n' >&2
  exit 1
}

cd "$repo_root"
cargo metadata --locked --no-deps --format-version 1 > "$tmp_file"

workspace_count=$(jq '[.packages[] | select(.source == null)] | length' "$tmp_file")
[ "$workspace_count" -gt 0 ] || {
  printf 'metadata error: workspace package scan set is empty\n' >&2
  exit 1
}

violations=$(jq -r '
  .packages[]
  | select(.source == null)
  | select(
      .publish != [] or
      .license != "MIT" or
      .repository != "https://github.com/jourdanlabs/omniscode" or
      .homepage != "https://github.com/jourdanlabs/omniscode"
    )
  | [
      .name,
      ("publish=" + (.publish | tostring)),
      ("license=" + (.license | tostring)),
      ("repository=" + (.repository | tostring)),
      ("homepage=" + (.homepage | tostring))
    ]
  | @tsv
' "$tmp_file")

if [ -n "$violations" ]; then
  printf 'metadata error: publishable or metadata-incomplete workspace packages:\n%s\n' \
    "$violations" >&2
  exit 1
fi

product_count=$(jq '[.packages[] | select(.source == null and .name == "omnis-key-cli" and .version == "0.1.0")] | length' "$tmp_file")
[ "$product_count" -eq 1 ] || {
  printf 'metadata error: expected exactly one omnis-key-cli package at 0.1.0\n' >&2
  exit 1
}

executable_targets=$(jq --arg repo_prefix "$repo_root/" -r '
  [
    .packages[]
    | select(.source == null) as $package
    | .targets[]
    | select(any(.kind[]; . == "bin" or . == "example" or . == "bench"))
    | {
        package: $package.name,
        target: .name,
        kind: (.kind | join(",")),
        crate_types: (.crate_types | join(",")),
        path: (.src_path | ltrimstr($repo_prefix))
      }
  ]
  | sort_by(.package, .target, .kind, .crate_types, .path)
  | .[]
  | [.package, .target, .kind, .crate_types, .path]
  | @tsv
' "$tmp_file")
expected_executable_targets=$(printf '%s\n%s' \
  $'jcode\tjcode\tbin\tbin\tsrc/main.rs' \
  $'omnis-key-cli\tomnis-key\tbin\tbin\tcrates/omnis-key-cli/src/main.rs')

[ "$executable_targets" = "$expected_executable_targets" ] || {
  printf '%s\n' \
    'metadata error: V1 executable target set differs from the exact jcode + omnis-key allowlist' \
    'expected:' "$expected_executable_targets" \
    'actual:' "${executable_targets:-<empty>}" >&2
  exit 1
}

workspace_manifests=$(jq --arg repo_prefix "$repo_root/" -r '
  [
    .packages[]
    | select(.source == null)
    | .manifest_path
    | select(startswith($repo_prefix))
    | ltrimstr($repo_prefix)
  ]
  | sort
  | .[]
' "$tmp_file")
release_tree_manifests=$(
  find . -type f -name Cargo.toml \
    ! -path './.git/*' \
    ! -path './target/*' |
    while IFS= read -r manifest; do
      printf '%s\n' "${manifest#./}"
    done |
    LC_ALL=C sort
)

[ "$release_tree_manifests" = "$workspace_manifests" ] || {
  printf '%s\n' \
    'metadata error: Cargo manifests outside the exact workspace are forbidden' \
    'workspace manifests:' "$workspace_manifests" \
    'release-tree manifests:' "${release_tree_manifests:-<empty>}" >&2
  exit 1
}

printf 'workspace metadata verified: packages=%s publishable=0 incomplete=0 product_version=0.1.0 executables=jcode,omnis-key standalone_manifests=0 quarantined_non_v1=0\n' \
  "$workspace_count"
