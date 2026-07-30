#!/bin/bash
# Create a local-file-only fresh clone, retain creation proof, then run its suite.
set -euo pipefail

if [ "$#" -ne 4 ]; then
  printf 'usage: prepare_builder_platform_suite.sh SOURCE_REPO PLATFORM CLONE_DESTINATION OUTPUT_DIR\n' >&2
  exit 2
fi

source_repo=$1
platform=$2
clone_destination=$3
output_dir=$4

[ -d "$source_repo" ] && [ ! -L "$source_repo" ] || {
  printf 'builder preparation error: source repository is absent or unsafe\n' >&2
  exit 2
}
source_repo=$(cd "$source_repo" && pwd -P)

case "$platform" in
  linux | macos) ;;
  *)
    printf 'builder preparation error: platform must be linux or macos\n' >&2
    exit 2
    ;;
esac

[ ! -L "$output_dir" ] || {
  printf 'builder preparation error: output directory is a symlink\n' >&2
  exit 2
}
/bin/mkdir -p "$output_dir"
/bin/chmod 700 "$output_dir"
output_dir=$(cd "$output_dir" && pwd -P)

case "$clone_destination" in
  /*) ;;
  *) clone_destination="$PWD/$clone_destination" ;;
esac
clone_parent=$(/usr/bin/dirname "$clone_destination")
[ -d "$clone_parent" ] && [ ! -L "$clone_parent" ] || {
  printf 'builder preparation error: clone parent is absent or unsafe\n' >&2
  exit 2
}
clone_parent=$(cd "$clone_parent" && pwd -P)
clone_destination="$clone_parent/$(/usr/bin/basename "$clone_destination")"

marker="$output_dir/${platform}-fresh-clone-marker.json"
creation_receipt="$output_dir/${platform}-fresh-clone-created.txt"
printf -v quoted_destination '%q' "$clone_destination"
printf -v quoted_marker '%q' "$marker"
creation_command="scripts/create_builder_fresh_clone.py --platform $platform --source . --candidate HEAD --destination $quoted_destination --marker $quoted_marker"

"$source_repo/scripts/run_builder_receipt.sh" \
  "$source_repo" \
  "$platform" \
  "${platform}-fresh-clone-created" \
  "$creation_receipt" \
  "$creation_command"

"$clone_destination/scripts/run_builder_platform_suite.sh" \
  "$clone_destination" \
  "$platform" \
  "$output_dir" \
  "$marker"
