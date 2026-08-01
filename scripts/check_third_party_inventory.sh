#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
inventory="$repo_root/THIRD_PARTY_ASSETS.json"
tmp_dir=""

die() {
  printf 'inventory error: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ -n "$tmp_dir" ] &&
     { [ -e "$tmp_dir" ] || [ -L "$tmp_dir" ]; }; then
    case "$tmp_dir" in
      /tmp/omnis-inventory.*)
        if [ -d "$tmp_dir" ] && [ ! -L "$tmp_dir" ]; then
          rm -rf -- "$tmp_dir" || status=1
        else
          printf 'inventory error: temporary root became unsafe\n' >&2
          status=1
        fi
        ;;
      *)
        printf 'inventory error: refusing unsafe cleanup path: %s\n' "$tmp_dir" >&2
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
  printf 'inventory error: interrupted by %s\n' "$1" >&2
  exit "$signal_status"
}

trap cleanup EXIT
trap 'exit_on_signal HUP' HUP
trap 'exit_on_signal INT' INT
trap 'exit_on_signal TERM' TERM

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print tolower($1)}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print tolower($1)}'
  else
    die "no SHA-256 implementation found"
  fi
}

for command_name in awk chmod cmp diff find git grep jq mktemp rm sort tr; do
  command -v "$command_name" >/dev/null 2>&1 ||
    die "$command_name is required"
done
[ -f "$inventory" ] || die "missing THIRD_PARTY_ASSETS.json"

tmp_dir=$(mktemp -d /tmp/omnis-inventory.XXXXXX) || die "mktemp failed"
chmod 700 "$tmp_dir" || die "could not make temporary directory private"
[ ! -L "$tmp_dir" ] || die "temporary directory is a symlink"

jq -e '
  .schemaVersion == 1 and
  (.inventoryScope | type == "string" and length > 0) and
  (.upstreamBaseCommit | test("^[0-9a-f]{40}$")) and
  (.assets | type == "array" and length > 0) and
  (.licenseFiles | type == "array" and length > 0) and
  (.unknownOrIncompatibleRights == []) and
  (all(.assets[];
    (.path | type == "string" and length > 0) and
    (.sha256 | test("^[0-9a-f]{64}$")) and
    (.category | type == "string" and length > 0) and
    (.source | type == "string" and length > 0) and
    (.copyright | type == "string" and length > 0) and
    (.license | type == "string" and length > 0) and
    (.redistribution | startswith("allowed")) and
    (.requiredNotice | type == "string" and length > 0)
  ))
' "$inventory" >/dev/null || die "inventory schema, rights, or redistribution status is invalid"

jq -r '.assets[].path' "$inventory" | LC_ALL=C sort > "$tmp_dir/inventory-paths"
jq -r '.assets[].path' "$inventory" | LC_ALL=C sort -u > "$tmp_dir/inventory-paths-unique"
cmp -s "$tmp_dir/inventory-paths" "$tmp_dir/inventory-paths-unique" ||
  die "duplicate asset path in inventory"

(
  cd "$repo_root"
  git ls-files |
    while IFS= read -r path; do
      [ -e "$path" ] || [ -L "$path" ] || continue
      case "$path" in
        assets/* | */assets/* | */Assets.xcassets/* | */fixtures/* | */testdata/* | \
        crates/jcode-base/src/prompt/* | crates/jcode-tui-mermaid/examples/*fixture*.json | \
        scripts/*.json | scripts/*.tsv | \
        *.png | *.jpg | *.jpeg | *.gif | *.webp | *.svg | *.ico | *.icns | \
        *.ttf | *.otf | *.woff | *.woff2 | *.mp4 | *.mov | *.webm | *.wav | \
        *.mp3 | *.onnx | *.safetensors)
          printf '%s\n' "$path"
          ;;
      esac
    done
) | LC_ALL=C sort -u > "$tmp_dir/selected-paths"

[ -s "$tmp_dir/selected-paths" ] || die "asset selector returned an empty scan set"
if ! cmp -s "$tmp_dir/selected-paths" "$tmp_dir/inventory-paths"; then
  diff -u "$tmp_dir/inventory-paths" "$tmp_dir/selected-paths" >&2 || true
  die "inventory does not exactly cover selected retained assets"
fi

upstream_commit=$(jq -r '.upstreamBaseCommit' "$inventory")
git -C "$repo_root" cat-file -e "$upstream_commit^{commit}" ||
  die "upstream base commit is not available"

while IFS=$'\t' read -r path expected_sha license notice; do
  case "$path" in
    /* | *..*) die "unsafe inventory path: $path" ;;
  esac
  [ -f "$repo_root/$path" ] || die "missing or non-regular asset: $path"
  git -C "$repo_root" ls-files --error-unmatch "$path" >/dev/null 2>&1 ||
    die "asset is not tracked: $path"
  actual_sha=$(sha256_file "$repo_root/$path")
  [ "$actual_sha" = "$expected_sha" ] ||
    die "SHA-256 mismatch for $path: expected $expected_sha, got $actual_sha"
  [ -e "$repo_root/$notice" ] || die "required notice missing for $path: $notice"
  if [ "$license" = "MIT" ]; then
    git -C "$repo_root" cat-file -e "$upstream_commit:$path" ||
      die "MIT inherited-asset provenance is not present at upstream base: $path"
  fi
done < <(jq -r '.assets[] | [.path, .sha256, .license, .requiredNotice] | @tsv' "$inventory")

while IFS=$'\t' read -r path expected_sha; do
  case "$path" in
    third_party/licenses/*) ;;
    *) die "unsafe license-file path: $path" ;;
  esac
  [ -f "$repo_root/$path" ] || die "missing license file: $path"
  actual_sha=$(sha256_file "$repo_root/$path")
  [ "$actual_sha" = "$expected_sha" ] ||
    die "license SHA-256 mismatch for $path: expected $expected_sha, got $actual_sha"
done < <(jq -r '.licenseFiles[] | [.path, .sha256] | @tsv' "$inventory")

license_sha=$(sha256_file "$repo_root/LICENSE")
provenance_license_sha=$(jq -r '.upstream.licenseSha256' "$repo_root/provenance/upstream.json")
[ "$license_sha" = "$provenance_license_sha" ] ||
  die "root LICENSE no longer matches upstream provenance"

if [ -f "$repo_root/.gitmodules" ] || git -C "$repo_root" ls-files | grep -q '^vendor/'; then
  die "submodule or vendored dependency present but V1 inventory declares none"
fi
if [ -f "$repo_root/.gitattributes" ] &&
   grep -Eiq 'filter[[:space:]]*=[[:space:]]*lfs|filter=lfs' "$repo_root/.gitattributes"; then
  die "Git LFS is configured but V1 inventory declares no LFS objects"
fi

printf 'third-party inventory verified: assets=%s license_files=%s unknown_rights=0\n' \
  "$(jq '.assets | length' "$inventory")" \
  "$(jq '.licenseFiles | length' "$inventory")"
