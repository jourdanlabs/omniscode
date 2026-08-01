#!/usr/bin/env bash
# Fail-closed OMNIS V1 security, dependency, license, and artifact preflight.
# Compatible with the macOS system Bash 3.2.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tools_file="$repo_root/config/security/tools.env"
exceptions_file="$repo_root/config/security/advisory_exceptions.json"
deny_config="$repo_root/config/security/deny.toml"
object_materializer="$repo_root/scripts/materialize_git_objects.py"

candidate_ref=HEAD
base_commit=a3a24cdb3aee97ebb43fe84e79bfa63828f3a39a
archive_path=""
report_path=""
advisory_db=""
private_tmp=""
report_tmp=""
report_sidecar_tmp=""
sha256_tool_path=""
sha256_tool_mode=""

usage() {
  cat <<'USAGE'
Usage:
  scripts/security_preflight.sh \
    --archive PATH \
    --report PATH \
    --advisory-db PATH \
    [--candidate-ref COMMIT] \
    [--base-commit COMMIT]

The candidate must be the clean checked-out HEAD. Every scanner and database
identity is pinned in config/security/tools.env. No scan leg is optional.
USAGE
}

plain_error() {
  printf 'security preflight error: %s\n' "$*" >&2
}

die() {
  plain_error "$*"
  exit 1
}

remove_private_tmp() {
  [ -n "$private_tmp" ] || return 0
  case "$private_tmp" in
    /tmp/omnis-security.*) ;;
    *)
      plain_error "refusing to clean unexpected temporary path: $private_tmp"
      return 1
      ;;
  esac
  [ ! -L "$private_tmp" ] || {
    plain_error "temporary root became a symlink"
    return 1
  }
  if [ "${OMNIS_PREFLIGHT_ENABLE_TEST_HOOKS:-0}" = "1" ] &&
     [ "${OMNIS_PREFLIGHT_TEST_FAIL_CLEANUP:-0}" = "1" ]; then
    plain_error "injected cleanup failure"
    return 1
  fi
  rm -rf -- "$private_tmp" || return 1
  [ ! -e "$private_tmp" ] && [ ! -L "$private_tmp" ] || return 1
  private_tmp=""
}

cleanup_on_exit() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ -n "$report_tmp" ] && { [ -e "$report_tmp" ] || [ -L "$report_tmp" ]; }; then
    rm -f -- "$report_tmp" || status=1
  fi
  if [ -n "$report_sidecar_tmp" ] &&
     { [ -e "$report_sidecar_tmp" ] || [ -L "$report_sidecar_tmp" ]; }; then
    rm -f -- "$report_sidecar_tmp" || status=1
  fi
  if ! remove_private_tmp; then
    plain_error "temporary cleanup failed"
    status=1
  fi
  exit "$status"
}

exit_on_signal() {
  signal_name=$1
  case "$signal_name" in
    HUP) signal_status=129 ;;
    INT) signal_status=130 ;;
    TERM) signal_status=143 ;;
    *)
      plain_error "unexpected signal handler invocation: $signal_name"
      signal_status=1
      ;;
  esac
  plain_error "interrupted by $signal_name"
  exit "$signal_status"
}

sha256_file() {
  case "$sha256_tool_mode" in
    sha256sum)
      sha256_output=$("$sha256_tool_path" "$1") ||
        die "SHA-256 command failed for $1"
      ;;
    shasum)
      sha256_output=$("$sha256_tool_path" -a 256 "$1") ||
        die "SHA-256 command failed for $1"
      ;;
    *)
      die "trusted SHA-256 tool was not selected"
      ;;
  esac
  printf '%s\n' "${sha256_output%% *}"
}

sha256_stdin() {
  case "$sha256_tool_mode" in
    sha256sum)
      sha256_output=$("$sha256_tool_path") ||
        die "SHA-256 command failed for standard input"
      ;;
    shasum)
      sha256_output=$("$sha256_tool_path" -a 256) ||
        die "SHA-256 command failed for standard input"
      ;;
    *)
      die "trusted SHA-256 tool was not selected"
      ;;
  esac
  printf '%s\n' "${sha256_output%% *}"
}

count_regular_files() {
  find "$1" -type f -print | wc -l | tr -d ' '
}

create_private_dir() {
  path=$1
  [ ! -e "$path" ] && [ ! -L "$path" ] || return 1
  mkdir "$path" || return 1
  chmod 700 "$path" || return 1
  [ -d "$path" ] && [ ! -L "$path" ]
}

run_gitleaks_dir() {
  label=$1
  target=$2
  output=$3
  [ -d "$target" ] && [ ! -L "$target" ] || die "$label scan target is unsafe"
  scan_count=$(count_regular_files "$target")
  if [ "${OMNIS_PREFLIGHT_ENABLE_TEST_HOOKS:-0}" = "1" ] &&
     [ "${OMNIS_PREFLIGHT_TEST_EMPTY_SCAN_LABEL:-}" = "$label" ]; then
    scan_count=0
  fi
  [ "$scan_count" -gt 0 ] || die "$label scan set is empty"
  if [ "${OMNIS_PREFLIGHT_ENABLE_TEST_HOOKS:-0}" = "1" ] &&
     [ "${OMNIS_PREFLIGHT_TEST_CRASH_SCAN_LABEL:-}" = "$label" ]; then
    scan_status=70
  else
    set +e
    (
      cd "$private_tmp/scanner-cwd" &&
        "$gitleaks_path" dir "$target" --no-banner --redact --report-format json \
          --report-path "$output"
    ) >/dev/null 2>"$output.stderr"
    scan_status=$?
    set -e
  fi
  case "$scan_status" in
    0)
      [ -f "$output" ] && [ ! -L "$output" ] ||
        die "$label secret scan produced no regular report"
      jq -e 'type == "array" and length == 0' "$output" >/dev/null ||
        die "$label clean report is invalid or contains findings"
      scan_report_sha256=$(sha256_file "$output")
      printf '%s\t%s\t0\tSCAN_CLEAN\t%s\n' \
        "$label" "$scan_count" "$scan_report_sha256" \
        >> "$private_tmp/secret-status.tsv"
      ;;
    1)
      die "$label secret scan detected potential secret material"
      ;;
    *)
      die "$label secret scan incomplete or scanner crashed (exit $scan_status)"
      ;;
  esac
}

run_gitleaks_git() {
  label=$1
  log_options=$2
  scan_count=$3
  output=$4
  if [ "${OMNIS_PREFLIGHT_ENABLE_TEST_HOOKS:-0}" = "1" ] &&
     [ "${OMNIS_PREFLIGHT_TEST_EMPTY_SCAN_LABEL:-}" = "$label" ]; then
    scan_count=0
  fi
  [ "$scan_count" -gt 0 ] || die "$label Git scan set is empty"
  if [ "${OMNIS_PREFLIGHT_ENABLE_TEST_HOOKS:-0}" = "1" ] &&
     [ "${OMNIS_PREFLIGHT_TEST_CRASH_SCAN_LABEL:-}" = "$label" ]; then
    scan_status=70
  else
    set +e
    (
      cd "$private_tmp/scanner-cwd" &&
        "$gitleaks_path" git "$repo_root" --log-opts="$log_options" \
          --no-banner --redact --report-format json --report-path "$output"
    ) >/dev/null 2>"$output.stderr"
    scan_status=$?
    set -e
  fi
  case "$scan_status" in
    0)
      [ -f "$output" ] && [ ! -L "$output" ] ||
        die "$label Git secret scan produced no regular report"
      jq -e 'type == "array" and length == 0' "$output" >/dev/null ||
        die "$label Git clean report is invalid or contains findings"
      scan_report_sha256=$(sha256_file "$output")
      printf '%s\t%s\t0\tSCAN_CLEAN\t%s\n' \
        "$label" "$scan_count" "$scan_report_sha256" \
        >> "$private_tmp/secret-status.tsv"
      ;;
    1)
      die "$label Git secret scan detected potential secret material"
      ;;
    *)
      die "$label Git secret scan incomplete or scanner crashed (exit $scan_status)"
      ;;
  esac
}

trap cleanup_on_exit EXIT
trap 'exit_on_signal HUP' HUP
trap 'exit_on_signal INT' INT
trap 'exit_on_signal TERM' TERM

while [ "$#" -gt 0 ]; do
  case "$1" in
    --candidate-ref)
      [ "$#" -ge 2 ] || die "--candidate-ref requires a value"
      candidate_ref=$2
      shift 2
      ;;
    --base-commit)
      [ "$#" -ge 2 ] || die "--base-commit requires a value"
      base_commit=$2
      shift 2
      ;;
    --archive)
      [ "$#" -ge 2 ] || die "--archive requires a value"
      archive_path=$2
      shift 2
      ;;
    --report)
      [ "$#" -ge 2 ] || die "--report requires a value"
      report_path=$2
      shift 2
      ;;
    --advisory-db)
      [ "$#" -ge 2 ] || die "--advisory-db requires a value"
      advisory_db=$2
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

[ -n "${BASH_VERSION:-}" ] || die "this script must run under Bash"
[ "${BASH_VERSINFO[0]}" -ge 3 ] || die "Bash 3.2 or newer is required"
[ -n "$archive_path" ] || die "--archive is required"
[ -n "$report_path" ] || die "--report is required"
[ -n "$advisory_db" ] || die "--advisory-db is required"

case "$archive_path" in /*) ;; *) archive_path="$PWD/$archive_path" ;; esac
case "$report_path" in /*) ;; *) report_path="$PWD/$report_path" ;; esac
case "$advisory_db" in /*) ;; *) advisory_db="$PWD/$advisory_db" ;; esac

[ -f "$tools_file" ] && [ ! -L "$tools_file" ] || die "pinned tool identity file absent or unsafe"
# shellcheck source=/dev/null
. "$tools_file"

# Candidate-controlled or ambient gitleaks configuration can suppress findings.
# V1 always uses the scanner's pinned embedded defaults.
unset GITLEAKS_CONFIG GITLEAKS_CONFIG_TOML
[ -z "${GITLEAKS_CONFIG+x}" ] && [ -z "${GITLEAKS_CONFIG_TOML+x}" ] ||
  die "could not clear ambient gitleaks configuration overrides"
unset GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_CEILING_DIRECTORIES \
  GIT_COMMON_DIR GIT_CONFIG GIT_CONFIG_PARAMETERS GIT_DIR \
  GIT_DISCOVERY_ACROSS_FILESYSTEM GIT_EXEC_PATH GIT_INDEX_FILE \
  GIT_NAMESPACE GIT_OBJECT_DIRECTORY GIT_PREFIX GIT_REPLACE_REF_BASE \
  GIT_SHALLOW_FILE GIT_WORK_TREE
export GIT_CONFIG_COUNT=0
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_NOSYSTEM=1
export GIT_NO_LAZY_FETCH=1
export GIT_NO_REPLACE_OBJECTS=1
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0

for command_name in \
  awk basename cargo cargo-audit cargo-deny cat chmod cmp cp date dirname find \
  git gitleaks go grep head jq ln mkdir mktemp mv python3 rm rustc sed sort tar \
  tr wc; do
  command -v "$command_name" >/dev/null 2>&1 ||
    die "$command_name absent; scan cannot start"
done
if [ -x /usr/bin/sha256sum ] && [ ! -L /usr/bin/sha256sum ]; then
  sha256_tool_path=/usr/bin/sha256sum
  sha256_tool_mode=sha256sum
elif [ -x /usr/bin/shasum ] && [ ! -L /usr/bin/shasum ]; then
  sha256_tool_path=/usr/bin/shasum
  sha256_tool_mode=shasum
else
  die "trusted operating-system SHA-256 tool absent; scan cannot start"
fi
[ -x /usr/bin/uname ] && [ ! -L /usr/bin/uname ] ||
  die "trusted operating-system uname absent; scan cannot start"

gitleaks_path=$(command -v gitleaks)
cargo_audit_path=$(command -v cargo-audit)
cargo_deny_path=$(command -v cargo-deny)
cargo_path=$(command -v cargo)
rustc_path=$(command -v rustc)
git_path=$(command -v git)
tar_path=$(command -v tar)
go_path=$(command -v go)
python_path=$(command -v python3)
jq_path=$(command -v jq)
gitleaks_executable=$(basename "$gitleaks_path")
cargo_audit_executable=$(basename "$cargo_audit_path")
cargo_deny_executable=$(basename "$cargo_deny_path")
cargo_executable=$(basename "$cargo_path")
rustc_executable=$(basename "$rustc_path")
git_executable=$(basename "$git_path")
tar_executable=$(basename "$tar_path")
go_executable=$(basename "$go_path")
python_executable=$(basename "$python_path")
jq_executable=$(basename "$jq_path")
for executable_path in "$gitleaks_path" "$cargo_audit_path" "$cargo_deny_path"; do
  [ -f "$executable_path" ] && [ -x "$executable_path" ] ||
    die "security executable is not a readable executable file: $executable_path"
done

host_uname_os=$(/usr/bin/uname -s) ||
  die "could not determine security-tool host operating system"
host_uname_arch=$(/usr/bin/uname -m) ||
  die "could not determine security-tool host architecture"
case "$host_uname_os/$host_uname_arch" in
  Darwin/arm64)
    security_tool_os=darwin
    security_tool_architecture=arm64
    expected_gitleaks_sha256=$GITLEAKS_SHA256_DARWIN_ARM64
    expected_cargo_audit_sha256=$CARGO_AUDIT_SHA256_DARWIN_ARM64
    expected_cargo_deny_sha256=$CARGO_DENY_SHA256_DARWIN_ARM64
    ;;
  Linux/arm64 | Linux/aarch64)
    security_tool_os=linux
    security_tool_architecture=arm64
    expected_gitleaks_sha256=$GITLEAKS_SHA256_LINUX_ARM64
    expected_cargo_audit_sha256=$CARGO_AUDIT_SHA256_LINUX_ARM64
    expected_cargo_deny_sha256=$CARGO_DENY_SHA256_LINUX_ARM64
    ;;
  *)
    die "security tool platform is not pinned for V1: $host_uname_os/$host_uname_arch"
    ;;
esac
for expected_tool_sha256 in \
  "$expected_gitleaks_sha256" \
  "$expected_cargo_audit_sha256" \
  "$expected_cargo_deny_sha256"; do
  [ "${#expected_tool_sha256}" -eq 64 ] ||
    die "pinned security executable SHA-256 is malformed for $security_tool_os/$security_tool_architecture"
  case "$expected_tool_sha256" in
    *[!0-9a-f]*)
      die "pinned security executable SHA-256 is malformed for $security_tool_os/$security_tool_architecture"
      ;;
  esac
done

gitleaks_sha256=$(sha256_file "$gitleaks_path")
cargo_audit_sha256=$(sha256_file "$cargo_audit_path")
cargo_deny_sha256=$(sha256_file "$cargo_deny_path")
[ "$gitleaks_sha256" = "$expected_gitleaks_sha256" ] ||
  die "gitleaks executable SHA-256 mismatch for $security_tool_os/$security_tool_architecture"
[ "$cargo_audit_sha256" = "$expected_cargo_audit_sha256" ] ||
  die "cargo-audit executable SHA-256 mismatch for $security_tool_os/$security_tool_architecture"
[ "$cargo_deny_sha256" = "$expected_cargo_deny_sha256" ] ||
  die "cargo-deny executable SHA-256 mismatch for $security_tool_os/$security_tool_architecture"

gitleaks_version_output=$("$gitleaks_path" version 2>&1) ||
  die "gitleaks present but version command failed"
printf '%s\n' "$gitleaks_version_output" | grep -Eq "(^|[^0-9])${GITLEAKS_VERSION}([^0-9]|$)" ||
  die "gitleaks identity mismatch: expected $GITLEAKS_VERSION, got $gitleaks_version_output"

cargo_audit_version_output=$("$cargo_audit_path" --version 2>&1) ||
  die "cargo-audit absent or version command failed"
printf '%s\n' "$cargo_audit_version_output" | grep -Eq "(^|[^0-9])${CARGO_AUDIT_VERSION}([^0-9]|$)" ||
  die "cargo-audit identity mismatch: expected $CARGO_AUDIT_VERSION, got $cargo_audit_version_output"

cargo_deny_version_output=$("$cargo_deny_path" --version 2>&1) ||
  die "cargo-deny absent or version command failed"
printf '%s\n' "$cargo_deny_version_output" | grep -Eq "(^|[^0-9])${CARGO_DENY_VERSION}([^0-9]|$)" ||
  die "cargo-deny identity mismatch: expected $CARGO_DENY_VERSION, got $cargo_deny_version_output"

gitleaks_build_info=$("$go_path" version -m "$gitleaks_path" 2>&1) ||
  die "could not inspect gitleaks build provenance"
gitleaks_build_go_version=$(printf '%s\n' "$gitleaks_build_info" |
  awk 'NR == 1 {print $NF}')
[ "$gitleaks_build_go_version" = "$GITLEAKS_GO_VERSION" ] ||
  die "gitleaks Go toolchain mismatch: expected $GITLEAKS_GO_VERSION, got ${gitleaks_build_go_version:-absent}"
gitleaks_build_goos=$(printf '%s\n' "$gitleaks_build_info" |
  sed -n 's/^[[:space:]]*build[[:space:]][[:space:]]*GOOS=//p')
gitleaks_build_goarch=$(printf '%s\n' "$gitleaks_build_info" |
  sed -n 's/^[[:space:]]*build[[:space:]][[:space:]]*GOARCH=//p')
[ "$gitleaks_build_goos" = "$security_tool_os" ] &&
  [ "$gitleaks_build_goarch" = "$security_tool_architecture" ] ||
  die "gitleaks target mismatch: expected $security_tool_os/$security_tool_architecture, got ${gitleaks_build_goos:-absent}/${gitleaks_build_goarch:-absent}"
gitleaks_build_revision=$(printf '%s\n' "$gitleaks_build_info" |
  sed -n 's/^[[:space:]]*build[[:space:]][[:space:]]*vcs\.revision=//p')
[ "$gitleaks_build_revision" = "$GITLEAKS_SOURCE_COMMIT" ] ||
  die "gitleaks build revision mismatch or absent: expected $GITLEAKS_SOURCE_COMMIT, got ${gitleaks_build_revision:-absent}"
gitleaks_build_modified=$(printf '%s\n' "$gitleaks_build_info" |
  sed -n 's/^[[:space:]]*build[[:space:]][[:space:]]*vcs\.modified=//p')
[ "$gitleaks_build_modified" = "false" ] ||
  die "gitleaks was not built from a clean pinned checkout"
gitleaks_build_info_sha256=$(
  printf '%s\n' "$gitleaks_build_info" | sha256_stdin
)

[ -f "$archive_path" ] && [ ! -L "$archive_path" ] ||
  die "exact release archive is absent, non-regular, or a symlink"
[ -f "$exceptions_file" ] && [ ! -L "$exceptions_file" ] ||
  die "proposed exception file absent or unsafe"
[ -f "$deny_config" ] && [ ! -L "$deny_config" ] ||
  die "license policy absent or unsafe"
[ -f "$object_materializer" ] && [ ! -L "$object_materializer" ] ||
  die "reachable-object materializer absent or unsafe"
for candidate_override in .gitleaks.toml .gitleaksignore; do
  [ ! -e "$repo_root/$candidate_override" ] &&
    [ ! -L "$repo_root/$candidate_override" ] ||
    die "candidate-controlled secret-scan override is forbidden: $candidate_override"
done

[ ! -e "$report_path" ] && [ ! -L "$report_path" ] ||
  die "report path already exists"
[ ! -e "$report_path.sha256" ] && [ ! -L "$report_path.sha256" ] ||
  die "report SHA-256 sidecar already exists"
report_parent=$(dirname "$report_path")
[ -d "$report_parent" ] && [ ! -L "$report_parent" ] ||
  die "report parent must be an existing non-symlink directory"

private_tmp=$(mktemp -d /tmp/omnis-security.XXXXXX) ||
  die "could not create private temporary root"
chmod 700 "$private_tmp" || die "could not make temporary root private"
[ -d "$private_tmp" ] && [ ! -L "$private_tmp" ] ||
  die "temporary root is not a private real directory"

# A hostile TMPDIR or a pre-planted symlink must not redirect any write.
create_private_dir "$private_tmp/adversary-target" ||
  die "could not create temporary-path adversary target"
create_private_dir "$private_tmp/scanner-cwd" ||
  die "could not create configuration-neutral scanner working directory"
ln -s "$private_tmp/adversary-target" "$private_tmp/preplanted" ||
  die "could not plant temporary-path symlink adversary"
if create_private_dir "$private_tmp/preplanted"; then
  die "private-directory helper accepted a pre-planted symlink"
fi
printf 'TEMP_PATH_ADVERSARY_REFUSED\n' > "$private_tmp/temp-adversary.status"

candidate=$(git -C "$repo_root" rev-parse --verify "$candidate_ref^{commit}") ||
  die "candidate ref is not a commit"
head_commit=$(git -C "$repo_root" rev-parse --verify HEAD)
[ "$candidate" = "$head_commit" ] ||
  die "candidate must be the checked-out HEAD"
candidate_tree=$(git -C "$repo_root" rev-parse "$candidate^{tree}")
base_resolved=$(git -C "$repo_root" rev-parse --verify "$base_commit^{commit}") ||
  die "base commit is unavailable"
git -C "$repo_root" merge-base --is-ancestor "$base_resolved" "$candidate" ||
  die "base commit is not an ancestor of candidate"

if [ -n "$(git -C "$repo_root" status --porcelain --untracked-files=all)" ]; then
  die "candidate worktree is not clean"
fi

shallow_repository=$(git -C "$repo_root" rev-parse --is-shallow-repository) ||
  die "could not determine whether the release repository is shallow"
[ "$shallow_repository" = "false" ] ||
  die "shallow repository cannot prove complete reachable-object coverage"
partial_clone_extension=$(git -C "$repo_root" config --get extensions.partialClone 2>/dev/null || true)
[ -z "$partial_clone_extension" ] ||
  die "partial-clone repository cannot prove complete reachable-object coverage"
promisor_remote_count=$(
  {
    git -C "$repo_root" config --get-regexp '^remote\..*\.promisor$' 2>/dev/null ||
      true
  } |
    awk 'tolower($2) == "true" {count++} END {print count+0}'
)
[ "$promisor_remote_count" -eq 0 ] ||
  die "promisor remote is configured; reachable-object scan would be incomplete"
partial_filter_count=$(
  {
    git -C "$repo_root" config --get-regexp '^remote\..*\.partialclonefilter$' 2>/dev/null ||
      true
  } |
    wc -l | tr -d ' '
)
[ "$partial_filter_count" -eq 0 ] ||
  die "partial-clone filter is configured; reachable-object scan would be incomplete"

GIT_NO_LAZY_FETCH=1 git -C "$repo_root" rev-list --objects --all --missing=print \
  > "$private_tmp/reachable-objects.txt" ||
  die "could not enumerate all reachable Git objects without lazy fetching"
missing_reachable_object_count=$(
  awk '/^\?/ {count++} END {print count+0}' "$private_tmp/reachable-objects.txt"
)
[ "$missing_reachable_object_count" -eq 0 ] ||
  die "reachable Git object set has missing/promisor objects"
reachable_object_count=$(
  awk '{
    object_id=$1
    sub(/^\?/, "", object_id)
    if (object_id != "") print object_id
  }' "$private_tmp/reachable-objects.txt" |
    LC_ALL=C sort -u | wc -l | tr -d ' '
)
[ "$reachable_object_count" -gt 0 ] ||
  die "reachable Git object scan set is empty"
GIT_NO_LAZY_FETCH=1 git -C "$repo_root" fsck --full --strict --no-dangling --no-progress \
  > "$private_tmp/git-fsck.out" 2> "$private_tmp/git-fsck.stderr" ||
  die "Git object database is incomplete or corrupt"

release_file_count=$(git -C "$repo_root" ls-tree -r --name-only "$candidate" | wc -l | tr -d ' ')
[ "$release_file_count" -gt 0 ] || die "release tree scan set is empty"
range_commit_count=$(git -C "$repo_root" rev-list --count "$base_resolved..$candidate")
[ "$range_commit_count" -gt 0 ] || die "JourdanLabs commit range is empty"
reachable_commit_count=$(git -C "$repo_root" rev-list --all --count)
[ "$reachable_commit_count" -gt 0 ] || die "reachable Git-object scan set is empty"

advisory_db_commit=$(git -C "$advisory_db" rev-parse --verify HEAD 2>/dev/null) ||
  die "advisory database is absent or not a Git checkout"
[ "$advisory_db_commit" = "$RUSTSEC_ADVISORY_DB_COMMIT" ] ||
  die "advisory database identity mismatch"
git -C "$advisory_db" diff --quiet --ignore-submodules -- &&
  git -C "$advisory_db" diff --cached --quiet --ignore-submodules -- ||
  die "advisory database worktree is modified"
[ -z "$(git -C "$advisory_db" status --porcelain --untracked-files=all)" ] ||
  die "advisory database contains modified, staged, or untracked files"
advisory_origin=$(git -C "$advisory_db" remote get-url origin 2>/dev/null) ||
  die "advisory database origin is absent"
case "$advisory_origin" in
  https://github.com/RustSec/advisory-db | https://github.com/RustSec/advisory-db.git)
    ;;
  *)
    die "advisory database origin is not the reviewed RustSec repository"
    ;;
esac

current_date=$(date -u +%Y-%m-%d)
jq -e --arg currentDate "$current_date" '
  .schemaVersion == 1 and
  (.proposedExceptions | type == "array") and
  (all(.proposedExceptions[];
    (.id | test("^RUSTSEC-[0-9]{4}-[0-9]{4}$")) and
    (.package | test("^[A-Za-z0-9][A-Za-z0-9_-]*$")) and
    (.version | test("^[0-9]+\\.[0-9]+\\.[0-9]+(?:[-+][0-9A-Za-z.+-]+)?$")) and
    (.scope | type == "string" and length > 0) and
    (.reason | type == "string" and length > 0) and
    (.proposer == "OMNIS V1 builder") and
    (.proposedOn | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}$")) and
    (.expiresOn | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}$")) and
    ((.proposedOn + "T00:00:00Z" | fromdateiso8601) <=
      ($currentDate + "T00:00:00Z" | fromdateiso8601)) and
    ((.proposedOn + "T00:00:00Z" | fromdateiso8601) <
      (.expiresOn + "T00:00:00Z" | fromdateiso8601)) and
    ((.expiresOn + "T00:00:00Z" | fromdateiso8601) >
      ($currentDate + "T00:00:00Z" | fromdateiso8601))
  ))
' "$exceptions_file" >/dev/null || die "proposed advisory exception schema is invalid"
exception_count=$(jq '.proposedExceptions | length' "$exceptions_file")
duplicate_exception_count=$(jq '[.proposedExceptions[].id] | length - (unique | length)' "$exceptions_file")
[ "$duplicate_exception_count" -eq 0 ] || die "duplicate proposed advisory exception ID"

archive_result=$("$python_path" "$repo_root/scripts/verify_source_archive.py" \
  --repo "$repo_root" --ref "$candidate" --archive "$archive_path" --json) ||
  die "release artifact verification failed"
printf '%s\n' "$archive_result" | jq -e \
  --arg commit "$candidate" --arg tree "$candidate_tree" \
  '.status == "ARCHIVE_VALID" and .commit == $commit and .tree == $tree' >/dev/null ||
  die "archive verifier returned inconsistent identity"
archive_sha256=$(printf '%s\n' "$archive_result" | jq -r '.sha256')
archive_bytes=$(printf '%s\n' "$archive_result" | jq -r '.compressedBytes')
archive_file_count=$(printf '%s\n' "$archive_result" | jq -r '.fileCount')
archive_prefix=$(printf '%s\n' "$archive_result" | jq -r '.prefix')

create_private_dir "$private_tmp/release-tree" ||
  die "could not create release-tree scan root"
create_private_dir "$private_tmp/exact-archive" ||
  die "could not create archive scan root"
git -C "$repo_root" archive --format=tar --prefix=release-tree/ "$candidate" |
  tar -xf - -C "$private_tmp/release-tree" ||
  die "could not materialize release tree"
tar -xzf "$archive_path" -C "$private_tmp/exact-archive" ||
  die "could not materialize verified exact archive"
if [ "${OMNIS_PREFLIGHT_ENABLE_TEST_HOOKS:-0}" = "1" ] &&
   [ "${OMNIS_PREFLIGHT_TEST_UNREADABLE_RELEASE_FILE:-0}" = "1" ]; then
  injected_unreadable=$(
    find "$private_tmp/release-tree/release-tree" -type f -print | sed -n '1p'
  )
  [ -n "$injected_unreadable" ] ||
    die "could not select injected unreadable release file"
  chmod 000 "$injected_unreadable" ||
    die "could not inject unreadable release file"
fi

(
  cd "$private_tmp/release-tree/release-tree"
  find . -type f -print |
    while IFS= read -r file; do
      [ -r "$file" ] || exit 1
    done
) || die "release tree contains an unreadable file"
(
  cd "$private_tmp/exact-archive/${archive_prefix%/}"
  find . -type f -print |
    while IFS= read -r file; do
      [ -r "$file" ] || exit 1
    done
) || die "exact archive contains an unreadable file"

create_private_dir "$private_tmp/positive-control" ||
  die "could not create planted-secret control"
# Assemble the positive-control PEM at runtime so the repository tree never
# stores contiguous private-key armor that would fail closed on itself.
{
  printf '%s\n' "-----BEGIN ""RSA PRIVATE KEY-----"
  printf '%s\n' "MIIEowIBAAKCAQEA0syntheticfixtureonlynotarealkeymaterial"
  printf '%s\n' "-----END ""RSA PRIVATE KEY-----"
} >"$private_tmp/positive-control/planted-private-key.pem" ||
  die "could not write planted-secret control"
chmod 600 "$private_tmp/positive-control/planted-private-key.pem" ||
  die "could not protect planted-secret control"
set +e
(
  cd "$private_tmp/scanner-cwd" &&
    "$gitleaks_path" dir "$private_tmp/positive-control" --no-banner --redact \
      --report-format json --report-path "$private_tmp/positive-control.json"
) >/dev/null 2>"$private_tmp/positive-control.stderr"
positive_status=$?
set -e
[ "$positive_status" -eq 1 ] ||
  die "planted-secret positive control was not detected (exit $positive_status)"
[ -s "$private_tmp/positive-control.json" ] ||
  die "planted-secret control returned detection without a report"
positive_findings=$(jq 'length' "$private_tmp/positive-control.json" 2>/dev/null) ||
  die "planted-secret report is invalid JSON"
[ "$positive_findings" -gt 0 ] ||
  die "planted-secret report contains zero findings"
positive_report_sha256=$(sha256_file "$private_tmp/positive-control.json")

: > "$private_tmp/secret-status.tsv"
run_gitleaks_dir "release_tree" \
  "$private_tmp/release-tree/release-tree" "$private_tmp/release-tree-gitleaks.json"
run_gitleaks_dir "exact_archive" \
  "$private_tmp/exact-archive/${archive_prefix%/}" "$private_tmp/archive-gitleaks.json"
run_gitleaks_git "jourdanlabs_commit_range" "$base_resolved..$candidate" \
  "$range_commit_count" "$private_tmp/range-gitleaks.json"
run_gitleaks_git "reachable_git_history" "--all" \
  "$reachable_commit_count" "$private_tmp/reachable-history-gitleaks.json"

# Materialize raw reachable objects only after the cheaper scanner legs have
# completed. Any failed scanner leg still exits before this large allocation.
create_private_dir "$private_tmp/reachable-git-objects" ||
  die "could not create reachable-object scan root"
materialization_result=$("$python_path" "$object_materializer" \
  --repo "$repo_root" \
  --objects "$private_tmp/reachable-objects.txt" \
  --output "$private_tmp/reachable-git-objects") ||
  die "could not materialize the complete reachable Git object set"
printf '%s\n' "$materialization_result" | jq -e \
  --argjson expected "$reachable_object_count" '
    .status == "OBJECTS_MATERIALIZED" and
    .objectCount == $expected and
    .contentBytes > 0 and
    (.types | type == "object") and
    ((.types | to_entries | map(.value) | add) == $expected)
  ' >/dev/null ||
  die "reachable-object materializer returned inconsistent evidence"
materialized_object_count=$(printf '%s\n' "$materialization_result" | jq '.objectCount')
materialized_object_bytes=$(printf '%s\n' "$materialization_result" | jq '.contentBytes')
materialized_object_types=$(printf '%s\n' "$materialization_result" | jq -c '.types')
run_gitleaks_dir "reachable_git_objects" \
  "$private_tmp/reachable-git-objects" "$private_tmp/reachable-objects-gitleaks.json"

create_private_dir "$private_tmp/git-metadata" ||
  die "could not create Git metadata scan root"
git_dir=$(git -C "$repo_root" rev-parse --git-dir)
case "$git_dir" in /*) ;; *) git_dir="$repo_root/$git_dir" ;; esac
[ -d "$git_dir" ] && [ ! -L "$git_dir" ] ||
  die "Git metadata directory is absent or unsafe"
git_common_dir=$(git -C "$repo_root" rev-parse --git-common-dir)
case "$git_common_dir" in
  /*) ;;
  *) git_common_dir="$repo_root/$git_common_dir" ;;
esac
[ -d "$git_common_dir" ] && [ ! -L "$git_common_dir" ] ||
  die "Git common metadata directory is absent or unsafe"
for forbidden_git_indirection in \
  "$git_common_dir/objects/info/alternates" \
  "$git_common_dir/info/grafts"; do
  [ ! -e "$forbidden_git_indirection" ] &&
    [ ! -L "$forbidden_git_indirection" ] ||
    die "Git object/history indirection is forbidden: $(basename "$forbidden_git_indirection")"
done
replace_ref_count=$(
  git -C "$repo_root" for-each-ref --format='%(refname)' refs/replace |
    wc -l | tr -d ' '
)
[ "$replace_ref_count" -eq 0 ] ||
  die "Git replace refs are present; source-history identity is ambiguous"
for metadata_name in HEAD config packed-refs shallow; do
  if [ -f "$git_dir/$metadata_name" ]; then
    [ -r "$git_dir/$metadata_name" ] || die "unreadable Git metadata: $metadata_name"
    cp "$git_dir/$metadata_name" "$private_tmp/git-metadata/$metadata_name" ||
      die "could not stage Git metadata: $metadata_name"
  fi
done
if [ -d "$git_dir/refs" ]; then
  create_private_dir "$private_tmp/git-metadata/refs" ||
    die "could not create Git refs scan root"
  find "$git_dir/refs" -type f -print |
    while IFS= read -r ref_file; do
      [ -r "$ref_file" ] || exit 1
      ref_name=${ref_file#"$git_dir/refs/"}
      safe_name=$(printf '%s' "$ref_name" | tr '/:' '__')
      cp "$ref_file" "$private_tmp/git-metadata/refs/$safe_name" || exit 1
    done || die "Git ref metadata scan set is unreadable"
fi
for tracked_metadata in .gitmodules .gitattributes; do
  if [ -f "$repo_root/$tracked_metadata" ]; then
    cp "$repo_root/$tracked_metadata" "$private_tmp/git-metadata/$tracked_metadata" ||
      die "could not stage $tracked_metadata"
  fi
done
git_metadata_count=$(count_regular_files "$private_tmp/git-metadata")
[ "$git_metadata_count" -gt 0 ] || die "Git metadata scan set is empty"
run_gitleaks_dir "git_publication_metadata" \
  "$private_tmp/git-metadata" "$private_tmp/git-metadata-gitleaks.json"

submodule_count=$(git -C "$repo_root" ls-tree -r "$candidate" |
  awk '$1 == "160000" {count++} END {print count+0}')
[ "$submodule_count" -eq 0 ] ||
  die "submodules are present; the V1 inventory and archive verifier require none"
lfs_pointer_count=$(
  {
    git -C "$repo_root" grep -Il \
      '^version https://git-lfs.github.com/spec/v1$' "$candidate" -- 2>/dev/null ||
      true
  } | wc -l | tr -d ' '
)
[ "$lfs_pointer_count" -eq 0 ] ||
  die "Git LFS pointers are present; the V1 inventory and artifact verifier require none"
lfs_object_count=0
if [ -e "$git_common_dir/lfs/objects" ] || [ -L "$git_common_dir/lfs/objects" ]; then
  [ -d "$git_common_dir/lfs/objects" ] &&
    [ ! -L "$git_common_dir/lfs/objects" ] ||
    die "Git LFS object storage is not a real directory"
  lfs_object_count=$(count_regular_files "$git_common_dir/lfs/objects")
fi
[ "$lfs_object_count" -eq 0 ] ||
  die "Git LFS objects are present; V1 requires an empty local LFS object store"

set +e
(cd "$repo_root" &&
  "$cargo_audit_path" audit --no-fetch --db "$advisory_db" --json) \
  > "$private_tmp/cargo-audit-unsuppressed.json" \
  2> "$private_tmp/cargo-audit-unsuppressed.stderr"
unsuppressed_audit_status=$?
set -e
if [ "$exception_count" -eq 0 ]; then
  expected_unsuppressed_audit_status=0
else
  expected_unsuppressed_audit_status=1
fi
[ "$unsuppressed_audit_status" -eq "$expected_unsuppressed_audit_status" ] ||
  die "unsuppressed dependency scan did not report the exact expected finding status (expected $expected_unsuppressed_audit_status, got $unsuppressed_audit_status)"
[ -s "$private_tmp/cargo-audit-unsuppressed.json" ] ||
  die "unsuppressed dependency scan produced an empty report"
jq -e . "$private_tmp/cargo-audit-unsuppressed.json" >/dev/null ||
  die "unsuppressed dependency report is invalid JSON"
jq -e --argjson exceptionCount "$exception_count" '
  (.vulnerabilities.count == $exceptionCount) and
  (.vulnerabilities.list | type == "array" and length == $exceptionCount)
' "$private_tmp/cargo-audit-unsuppressed.json" >/dev/null ||
  die "unsuppressed dependency vulnerability count/list differs from the exact proposed-exception set"
proposed_exception_findings_json=$(
  "$python_path" \
    "$repo_root/scripts/validate_advisory_exception_findings.py" \
    --exceptions "$exceptions_file" \
    --audit-report "$private_tmp/cargo-audit-unsuppressed.json"
) ||
  die "proposed exceptions do not equal the complete unsuppressed exact package/version finding set"
[ "$(printf '%s\n' "$proposed_exception_findings_json" | jq 'length')" -eq "$exception_count" ] ||
  die "proposed advisory exception finding count disagrees"
unsuppressed_audit_report_sha256=$(
  sha256_file "$private_tmp/cargo-audit-unsuppressed.json"
)

audit_args=(audit --no-fetch --db "$advisory_db" --json)
while IFS= read -r exception_id; do
  audit_args+=(--ignore "$exception_id")
done < <(jq -r '.proposedExceptions[].id' "$exceptions_file")
set +e
(cd "$repo_root" &&
  "$cargo_audit_path" "${audit_args[@]}") \
  > "$private_tmp/cargo-audit.json" 2> "$private_tmp/cargo-audit.stderr"
audit_status=$?
set -e
[ "$audit_status" -eq 0 ] ||
  die "dependency advisory scan failed or found unreviewed vulnerability (exit $audit_status)"
[ -s "$private_tmp/cargo-audit.json" ] ||
  die "dependency advisory scan produced an empty report"
jq -e . "$private_tmp/cargo-audit.json" >/dev/null ||
  die "dependency advisory report is invalid JSON"
jq -e --slurpfile exceptions "$exceptions_file" '
  (.vulnerabilities.count == 0) and
  ((.settings.ignore | sort) == ($exceptions[0].proposedExceptions | map(.id) | sort))
' "$private_tmp/cargo-audit.json" >/dev/null ||
  die "dependency report contains a vulnerability or exception-set drift"
audit_vulnerability_count=$(jq '.vulnerabilities.count' "$private_tmp/cargo-audit.json")
audit_unmaintained_count=$(jq '(.warnings.unmaintained // []) | length' "$private_tmp/cargo-audit.json")
audit_unsound_count=$(jq '(.warnings.unsound // []) | length' "$private_tmp/cargo-audit.json")
audit_notice_count=$(jq '(.warnings.notice // []) | length' "$private_tmp/cargo-audit.json")
audit_warnings_json=$(jq -c '
  [
    .warnings
    | to_entries[]
    | .key as $kind
    | .value[]
    | {
        kind: $kind,
        advisoryId: .advisory.id,
        package: .package.name,
        version: .package.version
      }
  ]
  | sort_by(.advisoryId, .package, .version)
' "$private_tmp/cargo-audit.json") ||
  die "could not serialize dependency warning evidence"
printf '%s\n' "$audit_warnings_json" | jq -e '
  type == "array" and
  all(.[];
    (.kind | type == "string" and length > 0) and
    (.advisoryId | test("^RUSTSEC-[0-9]{4}-[0-9]{4}$")) and
    (.package | type == "string" and length > 0) and
    (.version | test("^[0-9]+\\.[0-9]+\\.[0-9]+"))
  )
' >/dev/null || die "dependency warning evidence is malformed"
audit_warning_count=$(printf '%s\n' "$audit_warnings_json" | jq 'length')
categorized_warning_count=$(
  printf '%s\n%s\n%s\n' \
    "$audit_unmaintained_count" "$audit_unsound_count" "$audit_notice_count" |
    awk '{total += $1} END {print total+0}'
)
[ "$audit_warning_count" -eq "$categorized_warning_count" ] ||
  die "dependency warning categories are incomplete"
audit_report_sha256=$(sha256_file "$private_tmp/cargo-audit.json")
if [ "$exception_count" -gt 0 ]; then
  report_status="SCAN_COMPLETE_WITH_PROPOSED_EXCEPTIONS_HOLD"
  dependency_status="PENDING_INDEPENDENT_REVIEW"
  receipt_status="HOLD_PENDING_INDEPENDENT_EXCEPTION_REVIEW"
elif [ "$audit_warning_count" -gt 0 ]; then
  report_status="SCAN_COMPLETE_WITH_INFORMATIONAL_WARNINGS"
  dependency_status="SCAN_COMPLETE_WITH_INFORMATIONAL_WARNINGS"
  receipt_status="HOLD_INFORMATIONAL_WARNINGS_PENDING_REMEDIATION"
else
  report_status="SCAN_COMPLETE"
  dependency_status="SCAN_CLEAN"
  receipt_status="complete"
fi

set +e
(cd "$repo_root" &&
  "$cargo_deny_path" --config "$deny_config" check licenses) \
  > "$private_tmp/cargo-deny.out" 2> "$private_tmp/cargo-deny.stderr"
deny_status=$?
set -e
[ "$deny_status" -eq 0 ] ||
  die "dependency license scan failed, was incomplete, or found unapproved rights (exit $deny_status)"
[ -s "$private_tmp/cargo-deny.out" ] || [ -s "$private_tmp/cargo-deny.stderr" ] ||
  die "dependency license scan produced no evidence"
deny_evidence_sha256=$(
  {
    cat "$private_tmp/cargo-deny.out"
    cat "$private_tmp/cargo-deny.stderr"
  } | sha256_stdin
)

inventory_output=$("$repo_root/scripts/check_third_party_inventory.sh") ||
  die "third-party redistribution inventory check failed"
metadata_output=$("$repo_root/scripts/check_workspace_metadata.sh") ||
  die "workspace publish/metadata lockout check failed"
hygiene_output=$("$repo_root/scripts/check_release_hygiene.sh") ||
  die "release workflow/quarantine check failed"
printf '%s\n' "$inventory_output" | grep -q 'unknown_rights=0' ||
  die "inventory checker did not prove zero unknown rights"
printf '%s\n' "$metadata_output" | grep -q 'publishable=0 incomplete=0' ||
  die "workspace metadata checker did not prove lockout"
printf '%s\n' "$hygiene_output" | grep -q 'publication_paths=0' ||
  die "release hygiene checker did not prove quarantine"

secret_scan_count=$(wc -l < "$private_tmp/secret-status.tsv" | tr -d ' ')
[ "$secret_scan_count" -eq 6 ] ||
  die "secret scan leg count is incomplete: expected 6, got $secret_scan_count"
secret_scans_json=$(jq -Rn '
  [
    inputs
    | split("\t")
    | select(length == 5)
    | {
        name: .[0],
        scanSetCount: (.[1] | tonumber),
        exitStatus: (.[2] | tonumber),
        status: .[3],
        reportSha256: .[4]
      }
  ]
' < "$private_tmp/secret-status.tsv") ||
  die "could not serialize named secret-scan evidence"
printf '%s\n' "$secret_scans_json" | jq -e '
  length == 6 and
  ([.[].name] | sort) == ([
    "exact_archive",
    "git_publication_metadata",
    "jourdanlabs_commit_range",
    "reachable_git_history",
    "reachable_git_objects",
    "release_tree"
  ] | sort) and
  all(.[];
    .scanSetCount > 0 and
    .exitStatus == 0 and
    .status == "SCAN_CLEAN" and
    (.reportSha256 | test("^[0-9a-f]{64}$"))
  )
' >/dev/null || die "named secret-scan evidence is incomplete or inconsistent"
secret_status_sha256=$(sha256_file "$private_tmp/secret-status.tsv")
git_fsck_evidence_sha256=$(
  {
    cat "$private_tmp/git-fsck.out"
    cat "$private_tmp/git-fsck.stderr"
  } | sha256_stdin
)
inventory_count=$(printf '%s\n' "$inventory_output" | sed -n 's/.*assets=\([0-9][0-9]*\).*/\1/p')
workspace_package_count=$(printf '%s\n' "$metadata_output" | sed -n 's/.*packages=\([0-9][0-9]*\).*/\1/p')
[ -n "$inventory_count" ] && [ "$inventory_count" -gt 0 ] ||
  die "inventory evidence count is empty"
[ -n "$workspace_package_count" ] && [ "$workspace_package_count" -gt 0 ] ||
  die "workspace package evidence count is empty"

git_version=$(git --version | head -n 1)
tar_version=$(tar --version 2>&1 | head -n 1)
cargo_version=$("$cargo_path" --version)
rustc_version=$("$rustc_path" --version)
go_version=$("$go_path" version)
python_version=$("$python_path" --version 2>&1)
jq_version=$("$jq_path" --version)
sha_tool_version="$sha256_tool_mode ($sha256_tool_path)"

# Cleanup is a security leg. It must succeed before a retained report exists.
remove_private_tmp || die "security temporary cleanup failed"

umask 077
report_tmp=$(mktemp "$report_parent/.omnis-security-report.XXXXXX") ||
  die "could not create retained report temporary file"
report_sidecar_tmp=$(mktemp "$report_parent/.omnis-security-sha.XXXXXX") ||
  die "could not create retained report sidecar temporary file"
chmod 600 "$report_tmp" "$report_sidecar_tmp" ||
  die "could not protect retained report temporaries"

jq -n \
  --arg candidate "$candidate" \
  --arg tree "$candidate_tree" \
  --arg base "$base_resolved" \
  --arg archiveSha256 "$archive_sha256" \
  --arg archivePrefix "$archive_prefix" \
  --argjson archiveBytes "$archive_bytes" \
  --argjson archiveFileCount "$archive_file_count" \
  --arg gitleaksVersion "$GITLEAKS_VERSION" \
  --arg gitleaksCommit "$GITLEAKS_SOURCE_COMMIT" \
  --arg gitleaksGoVersion "$gitleaks_build_go_version" \
  --arg gitleaksGoos "$gitleaks_build_goos" \
  --arg gitleaksGoarch "$gitleaks_build_goarch" \
  --arg gitleaksExecutable "$gitleaks_executable" \
  --arg gitleaksSha256 "$gitleaks_sha256" \
  --arg expectedGitleaksSha256 "$expected_gitleaks_sha256" \
  --arg gitleaksBuildInfoSha256 "$gitleaks_build_info_sha256" \
  --arg cargoAuditVersion "$CARGO_AUDIT_VERSION" \
  --arg cargoAuditExecutable "$cargo_audit_executable" \
  --arg cargoAuditSha256 "$cargo_audit_sha256" \
  --arg expectedCargoAuditSha256 "$expected_cargo_audit_sha256" \
  --arg cargoDenyVersion "$CARGO_DENY_VERSION" \
  --arg cargoDenyExecutable "$cargo_deny_executable" \
  --arg cargoDenySha256 "$cargo_deny_sha256" \
  --arg expectedCargoDenySha256 "$expected_cargo_deny_sha256" \
  --arg securityToolOs "$security_tool_os" \
  --arg securityToolArchitecture "$security_tool_architecture" \
  --arg advisoryDbCommit "$advisory_db_commit" \
  --arg advisoryDbOrigin "$advisory_origin" \
  --arg auditReportSha256 "$audit_report_sha256" \
  --arg unsuppressedAuditReportSha256 "$unsuppressed_audit_report_sha256" \
  --arg licenseEvidenceSha256 "$deny_evidence_sha256" \
  --arg secretStatusSha256 "$secret_status_sha256" \
  --argjson secretScans "$secret_scans_json" \
  --arg gitFsckEvidenceSha256 "$git_fsck_evidence_sha256" \
  --arg gitVersion "$git_version" \
  --arg gitExecutable "$git_executable" \
  --arg tarVersion "$tar_version" \
  --arg tarExecutable "$tar_executable" \
  --arg cargoVersion "$cargo_version" \
  --arg cargoExecutable "$cargo_executable" \
  --arg rustcVersion "$rustc_version" \
  --arg rustcExecutable "$rustc_executable" \
  --arg goVersion "$go_version" \
  --arg goExecutable "$go_executable" \
  --arg pythonVersion "$python_version" \
  --arg pythonExecutable "$python_executable" \
  --arg jqVersion "$jq_version" \
  --arg jqExecutable "$jq_executable" \
  --arg shaToolVersion "$sha_tool_version" \
  --argjson releaseFileCount "$release_file_count" \
  --argjson rangeCommitCount "$range_commit_count" \
  --argjson reachableCommitCount "$reachable_commit_count" \
  --argjson reachableObjectCount "$reachable_object_count" \
  --argjson materializedObjectCount "$materialized_object_count" \
  --argjson materializedObjectBytes "$materialized_object_bytes" \
  --argjson materializedObjectTypes "$materialized_object_types" \
  --argjson missingReachableObjectCount "$missing_reachable_object_count" \
  --argjson gitMetadataCount "$git_metadata_count" \
  --argjson submoduleCount "$submodule_count" \
  --argjson replaceRefCount "$replace_ref_count" \
  --argjson lfsPointerCount "$lfs_pointer_count" \
  --argjson lfsObjectCount "$lfs_object_count" \
  --argjson positiveFindings "$positive_findings" \
  --argjson positiveExitStatus "$positive_status" \
  --arg positiveReportSha256 "$positive_report_sha256" \
  --argjson auditExitStatus "$audit_status" \
  --argjson unsuppressedAuditExitStatus "$unsuppressed_audit_status" \
  --argjson auditVulnerabilityCount "$audit_vulnerability_count" \
  --argjson proposedExceptionFindings "$proposed_exception_findings_json" \
  --argjson auditWarningCount "$audit_warning_count" \
  --argjson auditWarnings "$audit_warnings_json" \
  --argjson auditUnmaintainedCount "$audit_unmaintained_count" \
  --argjson auditUnsoundCount "$audit_unsound_count" \
  --argjson auditNoticeCount "$audit_notice_count" \
  --argjson denyExitStatus "$deny_status" \
  --argjson exceptionCount "$exception_count" \
  --argjson inventoryCount "$inventory_count" \
  --argjson workspacePackageCount "$workspace_package_count" \
  --arg reportStatus "$report_status" \
  --arg dependencyStatus "$dependency_status" \
  --arg currentDate "$current_date" \
  --slurpfile proposedExceptions "$exceptions_file" \
  '{
    schemaVersion: 1,
    status: $reportStatus,
    candidate: {commit: $candidate, tree: $tree, baseCommit: $base},
    archive: {
      kind: "local-review-source-archive",
      prefix: $archivePrefix,
      productVersion: "0.1.0",
      sha256: $archiveSha256,
      compressedBytes: $archiveBytes,
      fileCount: $archiveFileCount
    },
    tools: {
      secretScanner: {
        name: "gitleaks",
        version: $gitleaksVersion,
        sourceCommit: $gitleaksCommit,
        buildToolchain: $gitleaksGoVersion,
        target: {os: $gitleaksGoos, architecture: $gitleaksGoarch},
        executable: $gitleaksExecutable,
        executableSha256: $gitleaksSha256,
        expectedExecutableSha256: $expectedGitleaksSha256,
        identityPolicy: "host-targeted-exact-sha256-before-execution",
        goBuildInfoSha256: $gitleaksBuildInfoSha256,
        vcsModified: false,
        configurationPolicy: {
          source: "pinned-embedded-defaults",
          ambientOverridesCleared: true,
          candidateOverrideFiles: 0
        }
      },
      dependencyTool: {
        name: "cargo-audit",
        version: $cargoAuditVersion,
        target: {os: $securityToolOs, architecture: $securityToolArchitecture},
        executable: $cargoAuditExecutable,
        executableSha256: $cargoAuditSha256,
        expectedExecutableSha256: $expectedCargoAuditSha256,
        identityPolicy: "host-targeted-exact-sha256-before-execution"
      },
      licenseTool: {
        name: "cargo-deny",
        version: $cargoDenyVersion,
        target: {os: $securityToolOs, architecture: $securityToolArchitecture},
        executable: $cargoDenyExecutable,
        executableSha256: $cargoDenySha256,
        expectedExecutableSha256: $expectedCargoDenySha256,
        identityPolicy: "host-targeted-exact-sha256-before-execution"
      },
      advisoryDatabase: {
        repository: $advisoryDbOrigin,
        commit: $advisoryDbCommit,
        modifiedFiles: 0,
        stagedFiles: 0,
        untrackedFiles: 0
      },
      runtime: {
        git: {version: $gitVersion, executable: $gitExecutable},
        tar: {version: $tarVersion, executable: $tarExecutable},
        cargo: {version: $cargoVersion, executable: $cargoExecutable},
        rustc: {version: $rustcVersion, executable: $rustcExecutable},
        go: {version: $goVersion, executable: $goExecutable},
        python: {version: $pythonVersion, executable: $pythonExecutable},
        jq: {version: $jqVersion, executable: $jqExecutable},
        sha256: $shaToolVersion
      }
    },
    scanSets: {
      releaseTreeFiles: $releaseFileCount,
      exactArchiveFiles: $archiveFileCount,
      jourdanLabsRangeCommits: $rangeCommitCount,
      reachableGitCommits: $reachableCommitCount,
      reachableGitObjects: $reachableObjectCount,
      materializedGitObjects: $materializedObjectCount,
      materializedGitObjectBytes: $materializedObjectBytes,
      materializedGitObjectTypes: $materializedObjectTypes,
      missingOrPromisorGitObjects: $missingReachableObjectCount,
      shallowRepository: false,
      partialClone: false,
      gitObjectFsck: {
        status: "SCAN_CLEAN",
        exitStatus: 0,
        evidenceSha256: $gitFsckEvidenceSha256
      },
      publicationMetadataFiles: $gitMetadataCount,
      submodules: $submoduleCount,
      gitReplaceRefs: $replaceRefCount,
      gitAlternateObjectStores: 0,
      gitGrafts: 0,
      gitLfsPointers: $lfsPointerCount,
      gitLfsObjectFiles: $lfsObjectCount,
      inventoriedAssets: $inventoryCount,
      workspacePackages: $workspacePackageCount
    },
    legs: {
      secret: {
        status: "SCAN_CLEAN",
        namedScans: $secretScans,
        positiveControl: {
          status: "DETECTED_AS_REQUIRED",
          exitStatus: $positiveExitStatus,
          findingCount: $positiveFindings,
          reportSha256: $positiveReportSha256
        },
        scanStatusSha256: $secretStatusSha256
      },
      dependency: {
        status: $dependencyStatus,
        exitStatus: $auditExitStatus,
        reportSha256: $auditReportSha256,
        unsuppressedExitStatus: $unsuppressedAuditExitStatus,
        unsuppressedReportSha256: $unsuppressedAuditReportSha256,
        unreviewedVulnerabilityCount: $auditVulnerabilityCount,
        visibleWarningCount: $auditWarningCount,
        informationalWarnings: $auditWarnings,
        warningCounts: {
          unmaintained: $auditUnmaintainedCount,
          unsound: $auditUnsoundCount,
          notice: $auditNoticeCount
        },
        exceptionCount: $exceptionCount,
        proposedExceptionFindings: $proposedExceptionFindings,
        proposedExceptions: $proposedExceptions[0].proposedExceptions
      },
      license: {
        status: "SCAN_CLEAN",
        exitStatus: $denyExitStatus,
        evidenceSha256: $licenseEvidenceSha256,
        unknownOrIncompatibleRights: 0
      },
      artifact: {
        status: "SCAN_CLEAN",
        exitStatus: 0,
        archiveUnder50MiB: true,
        publishableWorkspacePackages: 0,
        metadataIncompleteWorkspacePackages: 0,
        activePublicationWorkflows: 0,
        temporaryPathAdversary: "REFUSED",
        cleanup: "COMPLETED"
      }
    },
    commands: [
      "gitleaks dir <release-tree>",
      "gitleaks dir <exact-archive>",
      "gitleaks git <repo> --log-opts=<base>..<candidate>",
      "gitleaks git <repo> --log-opts=--all",
      "scripts/materialize_git_objects.py <reachable-object-index>",
      "gitleaks dir <materialized-reachable-git-objects>",
      "gitleaks dir <publication-metadata>",
      "cargo-audit audit --no-fetch --db <pinned-db> --json",
      "scripts/validate_advisory_exception_findings.py <exceptions> <unsuppressed-audit>",
      "cargo-audit audit --no-fetch --db <pinned-db> --json <proposed-ignores>",
      "cargo-deny --config config/security/deny.toml check licenses",
      "scripts/check_third_party_inventory.sh",
      "scripts/check_workspace_metadata.sh",
      "scripts/check_release_hygiene.sh",
      "scripts/verify_source_archive.py"
    ],
    observedDateUtc: $currentDate,
    externalActions: false
  }' > "$report_tmp"

[ -s "$report_tmp" ] || die "retained security report is empty"
report_sha256=$(sha256_file "$report_tmp")
printf '%s  %s\n' "$report_sha256" "$(basename "$report_path")" > "$report_sidecar_tmp"
mv "$report_tmp" "$report_path"
report_tmp=""
mv "$report_sidecar_tmp" "$report_path.sha256"
report_sidecar_tmp=""
chmod 600 "$report_path" "$report_path.sha256" ||
  die "could not protect retained security evidence"

printf 'security preflight %s: commit=%s tree=%s report_sha256=%s\n' \
  "$receipt_status" "$candidate" "$candidate_tree" "$report_sha256"
