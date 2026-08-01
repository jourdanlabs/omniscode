#!/usr/bin/env bash
# Reproduce fail-closed security-preflight faults without retaining a report.
# Compatible with the macOS system Bash 3.2.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
preflight="$repo_root/scripts/security_preflight.sh"
archive=""
advisory_db=""
tools_dir=""
test_root=""
candidate_override=""

usage() {
  cat <<'USAGE'
Usage:
  tests/security/verify_preflight_faults.sh \
    --archive PATH \
    --advisory-db PATH \
    --tools-dir PATH
USAGE
}

die() {
  printf 'security fault-test error: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ -n "$candidate_override" ] &&
     { [ -e "$candidate_override" ] || [ -L "$candidate_override" ]; }; then
    rm -f -- "$candidate_override" || status=1
  fi
  if [ -n "$test_root" ] &&
     { [ -e "$test_root" ] || [ -L "$test_root" ]; }; then
    case "$test_root" in
      /tmp/omnis-security-faults.*)
        rm -rf -- "$test_root" || status=1
        ;;
      *)
        printf 'security fault-test error: refusing unsafe cleanup: %s\n' \
          "$test_root" >&2
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
  exit "$signal_status"
}

trap cleanup EXIT
trap 'exit_on_signal HUP' HUP
trap 'exit_on_signal INT' INT
trap 'exit_on_signal TERM' TERM

while [ "$#" -gt 0 ]; do
  case "$1" in
    --archive)
      [ "$#" -ge 2 ] || die "--archive requires a value"
      archive=$2
      shift 2
      ;;
    --advisory-db)
      [ "$#" -ge 2 ] || die "--advisory-db requires a value"
      advisory_db=$2
      shift 2
      ;;
    --tools-dir)
      [ "$#" -ge 2 ] || die "--tools-dir requires a value"
      tools_dir=$2
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

[ -n "$archive" ] || die "--archive is required"
[ -n "$advisory_db" ] || die "--advisory-db is required"
[ -n "$tools_dir" ] || die "--tools-dir is required"
case "$archive" in /*) ;; *) archive="$PWD/$archive" ;; esac
case "$advisory_db" in /*) ;; *) advisory_db="$PWD/$advisory_db" ;; esac
case "$tools_dir" in /*) ;; *) tools_dir="$PWD/$tools_dir" ;; esac
[ -f "$archive" ] && [ ! -L "$archive" ] || die "archive is absent or unsafe"
[ -d "$advisory_db" ] && [ ! -L "$advisory_db" ] ||
  die "advisory database is absent or unsafe"
[ -d "$tools_dir" ] && [ ! -L "$tools_dir" ] ||
  die "security tools directory is absent or unsafe"
[ -z "$(git -C "$repo_root" status --porcelain --untracked-files=all)" ] ||
  die "fault tests require a clean candidate worktree"

test_root=$(mktemp -d /tmp/omnis-security-faults.XXXXXX)
chmod 700 "$test_root"
results="$test_root/results.tsv"
: > "$results"

make_sanitized_path() {
  destination=$1
  include_gitleaks=$2
  mkdir "$destination"
  chmod 700 "$destination"
  for command_name in \
    awk basename cargo cargo-audit cargo-deny cat chmod cmp cp date dirname find \
    git go grep head jq ln mkdir mktemp mv python3 rm rustc sed sort tar tr wc; do
    command_path=$(command -v "$command_name" 2>/dev/null || true)
    [ -n "$command_path" ] ||
      die "could not construct sanitized PATH: $command_name is absent"
    ln -s "$command_path" "$destination/$command_name"
  done
  if [ "$include_gitleaks" = "1" ]; then
    command_path=$(command -v gitleaks 2>/dev/null || true)
    [ -n "$command_path" ] ||
      die "could not construct sanitized PATH: gitleaks is absent"
    ln -s "$command_path" "$destination/gitleaks"
  fi
}

expect_failure() {
  label=$1
  expected=$2
  report=$3
  database=$4
  shift 4
  log="$test_root/$label.log"
  set +e
  /usr/bin/env "$@" /bin/bash "$preflight" \
    --archive "$archive" \
    --report "$report" \
    --advisory-db "$database" > "$log" 2>&1
  status=$?
  set -e
  [ "$status" -ne 0 ] || die "$label unexpectedly succeeded"
  grep -F "$expected" "$log" >/dev/null ||
    die "$label did not emit the expected fail-closed reason"
  [ ! -e "$report" ] && [ ! -L "$report" ] ||
    die "$label retained a security report"
  [ ! -e "$report.sha256" ] && [ ! -L "$report.sha256" ] ||
    die "$label retained a security report digest"
  printf '%s\t%s\t%s\n' "$label" "$status" "$expected" >> "$results"
}

absent_path="$test_root/path-absent"
make_sanitized_path "$absent_path" 0
expect_failure \
  scanner-absent \
  "gitleaks absent; scan cannot start" \
  "$test_root/scanner-absent.json" \
  "$advisory_db" \
  "PATH=$absent_path"

modified_path="$test_root/path-modified"
make_sanitized_path "$modified_path" 1
rm -f -- "$modified_path/gitleaks"
cp "$(command -v gitleaks)" "$modified_path/gitleaks"
chmod 700 "$modified_path/gitleaks"
printf 'post-build-modification\n' >> "$modified_path/gitleaks"
expect_failure \
  scanner-modified \
  "gitleaks executable SHA-256 mismatch" \
  "$test_root/scanner-modified.json" \
  "$advisory_db" \
  "PATH=$modified_path"

forged_audit_path="$test_root/path-forged-audit"
make_sanitized_path "$forged_audit_path" 1
rm -f -- "$forged_audit_path/cargo-audit"
cat > "$forged_audit_path/cargo-audit" <<'FORGED_AUDIT'
#!/bin/sh
if [ -n "${OMNIS_PREFLIGHT_FORGED_SHIM_MARKER:-}" ]; then
  printf 'forged cargo-audit shim executed\n' > "$OMNIS_PREFLIGHT_FORGED_SHIM_MARKER"
fi
printf 'cargo-audit 0.22.2\n'
exit 0
FORGED_AUDIT
chmod 700 "$forged_audit_path/cargo-audit"
forged_audit_marker="$test_root/forged-audit-executed"
expect_failure \
  cargo-audit-forged-shim \
  "cargo-audit executable SHA-256 mismatch" \
  "$test_root/cargo-audit-forged-shim.json" \
  "$advisory_db" \
  "PATH=$forged_audit_path" \
  "OMNIS_PREFLIGHT_FORGED_SHIM_MARKER=$forged_audit_marker"
[ ! -e "$forged_audit_marker" ] && [ ! -L "$forged_audit_marker" ] ||
  die "forged cargo-audit shim executed before its identity was refused"

forged_deny_path="$test_root/path-forged-deny"
make_sanitized_path "$forged_deny_path" 1
rm -f -- "$forged_deny_path/cargo-deny"
cat > "$forged_deny_path/cargo-deny" <<'FORGED_DENY'
#!/bin/sh
if [ -n "${OMNIS_PREFLIGHT_FORGED_SHIM_MARKER:-}" ]; then
  printf 'forged cargo-deny shim executed\n' > "$OMNIS_PREFLIGHT_FORGED_SHIM_MARKER"
fi
printf 'cargo-deny 0.20.2\n'
exit 0
FORGED_DENY
chmod 700 "$forged_deny_path/cargo-deny"
forged_deny_marker="$test_root/forged-deny-executed"
expect_failure \
  cargo-deny-forged-shim \
  "cargo-deny executable SHA-256 mismatch" \
  "$test_root/cargo-deny-forged-shim.json" \
  "$advisory_db" \
  "PATH=$forged_deny_path" \
  "OMNIS_PREFLIGHT_FORGED_SHIM_MARKER=$forged_deny_marker"
[ ! -e "$forged_deny_marker" ] && [ ! -L "$forged_deny_marker" ] ||
  die "forged cargo-deny shim executed before its identity was refused"

normal_path="$tools_dir:$PATH"
expect_failure \
  scanner-empty-set \
  "release_tree scan set is empty" \
  "$test_root/scanner-empty.json" \
  "$advisory_db" \
  "PATH=$normal_path" \
  "OMNIS_PREFLIGHT_ENABLE_TEST_HOOKS=1" \
  "OMNIS_PREFLIGHT_TEST_EMPTY_SCAN_LABEL=release_tree"

expect_failure \
  scanner-crash \
  "release_tree secret scan incomplete or scanner crashed (exit 70)" \
  "$test_root/scanner-crash.json" \
  "$advisory_db" \
  "PATH=$normal_path" \
  "OMNIS_PREFLIGHT_ENABLE_TEST_HOOKS=1" \
  "OMNIS_PREFLIGHT_TEST_CRASH_SCAN_LABEL=release_tree"

expect_failure \
  unreadable-release-file \
  "release tree contains an unreadable file" \
  "$test_root/unreadable.json" \
  "$advisory_db" \
  "PATH=$normal_path" \
  "OMNIS_PREFLIGHT_ENABLE_TEST_HOOKS=1" \
  "OMNIS_PREFLIGHT_TEST_UNREADABLE_RELEASE_FILE=1"

expect_failure \
  wrong-advisory-database \
  "advisory database identity mismatch" \
  "$test_root/wrong-advisory-db.json" \
  "$repo_root" \
  "PATH=$normal_path"

candidate_override="$repo_root/.gitleaks.toml"
[ ! -e "$candidate_override" ] && [ ! -L "$candidate_override" ] ||
  die "candidate override fixture path already exists"
printf '[extend]\nuseDefault = false\n' > "$candidate_override"
expect_failure \
  candidate-scanner-override \
  "candidate-controlled secret-scan override is forbidden: .gitleaks.toml" \
  "$test_root/candidate-override.json" \
  "$advisory_db" \
  "PATH=$normal_path"
rm -f -- "$candidate_override"
candidate_override=""

partial_repo="$test_root/partial-repo"
git clone --quiet --shared "$repo_root" "$partial_repo"
git -C "$partial_repo" config core.repositoryformatversion 1
git -C "$partial_repo" config extensions.partialClone origin
partial_preflight="$partial_repo/scripts/security_preflight.sh"
original_preflight=$preflight
preflight=$partial_preflight
expect_failure \
  partial-clone \
  "partial-clone repository cannot prove complete reachable-object coverage" \
  "$test_root/partial-clone.json" \
  "$advisory_db" \
  "PATH=$normal_path"
preflight=$original_preflight

before_cleanup="$test_root/before-cleanup.txt"
after_cleanup="$test_root/after-cleanup.txt"
find /tmp -maxdepth 1 -type d -name 'omnis-security.*' -print |
  LC_ALL=C sort > "$before_cleanup"
expect_failure \
  cleanup-failure \
  "injected cleanup failure" \
  "$test_root/cleanup-failure.json" \
  "$advisory_db" \
  "PATH=$normal_path" \
  "OMNIS_PREFLIGHT_ENABLE_TEST_HOOKS=1" \
  "OMNIS_PREFLIGHT_TEST_EMPTY_SCAN_LABEL=release_tree" \
  "OMNIS_PREFLIGHT_TEST_FAIL_CLEANUP=1"
find /tmp -maxdepth 1 -type d -name 'omnis-security.*' -print |
  LC_ALL=C sort > "$after_cleanup"
new_cleanup_roots="$test_root/new-cleanup-roots.txt"
comm -13 "$before_cleanup" "$after_cleanup" > "$new_cleanup_roots"
[ -s "$new_cleanup_roots" ] ||
  die "cleanup-failure hook left no reproducible temporary root"
while IFS= read -r leaked_root; do
  case "$leaked_root" in
    /tmp/omnis-security.*)
      [ -d "$leaked_root" ] && [ ! -L "$leaked_root" ] ||
        die "cleanup-failure fixture root is unsafe"
      chmod -R u+rwX "$leaked_root"
      rm -rf -- "$leaked_root"
      ;;
    *)
      die "cleanup-failure fixture escaped the expected temporary prefix"
      ;;
  esac
done < "$new_cleanup_roots"

case_count=$(wc -l < "$results" | tr -d ' ')
[ "$case_count" -eq 11 ] ||
  die "fault-test matrix is incomplete: expected 11, got $case_count"
printf 'PASS: security preflight failed closed for %s injected faults\n' "$case_count"
sed 's/\t/ | /g' "$results"
