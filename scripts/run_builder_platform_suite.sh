#!/bin/bash
# Run the reproducible local command set used by verification-index assembly.
set -euo pipefail

if [ "$#" -ne 4 ]; then
  printf 'usage: run_builder_platform_suite.sh REPO PLATFORM OUTPUT_DIR CLONE_MARKER\n' >&2
  exit 2
fi

repo=$1
platform=$2
output_dir=$3
clone_marker=$4

[ -d "$repo" ] && [ ! -L "$repo" ] || {
  printf 'builder suite error: repository root is absent or unsafe\n' >&2
  exit 2
}
repo=$(cd "$repo" && pwd -P)
receipt_runner="$repo/scripts/run_builder_receipt.sh"
[ -f "$receipt_runner" ] && [ ! -L "$receipt_runner" ] && [ -x "$receipt_runner" ] || {
  printf 'builder suite error: receipt runner is not executable\n' >&2
  exit 2
}
[ ! -L "$output_dir" ] || {
  printf 'builder suite error: output directory is a symlink\n' >&2
  exit 2
}
/bin/mkdir -p "$output_dir"
/bin/chmod 700 "$output_dir"
output_dir=$(cd "$output_dir" && pwd -P)

run_case() {
  case_id=$1
  command_text=$2
  "$receipt_runner" \
    "$repo" \
    "$platform" \
    "${platform}-${case_id}" \
    "$output_dir/${platform}-${case_id}.txt" \
    "$command_text"
}

printf -v quoted_clone_marker '%q' "$clone_marker"
run_case setup-clone-verification \
  "scripts/verify_builder_fresh_clone.py --marker $quoted_clone_marker"
run_case setup-toolchain \
  'uname -a && rustc -Vv && cargo -V && git --version && python3 --version && cc --version'

run_case section9-01-fmt \
  'cargo fmt --all -- --check'
run_case section9-02-check \
  'cargo check --workspace --all-targets'
run_case section9-03-clippy-jcode-omnis \
  'cargo clippy -p jcode-omnis --all-targets -- -D warnings'
run_case section9-04-clippy-omnis-key-cli \
  'cargo clippy -p omnis-key-cli --all-targets -- -D warnings'
run_case section9-05-test-jcode-omnis \
  'cargo test -p jcode-omnis'
run_case section9-06-test-omnis-key-cli \
  'cargo test -p omnis-key-cli'
run_case section9-07-build-omnis-key \
  'cargo build --locked -p omnis-key-cli --bin omnis-key'
run_case section9-08-test-base-omnis \
  'cargo test -p jcode-base omnis::tests'
run_case section9-09-test-base-safety \
  'cargo test -p jcode-base safety::tests'
run_case section9-10-test-base-adversarial \
  'cargo test -p jcode-base safety::adversarial_tests'
run_case section9-11-test-jcode-omnis \
  'cargo test -p jcode --lib cli::omnis::tests'
run_case section9-12-test-jcode-startup \
  'cargo test -p jcode --lib cli::startup::tests'
run_case section9-13-test-authority-override \
  'cargo test -p jcode --lib cli::args::tests::omnis_checkpoint_commands_expose_no_authority_override'
run_case section9-14-test-e2e-safety \
  'cargo test --test e2e safety -- --test-threads=1'

run_case additional-version-text \
  'cargo run --locked -q -p omnis-key-cli --bin omnis-key -- --version'
run_case additional-version-json \
  'cargo run --locked -q -p omnis-key-cli --bin omnis-key -- version --json'
run_case additional-build-jcode \
  'cargo build --locked -p jcode --bin jcode'
run_case additional-sovereignty-runtime \
  'python3 tests/sovereignty/verify_runtime.py --omnis-key target/debug/omnis-key --jcode target/debug/jcode'
run_case additional-runtime-harness-self-tests \
  'python3 tests/sovereignty/test_verify_runtime_adversarial.py'
run_case additional-demo-sigkill-hold \
  'python3 tests/holds/reproduce_demo_sigkill_reclamation_hold.py --omnis-key target/debug/omnis-key'

runtime_source="$repo/target/sovereignty/runtime-receipt.json"
runtime_destination="$output_dir/${platform}-runtime-sovereignty.json"
[ -f "$runtime_source" ] && [ ! -L "$runtime_source" ] || {
  printf 'builder suite error: rich runtime receipt is absent or unsafe\n' >&2
  exit 1
}
[ ! -e "$runtime_destination" ] && [ ! -L "$runtime_destination" ] || {
  printf 'builder suite error: rich runtime receipt destination exists\n' >&2
  exit 1
}
/bin/cp "$runtime_source" "$runtime_destination"
/bin/chmod 600 "$runtime_destination"

run_case additional-workspace-metadata \
  'scripts/check_workspace_metadata.sh'
run_case additional-third-party-inventory \
  'scripts/check_third_party_inventory.sh'
run_case additional-release-hygiene \
  'scripts/check_release_hygiene.sh'
run_case additional-boundary-tests \
  'cargo test -p jcode-base omnis::boundary::tests'
run_case additional-full-workspace-tests \
  'cargo test --workspace --all-targets --locked'
run_case additional-release-diff-guardrails \
  'python3 scripts/check_release_diff_guardrails.py --base 670955adf1eebb207bc4a4411e5f6083562d167c --candidate HEAD --check-warnings'
run_case additional-git-diff-check \
  'git diff --check'
run_case additional-committed-range-diff-check \
  'git diff --check 670955adf1eebb207bc4a4411e5f6083562d167c..HEAD'
run_case additional-dependency-boundaries \
  'python3 scripts/check_dependency_boundaries.py'
run_case additional-assembler-self-tests \
  'python3 scripts/test_assemble_verification_index.py'
run_case additional-archive-self-tests \
  'python3 scripts/test_verify_source_archive.py'
run_case additional-security-exception-binding-self-tests \
  'python3 scripts/test_security_exception_binding.py'
