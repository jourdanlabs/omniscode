#!/bin/bash
# Retain one clean-candidate command receipt under a non-ambient toolchain.
set -euo pipefail
set -f

if [ "$#" -ne 5 ]; then
  printf 'usage: run_builder_receipt.sh REPO PLATFORM RECEIPT_ID OUTPUT COMMAND\n' >&2
  exit 2
fi

repo=$1
platform=$2
receipt_id=$3
output=$4
command_text=$5
temporary=""
toolchain_root=""

plain_error() {
  printf 'builder receipt error: %s\n' "$*" >&2
}

core_executable() {
  core_name=$1
  shift
  for core_candidate in "$@"; do
    if [ -f "$core_candidate" ] && [ -x "$core_candidate" ]; then
      core_directory=$(cd "$(/usr/bin/dirname "$core_candidate")" && pwd -P)
      printf '%s/%s\n' "$core_directory" "$(/usr/bin/basename "$core_candidate")"
      return 0
    fi
  done
  plain_error "required host executable is absent: $core_name"
  return 1
}

cleanup() {
  command_status=$?
  trap - EXIT HUP INT TERM
  if [ -n "$temporary" ] &&
     { [ -e "$temporary" ] || [ -L "$temporary" ]; }; then
    "$core_rm" -f -- "$temporary" || command_status=1
  fi
  if [ -n "$toolchain_root" ] &&
     { [ -e "$toolchain_root" ] || [ -L "$toolchain_root" ]; }; then
    case "$toolchain_root" in
      "$output_parent/.builder-toolchain."*)
        if [ -d "$toolchain_root" ] && [ ! -L "$toolchain_root" ]; then
          "$core_rm" -rf -- "$toolchain_root" || command_status=1
        else
          "$core_rm" -f -- "$toolchain_root" || command_status=1
          plain_error "toolchain root became unsafe during command execution"
          command_status=1
        fi
        ;;
      *)
        plain_error "refusing unsafe toolchain cleanup target"
        command_status=1
        ;;
    esac
  fi
  exit "$command_status"
}

exit_on_signal() {
  case "$1" in
    HUP) signal_status=129 ;;
    INT) signal_status=130 ;;
    TERM) signal_status=143 ;;
    *) signal_status=1 ;;
  esac
  plain_error "interrupted by $1"
  exit "$signal_status"
}

trap cleanup EXIT
trap 'exit_on_signal HUP' HUP
trap 'exit_on_signal INT' INT
trap 'exit_on_signal TERM' TERM

core_rm=$(core_executable rm /bin/rm /usr/bin/rm)
core_mv=$(core_executable mv /bin/mv /usr/bin/mv)
core_chmod=$(core_executable chmod /bin/chmod /usr/bin/chmod)
core_mkdir=$(core_executable mkdir /bin/mkdir /usr/bin/mkdir)
core_ln=$(core_executable ln /bin/ln /usr/bin/ln)
core_mktemp=$(core_executable mktemp /usr/bin/mktemp /bin/mktemp)
core_date=$(core_executable date /bin/date /usr/bin/date)
core_env=$(core_executable env /usr/bin/env /bin/env)
core_id=$(core_executable id /usr/bin/id /bin/id)
core_readlink=$(core_executable readlink /usr/bin/readlink /bin/readlink)

[ -d "$repo" ] && [ ! -L "$repo" ] || {
  plain_error "repository root is absent or unsafe"
  exit 2
}
repo=$(cd "$repo" && pwd -P)
runner_source=${BASH_SOURCE[0]}
runner_directory=$(cd "$(/usr/bin/dirname "$runner_source")" && pwd -P)
runner_path="$runner_directory/$("/usr/bin/basename" "$runner_source")"
[ "$runner_path" = "$repo/scripts/run_builder_receipt.sh" ] &&
  [ -f "$runner_path" ] &&
  [ ! -L "$runner_path" ] || {
  plain_error "receipt runner must be the candidate-tracked script"
  exit 2
}
case "$platform" in
  linux)
    [ "$(/usr/bin/uname -s)" = "Linux" ] || {
      plain_error "linux receipt requested on a non-Linux host"
      exit 2
    }
    ;;
  macos)
    [ "$(/usr/bin/uname -s)" = "Darwin" ] || {
      plain_error "macos receipt requested on a non-macOS host"
      exit 2
    }
    ;;
  *)
    plain_error "platform must be linux or macos"
    exit 2
    ;;
esac
case "$receipt_id" in
  "" | *[!a-z0-9._-]* | [!a-z0-9]*)
    plain_error "receipt ID is unsafe"
    exit 2
    ;;
esac
[ "${#receipt_id}" -le 128 ] || {
  plain_error "receipt ID exceeds 128 characters"
  exit 2
}
case "$command_text" in
  "" | *$'\n'* | *$'\r'*)
    plain_error "command must be one nonempty line"
    exit 2
    ;;
esac

[ ! -e "$output" ] && [ ! -L "$output" ] || {
  plain_error "output already exists"
  exit 2
}
output_parent=$(/usr/bin/dirname "$output")
output_name=$(/usr/bin/basename "$output")
[ "$output_name" != "." ] && [ "$output_name" != ".." ] || {
  plain_error "output filename is unsafe"
  exit 2
}
[ -d "$output_parent" ] && [ ! -L "$output_parent" ] || {
  plain_error "output parent is absent or unsafe"
  exit 2
}
output_parent=$(cd "$output_parent" && pwd -P)
case "$output_parent/" in
  "$repo/" | "$repo/"*)
    plain_error "output parent must remain outside the candidate worktree"
    exit 2
    ;;
esac
output="$output_parent/$output_name"

account_uid=$("$core_id" -u)
account_name=$("$core_id" -un)
trusted_home=""
if [ "$platform" = "linux" ] && [ -x /usr/bin/getent ]; then
  passwd_entry=$(/usr/bin/getent passwd "$account_uid" || true)
  if [ -n "$passwd_entry" ]; then
    old_ifs=$IFS
    IFS=:
    set -- $passwd_entry
    IFS=$old_ifs
    [ "$#" -ge 6 ] && trusted_home=$6
  fi
elif [ "$platform" = "macos" ] && [ -x /usr/bin/dscl ]; then
  home_entry=$(/usr/bin/dscl . -read "/Users/$account_name" NFSHomeDirectory 2>/dev/null || true)
  case "$home_entry" in
    "NFSHomeDirectory: "*) trusted_home=${home_entry#NFSHomeDirectory: } ;;
  esac
fi
if [ -z "$trusted_home" ]; then
  case "${HOME:-}" in
    /*) trusted_home=$HOME ;;
    *)
      plain_error "could not resolve the invoking account home directory"
      exit 2
      ;;
  esac
fi
[ -d "$trusted_home" ] && [ ! -L "$trusted_home" ] || {
  plain_error "invoking account home directory is unsafe"
  exit 2
}
trusted_home=$(cd "$trusted_home" && pwd -P)

trusted_bash=$(core_executable bash /bin/bash)
trusted_git=$(core_executable git /usr/bin/git /usr/local/bin/git /opt/homebrew/bin/git)
trusted_python3=$(core_executable python3 /usr/bin/python3 /usr/local/bin/python3 /opt/homebrew/bin/python3)
trusted_cc=$(core_executable cc /usr/bin/cc /usr/local/bin/cc)
trusted_uname=$(core_executable uname /usr/bin/uname /bin/uname)

find_rust_tool() {
  rust_tool_name=$1
  for rust_directory in \
    "$trusted_home/.cargo/bin" \
    /usr/local/cargo/bin \
    /root/.cargo/bin \
    /opt/homebrew/bin \
    /usr/local/bin \
    /usr/bin; do
    rust_candidate="$rust_directory/$rust_tool_name"
    if [ -f "$rust_candidate" ] && [ -x "$rust_candidate" ]; then
      rust_physical_directory=$(cd "$rust_directory" && pwd -P)
      printf '%s/%s\n' "$rust_physical_directory" "$rust_tool_name"
      return 0
    fi
  done
  plain_error "trusted Rust tool is absent: $rust_tool_name"
  return 1
}

trusted_cargo=$(find_rust_tool cargo)
trusted_rustc=$(find_rust_tool rustc)
trusted_rustfmt=$(find_rust_tool rustfmt)
trusted_cargo_fmt=$(find_rust_tool cargo-fmt)
trusted_cargo_clippy=$(find_rust_tool cargo-clippy)
trusted_clippy_driver=$(find_rust_tool clippy-driver)
cargo_bin_directory=$(/usr/bin/dirname "$trusted_cargo")
trusted_cargo_home=$(cd "$cargo_bin_directory/.." && pwd -P)
if [ -d "$trusted_cargo_home/../rustup" ]; then
  trusted_rustup_home=$(cd "$trusted_cargo_home/../rustup" && pwd -P)
elif [ -d "$trusted_home/.rustup" ]; then
  trusted_rustup_home=$(cd "$trusted_home/.rustup" && pwd -P)
else
  plain_error "trusted Rustup home is absent"
  exit 2
fi

if [ "$platform" = "macos" ]; then
  trusted_hasher=$(core_executable shasum /usr/bin/shasum)
else
  trusted_hasher=$(core_executable sha256sum /usr/bin/sha256sum /bin/sha256sum /sbin/sha256sum)
fi

supplemental_tool_path=""
supplemental_input=${OMNIS_BUILDER_SUPPLEMENTAL_TOOL_PATH:-}
if [ -n "$supplemental_input" ]; then
  case "$supplemental_input" in
    :* | *: | *::* | *$'\n'* | *$'\r'*)
      plain_error "supplemental tool path has empty or unsafe components"
      exit 2
      ;;
  esac
  old_ifs=$IFS
  IFS=:
  set -- $supplemental_input
  IFS=$old_ifs
  [ "$#" -gt 0 ] || {
    plain_error "supplemental tool path is empty"
    exit 2
  }
  for supplemental_directory in "$@"; do
    case "$supplemental_directory" in
      /*) ;;
      *)
        plain_error "supplemental tool directory must be absolute"
        exit 2
        ;;
    esac
    [ -d "$supplemental_directory" ] && [ ! -L "$supplemental_directory" ] || {
      plain_error "supplemental tool directory is absent or unsafe"
      exit 2
    }
    supplemental_physical=$(cd "$supplemental_directory" && pwd -P)
    [ "$supplemental_physical" = "$supplemental_directory" ] || {
      plain_error "supplemental tool directory is not canonical"
      exit 2
    }
    case ":$supplemental_tool_path:" in
      *":$supplemental_physical:"*)
        plain_error "supplemental tool directory is duplicated"
        exit 2
        ;;
    esac
    if [ -z "$supplemental_tool_path" ]; then
      supplemental_tool_path=$supplemental_physical
    else
      supplemental_tool_path="$supplemental_tool_path:$supplemental_physical"
    fi
  done
fi

supplemental_cargo_audit=""
supplemental_cargo_deny=""
supplemental_gitleaks=""
supplemental_go=""
find_supplemental_tool() {
  supplemental_name=$1
  supplemental_match=""
  supplemental_count=0
  old_ifs=$IFS
  IFS=:
  set -- $supplemental_tool_path
  IFS=$old_ifs
  for supplemental_directory in "$@"; do
    supplemental_candidate="$supplemental_directory/$supplemental_name"
    if [ -f "$supplemental_candidate" ] &&
       [ ! -L "$supplemental_candidate" ] &&
       [ -x "$supplemental_candidate" ]; then
      supplemental_match=$supplemental_candidate
      supplemental_count=$((supplemental_count + 1))
    fi
  done
  [ "$supplemental_count" -eq 1 ] || {
    plain_error "supplemental tool must resolve exactly once: $supplemental_name"
    return 1
  }
  printf '%s\n' "$supplemental_match"
}
if [ -n "$supplemental_tool_path" ]; then
  supplemental_cargo_audit=$(find_supplemental_tool cargo-audit)
  supplemental_cargo_deny=$(find_supplemental_tool cargo-deny)
  supplemental_gitleaks=$(find_supplemental_tool gitleaks)
  supplemental_go=$(find_supplemental_tool go)
fi

toolchain_root=$("$core_mktemp" -d "$output_parent/.builder-toolchain.XXXXXX")
"$core_chmod" 700 "$toolchain_root"
toolchain_bin="$toolchain_root/bin"
"$core_mkdir" "$toolchain_bin"
"$core_chmod" 700 "$toolchain_bin"

link_tool() {
  link_name=$1
  link_target=$2
  "$core_ln" -s "$link_target" "$toolchain_bin/$link_name"
}
link_tool bash "$trusted_bash"
link_tool cargo "$trusted_cargo"
link_tool cargo-clippy "$trusted_cargo_clippy"
link_tool cargo-fmt "$trusted_cargo_fmt"
link_tool cc "$trusted_cc"
link_tool clippy-driver "$trusted_clippy_driver"
link_tool git "$trusted_git"
link_tool python3 "$trusted_python3"
link_tool rustc "$trusted_rustc"
link_tool rustfmt "$trusted_rustfmt"
link_tool uname "$trusted_uname"
if [ -n "$supplemental_tool_path" ]; then
  link_tool cargo-audit "$supplemental_cargo_audit"
  link_tool cargo-deny "$supplemental_cargo_deny"
  link_tool gitleaks "$supplemental_gitleaks"
  link_tool go "$supplemental_go"
fi

trusted_path="$toolchain_bin:/usr/bin:/bin:/usr/sbin:/sbin"

run_trusted() {
  "$core_env" -i \
    HOME="$trusted_home" \
    CARGO_HOME="$trusted_cargo_home" \
    RUSTUP_HOME="$trusted_rustup_home" \
    PATH="$trusted_path" \
    LANG=C \
    LC_ALL=C \
    TMPDIR="$toolchain_root" \
    CARGO_TERM_COLOR=never \
    RUST_BACKTRACE=0 \
    RUSTC="$trusted_rustc" \
    CC="$trusted_cc" \
    GIT_ALLOW_PROTOCOL=file \
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_TERMINAL_PROMPT=0 \
    OMNIS_BUILDER_TOOL_BASH="$trusted_bash" \
    OMNIS_BUILDER_TOOL_CARGO="$trusted_cargo" \
    OMNIS_BUILDER_TOOL_CC="$trusted_cc" \
    OMNIS_BUILDER_TOOL_GIT="$trusted_git" \
    OMNIS_BUILDER_TOOL_PYTHON3="$trusted_python3" \
    OMNIS_BUILDER_TOOL_RUSTC="$trusted_rustc" \
    OMNIS_BUILDER_TOOL_UNAME="$trusted_uname" \
    "$@"
}

run_trusted "$trusted_git" -C "$repo" rev-parse --is-inside-work-tree >/dev/null 2>&1 || {
  plain_error "repository root is not a Git worktree"
  exit 2
}
[ -z "$(run_trusted "$trusted_git" -C "$repo" status --porcelain=v1 --untracked-files=all)" ] || {
  plain_error "candidate worktree must be clean before receipt execution"
  exit 2
}
candidate=$(run_trusted "$trusted_git" -C "$repo" rev-parse --verify 'HEAD^{commit}')
tree=$(run_trusted "$trusted_git" -C "$repo" rev-parse 'HEAD^{tree}')

sha256_path() {
  sha_path=$1
  if [ "$platform" = "macos" ]; then
    sha_line=$(run_trusted "$trusted_hasher" -a 256 "$sha_path")
  else
    sha_line=$(run_trusted "$trusted_hasher" "$sha_path")
  fi
  sha_digest=${sha_line%% *}
  case "$sha_digest" in
    *[!0-9a-f]* | "")
      plain_error "could not hash trusted executable: $sha_path"
      return 1
      ;;
  esac
  [ "${#sha_digest}" -eq 64 ] || {
    plain_error "trusted executable digest has the wrong length: $sha_path"
    return 1
  }
  printf '%s\n' "$sha_digest"
}

single_line_identity() {
  identity_name=$1
  identity_path=$2
  case "$identity_name" in
    bash) identity_output=$(run_trusted "$identity_path" --version 2>&1) ;;
    cargo) identity_output=$(run_trusted "$identity_path" -Vv 2>&1) ;;
    cargo-audit) identity_output=$(run_trusted "$identity_path" --version 2>&1) ;;
    cargo-clippy) identity_output=$(run_trusted "$identity_path" --version 2>&1) ;;
    cargo-deny) identity_output=$(run_trusted "$identity_path" --version 2>&1) ;;
    cargo-fmt) identity_output=$(run_trusted "$identity_path" --version 2>&1) ;;
    cc) identity_output=$(run_trusted "$identity_path" --version 2>&1) ;;
    clippy-driver) identity_output=$(run_trusted "$identity_path" --version 2>&1) ;;
    git) identity_output=$(run_trusted "$identity_path" --version 2>&1) ;;
    gitleaks) identity_output=$(run_trusted "$identity_path" version 2>&1) ;;
    go) identity_output=$(run_trusted "$identity_path" version 2>&1) ;;
    python3) identity_output=$(run_trusted "$identity_path" --version 2>&1) ;;
    rustc) identity_output=$(run_trusted "$identity_path" -Vv 2>&1) ;;
    rustfmt) identity_output=$(run_trusted "$identity_path" --version 2>&1) ;;
    uname) identity_output=$(run_trusted "$identity_path" -a 2>&1) ;;
    *)
      plain_error "unknown trusted tool identity: $identity_name"
      return 1
      ;;
  esac
  identity_output=${identity_output//$'\r'/}
  identity_output=${identity_output//$'\n'/\\n}
  case "$identity_output" in
    "" | *$'\r'* | *$'\n'*)
      plain_error "trusted tool identity is empty or unsafe: $identity_name"
      return 1
      ;;
  esac
  printf '%s\n' "$identity_output"
}

toolchain_identity="$toolchain_root/toolchain-identity.txt"
: > "$toolchain_identity"
"$core_chmod" 600 "$toolchain_identity"
printf 'trustedSupplementalToolPath=%s\n' "$supplemental_tool_path" >> "$toolchain_identity"
append_tool_identity() {
  identity_name=$1
  identity_path=$2
  printf 'trustedTool.%s.path=%s\n' "$identity_name" "$identity_path" >> "$toolchain_identity"
  printf 'trustedTool.%s.sha256=%s\n' "$identity_name" "$(sha256_path "$identity_path")" >> "$toolchain_identity"
  printf 'trustedTool.%s.identity=%s\n' "$identity_name" "$(single_line_identity "$identity_name" "$identity_path")" >> "$toolchain_identity"
}
append_tool_identity bash "$trusted_bash"
append_tool_identity cargo "$trusted_cargo"
append_tool_identity cargo-clippy "$trusted_cargo_clippy"
append_tool_identity cargo-fmt "$trusted_cargo_fmt"
append_tool_identity cc "$trusted_cc"
append_tool_identity clippy-driver "$trusted_clippy_driver"
append_tool_identity git "$trusted_git"
append_tool_identity python3 "$trusted_python3"
append_tool_identity rustc "$trusted_rustc"
append_tool_identity rustfmt "$trusted_rustfmt"
append_tool_identity uname "$trusted_uname"
append_supplemental_identity() {
  supplemental_identity_name=$1
  supplemental_identity_path=$2
  if [ -n "$supplemental_identity_path" ]; then
    printf 'trustedSupplementalTool.%s.path=%s\n' \
      "$supplemental_identity_name" "$supplemental_identity_path" >> "$toolchain_identity"
    printf 'trustedSupplementalTool.%s.sha256=%s\n' \
      "$supplemental_identity_name" \
      "$(sha256_path "$supplemental_identity_path")" >> "$toolchain_identity"
    printf 'trustedSupplementalTool.%s.identity=%s\n' \
      "$supplemental_identity_name" \
      "$(single_line_identity "$supplemental_identity_name" "$supplemental_identity_path")" >> "$toolchain_identity"
  else
    printf 'trustedSupplementalTool.%s.path=\n' "$supplemental_identity_name" >> "$toolchain_identity"
    printf 'trustedSupplementalTool.%s.sha256=\n' "$supplemental_identity_name" >> "$toolchain_identity"
    printf 'trustedSupplementalTool.%s.identity=\n' "$supplemental_identity_name" >> "$toolchain_identity"
  fi
}
append_supplemental_identity cargo-audit "$supplemental_cargo_audit"
append_supplemental_identity cargo-deny "$supplemental_cargo_deny"
append_supplemental_identity gitleaks "$supplemental_gitleaks"
append_supplemental_identity go "$supplemental_go"
toolchain_fingerprint=$(sha256_path "$toolchain_identity")

validate_toolchain_link() {
  validation_name=$1
  validation_target=$2
  validation_link="$toolchain_bin/$validation_name"
  [ -L "$validation_link" ] &&
    [ "$("$core_readlink" "$validation_link")" = "$validation_target" ] || {
    plain_error "trusted tool link changed during command: $validation_name"
    return 1
  }
}

validate_toolchain_root() {
  [ -d "$toolchain_root" ] && [ ! -L "$toolchain_root" ] &&
    [ -d "$toolchain_bin" ] && [ ! -L "$toolchain_bin" ] &&
    [ -f "$toolchain_identity" ] && [ ! -L "$toolchain_identity" ] || {
    plain_error "trusted toolchain root changed during command"
    return 1
  }
  [ "$(sha256_path "$toolchain_identity")" = "$toolchain_fingerprint" ] || {
    plain_error "trusted toolchain identity changed during command"
    return 1
  }
  validate_toolchain_link bash "$trusted_bash" || return 1
  validate_toolchain_link cargo "$trusted_cargo" || return 1
  validate_toolchain_link cargo-clippy "$trusted_cargo_clippy" || return 1
  validate_toolchain_link cargo-fmt "$trusted_cargo_fmt" || return 1
  validate_toolchain_link cc "$trusted_cc" || return 1
  validate_toolchain_link clippy-driver "$trusted_clippy_driver" || return 1
  validate_toolchain_link git "$trusted_git" || return 1
  validate_toolchain_link python3 "$trusted_python3" || return 1
  validate_toolchain_link rustc "$trusted_rustc" || return 1
  validate_toolchain_link rustfmt "$trusted_rustfmt" || return 1
  validate_toolchain_link uname "$trusted_uname" || return 1
  if [ -n "$supplemental_tool_path" ]; then
    validate_toolchain_link cargo-audit "$supplemental_cargo_audit" || return 1
    validate_toolchain_link cargo-deny "$supplemental_cargo_deny" || return 1
    validate_toolchain_link gitleaks "$supplemental_gitleaks" || return 1
    validate_toolchain_link go "$supplemental_go" || return 1
  fi
}

temporary=$("$core_mktemp" "$output_parent/.builder-receipt.XXXXXX")
"$core_chmod" 600 "$temporary"
{
  printf 'schemaVersion=2\n'
  printf 'receiptId=%s\n' "$receipt_id"
  printf 'platform=%s\n' "$platform"
  printf 'candidateCommit=%s\n' "$candidate"
  printf 'candidateTree=%s\n' "$tree"
  printf 'command=%s\n' "$command_text"
  printf 'startedUtc=%s\n' "$("$core_date" -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'trustedToolchainFormat=absolute-executables-v1\n'
  printf 'trustedToolchainFingerprintSha256=%s\n' "$toolchain_fingerprint"
  printf 'trustedSupplementalToolPath=%s\n' "$supplemental_tool_path"
  while IFS= read -r identity_line; do
    case "$identity_line" in
      trustedSupplementalToolPath=*) ;;
      *) printf '%s\n' "$identity_line" ;;
    esac
  done < "$toolchain_identity"
  printf '%s\n' '--- command output ---'
} > "$temporary"

launcher="$repo/scripts/lib/run_trusted_builder_command.py"
[ -f "$launcher" ] && [ ! -L "$launcher" ] || {
  plain_error "tracked trusted command launcher is absent or unsafe"
  exit 2
}

set +e
run_trusted "$trusted_python3" "$launcher" "$repo" "$command_text" >> "$temporary" 2>&1
command_status=$?
set -e

if ! validate_toolchain_root >> "$temporary" 2>&1; then
  command_status=125
fi
post_candidate=$(run_trusted "$trusted_git" -C "$repo" rev-parse --verify 'HEAD^{commit}' 2>/dev/null || true)
post_tree=$(run_trusted "$trusted_git" -C "$repo" rev-parse 'HEAD^{tree}' 2>/dev/null || true)
post_dirty=$(run_trusted "$trusted_git" -C "$repo" status --porcelain=v1 --untracked-files=all 2>/dev/null || true)
if [ "$post_candidate" != "$candidate" ] ||
   [ "$post_tree" != "$tree" ] ||
   [ -n "$post_dirty" ]; then
  printf '%s\n' 'builder receipt error: candidate identity or cleanliness changed during command' >> "$temporary"
  command_status=125
fi

{
  printf '%s\n' '--- receipt result ---'
  printf 'exitStatus=%s\n' "$command_status"
  printf 'finishedUtc=%s\n' "$("$core_date" -u +%Y-%m-%dT%H:%M:%SZ)"
} >> "$temporary"

"$core_mv" "$temporary" "$output"
temporary=""
"$core_chmod" 600 "$output"
exit "$command_status"
