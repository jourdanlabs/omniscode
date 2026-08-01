//! # jcode-verifiers — Claim Ledger stage 3
//!
//! **Load-bearing rule (Pan architecture, 2026-07-30):**
//! this crate contains **no model call**. Verifiers are real tools whose output
//! a third party can reproduce: `git`, process exit codes, parsed test summaries.
//!
//! If a model ever adjudicates here, receipts become worthless.
//!
//! Dependency policy: **zero** `jcode-provider*`, `jcode-base`, or HTTP LLM clients.
//! Enforced by `tests/no_provider_deps.rs`.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// Result of one deterministic verifier run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationEvidence {
    pub verifier: String,
    pub command: Vec<String>,
    pub exit_code: i32,
    pub stdout_excerpt: String,
    pub stderr_excerpt: String,
    /// Machine-readable payload (e.g. file set). Never secrets.
    pub facts: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerifierDecision {
    /// Tool proved the claim true.
    ProvedTrue,
    /// Tool proved the claim false.
    ProvedFalse,
    /// Tool ran but could not decide.
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierResult {
    pub decision: VerifierDecision,
    pub evidence: VerificationEvidence,
    pub bound: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum VerifierError {
    #[error("git unavailable or not a repository: {0}")]
    Git(String),
    #[error("command failed to spawn: {0}")]
    Spawn(String),
    #[error("invalid claim input: {0}")]
    Invalid(String),
}

fn excerpt(s: &str, max: usize) -> String {
    let t = s.trim();
    if t.len() <= max {
        t.to_string()
    } else {
        format!("{}…", &t[..max])
    }
}

fn run_command(
    cwd: &Path,
    program: &str,
    args: &[&str],
) -> Result<(i32, String, String), VerifierError> {
    let output = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .output()
        .map_err(|e| VerifierError::Spawn(format!("{program}: {e}")))?;
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    Ok((code, stdout, stderr))
}

/// P1 · "I changed only these files"
///
/// Compares `git diff --name-only <base>` (default: `HEAD`) working tree + index
/// against the declared set. Paths are normalized to repo-relative forward slashes.
pub fn verify_files_changed(
    repo: &Path,
    declared: &BTreeSet<String>,
    base: Option<&str>,
) -> Result<VerifierResult, VerifierError> {
    if declared.is_empty() {
        return Err(VerifierError::Invalid(
            "files-changed claim requires a non-empty declared set".into(),
        ));
    }
    let base = base.unwrap_or("HEAD");
    let args = ["diff", "--name-only", base];
    let (code, stdout, stderr) = run_command(repo, "git", &args)?;
    if code != 0 {
        return Ok(VerifierResult {
            decision: VerifierDecision::Unresolved,
            evidence: VerificationEvidence {
                verifier: "files_changed".into(),
                command: vec![
                    "git".into(),
                    "diff".into(),
                    "--name-only".into(),
                    base.into(),
                ],
                exit_code: code,
                stdout_excerpt: excerpt(&stdout, 800),
                stderr_excerpt: excerpt(&stderr, 800),
                facts: serde_json::json!({ "error": "git_diff_failed" }),
            },
            bound: Some("requires a git worktree with the named base ref".into()),
        });
    }

    // Also include staged-only names (diff HEAD misses pure index changes when base=HEAD
    // for unstaged; for full picture use name-only of working tree vs base for both).
    let mut actual: BTreeSet<String> = BTreeSet::new();
    for line in stdout.lines() {
        let p = line.trim().replace('\\', "/");
        if !p.is_empty() {
            actual.insert(p);
        }
    }
    // Untracked files that are part of "what I changed" — agents often create new files.
    // Bound: we include untracked via `git ls-files --others --exclude-standard`.
    let (ucode, ustdout, _) =
        run_command(repo, "git", &["ls-files", "--others", "--exclude-standard"])?;
    if ucode == 0 {
        for line in ustdout.lines() {
            let p = line.trim().replace('\\', "/");
            if !p.is_empty() {
                actual.insert(p);
            }
        }
    }

    let declared_norm: BTreeSet<String> = declared
        .iter()
        .map(|s| s.trim().trim_start_matches("./").replace('\\', "/"))
        .filter(|s| !s.is_empty())
        .collect();

    let extra: BTreeSet<_> = actual.difference(&declared_norm).cloned().collect();
    let missing: BTreeSet<_> = declared_norm.difference(&actual).cloned().collect();
    let equal = extra.is_empty() && missing.is_empty();

    let decision = if equal {
        VerifierDecision::ProvedTrue
    } else {
        VerifierDecision::ProvedFalse
    };

    Ok(VerifierResult {
        decision,
        evidence: VerificationEvidence {
            verifier: "files_changed".into(),
            command: vec![
                "git".into(),
                "diff".into(),
                "--name-only".into(),
                base.into(),
                "+ ls-files --others --exclude-standard".into(),
            ],
            exit_code: 0,
            stdout_excerpt: excerpt(&format!("actual={actual:?}"), 800),
            stderr_excerpt: excerpt(&stderr, 200),
            facts: serde_json::json!({
                "base": base,
                "declared": declared_norm,
                "actual": actual,
                "extra": extra,
                "missing_from_worktree": missing,
            }),
        },
        bound: Some(
            "compares git worktree+untracked (not ignored) against declared set; does not expand renames beyond git's name-only view"
                .into(),
        ),
    })
}

/// P1 · "the build passes" — run the supplied command; exit 0 ⇒ proved true.
pub fn verify_build(cwd: &Path, command: &[String]) -> Result<VerifierResult, VerifierError> {
    verify_exit_zero(cwd, command, "build")
}

/// P1 · "tests pass" — run the supplied command; exit 0 ⇒ proved true.
pub fn verify_tests(cwd: &Path, command: &[String]) -> Result<VerifierResult, VerifierError> {
    verify_exit_zero(cwd, command, "tests")
}

fn verify_exit_zero(
    cwd: &Path,
    command: &[String],
    verifier: &str,
) -> Result<VerifierResult, VerifierError> {
    if command.is_empty() {
        return Err(VerifierError::Invalid(format!(
            "{verifier} claim requires a non-empty command"
        )));
    }
    let program = &command[0];
    let args: Vec<&str> = command[1..].iter().map(String::as_str).collect();
    let (code, stdout, stderr) = run_command(cwd, program, &args)?;
    let decision = if code == 0 {
        VerifierDecision::ProvedTrue
    } else {
        VerifierDecision::ProvedFalse
    };
    Ok(VerifierResult {
        decision,
        evidence: VerificationEvidence {
            verifier: verifier.into(),
            command: command.to_vec(),
            exit_code: code,
            stdout_excerpt: excerpt(&stdout, 1200),
            stderr_excerpt: excerpt(&stderr, 1200),
            facts: serde_json::json!({
                "cwd": cwd.display().to_string(),
                "exit_code": code,
            }),
        },
        bound: Some(format!(
            "exit code only — does not interpret {verifier} output semantics beyond process status"
        )),
    })
}

/// Helper for tests: path existence check (not a product verifier).
pub fn path_is_dir(p: impl AsRef<Path>) -> bool {
    p.as_ref().is_dir()
}

pub type RepoPath = PathBuf;

/// Soft wall-clock budget documentation (verifiers themselves do not enforce it).
pub const DEFAULT_COMMAND_BUDGET: Duration = Duration::from_secs(600);
