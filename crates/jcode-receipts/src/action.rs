//! Redacted agent action receipts.

use crate::policy::{action_receipts_enabled, receipt_full_argv_enabled};
use anyhow::{Context, Result, bail};
use jcode_base::omnis::{self, AppendOutcome, ClaimCeiling, append_idempotent_with_evidence};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub const FULL_ARGV_WARNING: &str = "\
WARNING: --receipt-full-argv / JCODE_RECEIPT_FULL_ARGV is enabled. \
Full command strings will be written to the plaintext append-only ledger. \
Do not use with secrets. Prefer the default redacted mode.";

/// Closed enum of receipted tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionTool {
    Edit,
    Write,
    Bash,
    Read,
}

impl ActionTool {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Edit => "edit",
            Self::Write => "write",
            Self::Bash => "bash",
            Self::Read => "read",
        }
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

pub fn content_sha256(text: &str) -> String {
    format!("sha256:{}", sha256_hex(text.as_bytes()))
}

/// Program name only — first token of argv (basename if path-like).
pub fn program_name(command: &str) -> String {
    let first = command
        .split_whitespace()
        .next()
        .unwrap_or("unknown")
        .trim_matches(|c| c == '"' || c == '\'');
    Path::new(first)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(first)
        .to_string()
}

pub fn repo_root_sha256(repo: &Path) -> String {
    format!("sha256:{}", sha256_hex(repo.to_string_lossy().as_bytes()))
}

fn cwd_sha256(cwd: &Path) -> String {
    format!("sha256:{}", sha256_hex(cwd.to_string_lossy().as_bytes()))
}

fn event_id(tool: ActionTool, salt: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    // event_id is plaintext — use only non-secret material
    format!(
        "agent.{}-{}-{}",
        tool.as_str(),
        &sha256_hex(salt.as_bytes())[..16],
        nanos
    )
}

/// Evidence blob: shape + hashes only (unless full_argv explicitly enabled).
#[derive(Debug, Serialize)]
struct ActionEvidence {
    tool: ActionTool,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_before_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_after_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    argv_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    argv_program: Option<String>,
    /// Only when full_argv policy is on — never the default.
    #[serde(skip_serializing_if = "Option::is_none")]
    argv_full: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
    cwd_sha256: String,
    repo_root_sha256: String,
    redacted: bool,
}

/// Serialize evidence for both digest binding and ledger storage (same bytes).
fn evidence_value(ev: &ActionEvidence) -> Result<serde_json::Value> {
    serde_json::to_value(ev).context("serialize action evidence")
}

fn evidence_digest_from_value(value: &serde_json::Value) -> Result<String> {
    let bytes = serde_json::to_vec(value).context("serialize action evidence bytes")?;
    Ok(format!("sha256:{}", sha256_hex(&bytes)))
}

fn subject_for(tool: ActionTool, target_or_program: &str) -> String {
    // Subject is plaintext — path is OK (repo-relative); never full secret-bearing argv.
    format!("{}:{}", tool.as_str(), target_or_program)
}

fn append_action(
    kind: &str,
    subject: &str,
    evidence: &ActionEvidence,
    eid: &str,
) -> Result<AppendOutcome> {
    // Store the safe evidence object on the ledger line (FIX 1). argv_full is only
    // present when the operator explicitly enabled full-argv (still hashed into digest).
    let payload = evidence_value(evidence)?;
    let digest = evidence_digest_from_value(&payload)?;
    let ledger = omnis::canonical_ledger_path().context("RECEIPT_APPEND_FAILED: ledger path")?;
    // Ensure parents are 0700 before append (FIX 3 path used by agent tools).
    if let Some(parent) = ledger.parent() {
        omnis::ensure_private_directory_tree(parent).with_context(|| {
            format!(
                "RECEIPT_APPEND_FAILED: cannot create private ledger parent {}",
                parent.display()
            )
        })?;
    }
    append_idempotent_with_evidence(
        &ledger,
        eid,
        kind,
        subject,
        &digest,
        ClaimCeiling::LocalRecord,
        payload,
    )
    .map_err(|e| {
        anyhow::anyhow!(
            "RECEIPT_APPEND_FAILED: ledger unwritable or chain unsafe at {} ({e:#}). \
             The mutation was NOT applied (or was rolled back). Fix the ledger or run with --no-receipts.",
            ledger.display()
        )
    })
}

/// Preflight: can we append? Used before bash so we refuse to run unreceipted.
pub fn preflight_ledger_writable() -> Result<()> {
    if !action_receipts_enabled() {
        return Ok(());
    }
    let ledger = omnis::canonical_ledger_path().context("RECEIPT_APPEND_FAILED: ledger path")?;
    if let Some(parent) = ledger.parent() {
        omnis::ensure_private_directory_tree(parent).with_context(|| {
            format!(
                "RECEIPT_APPEND_FAILED: cannot create private ledger parent {}",
                parent.display()
            )
        })?;
    }
    // verify empty-or-valid
    let v = omnis::verify(&ledger).context("RECEIPT_APPEND_FAILED: cannot verify ledger")?;
    if !v.valid() && v.entries() > 0 {
        bail!(
            "RECEIPT_APPEND_FAILED: ledger invalid at {} — refuse to run unreceipted action",
            ledger.display()
        );
    }
    Ok(())
}

pub struct EditReceiptInput<'a> {
    pub target_repo_relative: &'a str,
    pub before: &'a str,
    pub after: &'a str,
    pub cwd: &'a Path,
    pub repo_root: &'a Path,
}

/// Record an edit receipt **before** the caller applies the write.
pub fn record_edit(input: EditReceiptInput<'_>) -> Result<Option<AppendOutcome>> {
    if !action_receipts_enabled() {
        return Ok(None);
    }
    let ev = ActionEvidence {
        tool: ActionTool::Edit,
        target: Some(input.target_repo_relative.replace('\\', "/")),
        content_before_sha256: Some(content_sha256(input.before)),
        content_after_sha256: Some(content_sha256(input.after)),
        argv_sha256: None,
        argv_program: None,
        argv_full: None,
        exit_code: None,
        cwd_sha256: cwd_sha256(input.cwd),
        repo_root_sha256: repo_root_sha256(input.repo_root),
        redacted: true,
    };
    let eid = event_id(ActionTool::Edit, input.target_repo_relative);
    let subject = subject_for(ActionTool::Edit, input.target_repo_relative);
    Ok(Some(append_action("agent.edit", &subject, &ev, &eid)?))
}

pub struct WriteReceiptInput<'a> {
    pub target_repo_relative: &'a str,
    pub before: Option<&'a str>,
    pub after: &'a str,
    pub cwd: &'a Path,
    pub repo_root: &'a Path,
}

pub fn record_write(input: WriteReceiptInput<'_>) -> Result<Option<AppendOutcome>> {
    if !action_receipts_enabled() {
        return Ok(None);
    }
    let ev = ActionEvidence {
        tool: ActionTool::Write,
        target: Some(input.target_repo_relative.replace('\\', "/")),
        content_before_sha256: input.before.map(content_sha256),
        content_after_sha256: Some(content_sha256(input.after)),
        argv_sha256: None,
        argv_program: None,
        argv_full: None,
        exit_code: None,
        cwd_sha256: cwd_sha256(input.cwd),
        repo_root_sha256: repo_root_sha256(input.repo_root),
        redacted: true,
    };
    let eid = event_id(ActionTool::Write, input.target_repo_relative);
    let subject = subject_for(ActionTool::Write, input.target_repo_relative);
    Ok(Some(append_action("agent.write", &subject, &ev, &eid)?))
}

pub struct BashReceiptInput<'a> {
    pub command: &'a str,
    pub exit_code: i32,
    pub cwd: &'a Path,
    pub repo_root: &'a Path,
}

pub fn record_bash(input: BashReceiptInput<'_>) -> Result<Option<AppendOutcome>> {
    if !action_receipts_enabled() {
        return Ok(None);
    }
    let full = receipt_full_argv_enabled();
    let prog = program_name(input.command);
    let ev = ActionEvidence {
        tool: ActionTool::Bash,
        target: None,
        content_before_sha256: None,
        content_after_sha256: None,
        argv_sha256: Some(format!("sha256:{}", sha256_hex(input.command.as_bytes()))),
        argv_program: Some(prog.clone()),
        argv_full: if full {
            Some(input.command.to_string())
        } else {
            None
        },
        exit_code: Some(input.exit_code),
        cwd_sha256: cwd_sha256(input.cwd),
        repo_root_sha256: repo_root_sha256(input.repo_root),
        redacted: !full,
    };
    let eid = event_id(ActionTool::Bash, &format!("{}:{}", prog, input.exit_code));
    let subject = subject_for(ActionTool::Bash, &prog);
    Ok(Some(append_action("agent.bash", &subject, &ev, &eid)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_name_strips_path_and_args() {
        assert_eq!(
            program_name("curl -H 'Authorization: Bearer sk-ant-SECRET' https://x"),
            "curl"
        );
        assert_eq!(program_name("/usr/bin/node cart.test.js"), "node");
        assert_eq!(program_name("cargo test --lib"), "cargo");
    }

    #[test]
    fn content_hash_stable() {
        assert_eq!(content_sha256("a"), content_sha256("a"));
        assert_ne!(content_sha256("a"), content_sha256("b"));
    }
}
