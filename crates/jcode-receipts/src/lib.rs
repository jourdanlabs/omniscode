//! # jcode-receipts — agent action receipts
//!
//! The OMNIS hash chain (`jcode_base::omnis`) already lives as a library.
//! This crate is the **agent-facing surface**: redacted action records, policy
//! flags, and fail-closed helpers so tools never shell out to `omnis-key`.
//!
//! ## Redaction rule (load-bearing)
//! Receipt the *shape and effect* of an action. **Never** raw argv, file
//! contents, or env. Secrets must not enter the append-only plaintext ledger.
//!
//! ## Provenance ≠ veracity
//! Receipts prove **what happened**, not that the work was correct.

#![forbid(unsafe_code)]

mod action;
mod policy;

// Re-export the chain primitive so both omnis-key-cli and tools share one import path.
pub use jcode_base::omnis::{
    AppendDisposition, AppendOutcome, ClaimCeiling, Receipt, Verification, append,
    append_idempotent, append_idempotent_with_evidence, canonical_ledger_path,
    ensure_private_directory_tree, ledger_path, validate_private_directory, validate_private_file,
    verified_receipts, verify,
};

pub use action::{
    ActionTool, BashReceiptInput, EditReceiptInput, FULL_ARGV_WARNING, WriteReceiptInput,
    content_sha256, preflight_ledger_writable, program_name, record_bash, record_edit,
    record_write, repo_root_sha256, sha256_hex,
};

/// Preflight only when receipts are enabled.
pub fn preflight_if_enabled() -> anyhow::Result<()> {
    if !action_receipts_enabled() {
        return Ok(());
    }
    preflight_ledger_writable()
}
pub use policy::{
    ActionReceiptPolicy, action_receipts_enabled, receipt_full_argv_enabled, receipt_reads_enabled,
    session_receipts_disabled_note,
};
