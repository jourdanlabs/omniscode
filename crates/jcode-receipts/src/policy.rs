//! Policy flags for agent action receipts.

use std::sync::atomic::{AtomicBool, Ordering};

static NO_RECEIPTS: AtomicBool = AtomicBool::new(false);
static FULL_ARGV: AtomicBool = AtomicBool::new(false);
static RECEIPT_READS: AtomicBool = AtomicBool::new(false);
static SESSION_NO_RECEIPTS_NOTED: AtomicBool = AtomicBool::new(false);

/// Runtime policy (CLI flags win over env after `configure`).
#[derive(Debug, Clone, Copy, Default)]
pub struct ActionReceiptPolicy {
    /// When true, skip all action receipts (explicit opt-out).
    pub no_receipts: bool,
    /// When true, store raw argv in evidence JSON (OFF by default; prints warning).
    pub full_argv: bool,
    /// When true, also receipt read/ls/grep (OFF by default).
    pub receipt_reads: bool,
}

impl ActionReceiptPolicy {
    pub fn from_env() -> Self {
        Self {
            no_receipts: env_truthy("JCODE_NO_RECEIPTS") || env_truthy("OMNIS_NO_RECEIPTS"),
            full_argv: env_truthy("JCODE_RECEIPT_FULL_ARGV")
                || env_truthy("OMNIS_RECEIPT_FULL_ARGV"),
            receipt_reads: env_truthy("JCODE_RECEIPT_READS") || env_truthy("OMNIS_RECEIPT_READS"),
        }
    }

    /// Install process-wide policy (call once from CLI startup).
    pub fn install(self) {
        NO_RECEIPTS.store(self.no_receipts, Ordering::SeqCst);
        FULL_ARGV.store(self.full_argv, Ordering::SeqCst);
        RECEIPT_READS.store(self.receipt_reads, Ordering::SeqCst);
        if self.no_receipts {
            SESSION_NO_RECEIPTS_NOTED.store(true, Ordering::SeqCst);
        }
    }
}

fn env_truthy(key: &str) -> bool {
    std::env::var(key)
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

pub fn action_receipts_enabled() -> bool {
    if NO_RECEIPTS.load(Ordering::SeqCst) {
        return false;
    }
    if env_truthy("JCODE_NO_RECEIPTS") || env_truthy("OMNIS_NO_RECEIPTS") {
        return false;
    }
    true
}

pub fn receipt_full_argv_enabled() -> bool {
    FULL_ARGV.load(Ordering::SeqCst)
        || env_truthy("JCODE_RECEIPT_FULL_ARGV")
        || env_truthy("OMNIS_RECEIPT_FULL_ARGV")
}

pub fn receipt_reads_enabled() -> bool {
    RECEIPT_READS.load(Ordering::SeqCst)
        || env_truthy("JCODE_RECEIPT_READS")
        || env_truthy("OMNIS_RECEIPT_READS")
}

/// For session summary: was `--no-receipts` (or env) used this process?
pub fn session_receipts_disabled_note() -> Option<&'static str> {
    if !action_receipts_enabled() || SESSION_NO_RECEIPTS_NOTED.load(Ordering::SeqCst) {
        Some(
            "RECEIPTS_DISABLED: session ran with --no-receipts / JCODE_NO_RECEIPTS (explicit opt-out; not silently unreceipted)",
        )
    } else {
        None
    }
}
