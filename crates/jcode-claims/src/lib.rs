//! # Claim Ledger (OMNIS CODE)
//!
//! An agent's claims about a codebase are either **grounded** in deterministic
//! verification, or **visibly refused**. Never merely asserted.
//!
//! Pipeline:
//! 1. EXTRACT (S2 — LLM allowed only there; not in this crate's S1 path)
//! 2. TYPE — does a verifier exist? no → short-circuit, **no verification field**
//! 3. VERIFY — `jcode-verifiers` only (no model)
//! 4. RECEIPT — hash-chained claim ledger
//!
//! Frozen verdict vocabulary — the agent cannot author a new one.

#![forbid(unsafe_code)]

mod ledger;
mod pipeline;
mod types;

pub use ledger::{ClaimLedger, ClaimReceipt};
pub use pipeline::{
    ClaimEvaluateOptions, ClaimOutcome, ClaimsBatchResult, evaluate_claim, evaluate_claims,
};
pub use types::{ClaimInput, ClaimKind, ClaimVerdict, TypedClaim, VERDICT_VOCABULARY};

/// Pocket thesis.
pub const THESIS: &str = "An agent's claims about your codebase are either grounded in the codebase, or visibly refused. Never asserted.";
