//! Experimental source kernel for OMNIS checkpoint primitives.
//!
//! This crate is source-only and separately activated; the public foundation
//! does not provision a service account, install keys, activate a daemon, or
//! make checkpoint authority available.

pub mod client;
pub mod crypto;
pub mod daemon;
pub mod model;
pub mod protocol;
mod store;

pub use model::{
    AnchorRequest, AppendDisposition, CheckpointRecord, ReceiptLinkWitness, SignedCheckpoint,
};
