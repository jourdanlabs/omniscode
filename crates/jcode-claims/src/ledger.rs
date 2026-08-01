//! Hash-chained claim receipt log (Claim Ledger stage 4 substrate).
//! Extends the OMNIS receipt *discipline* without forking jcode-omnis authority.

use crate::types::ClaimVerdict;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClaimReceipt {
    pub seq: u64,
    pub ts: String,
    pub claim_id: String,
    pub verdict: ClaimVerdict,
    pub kind_name: String,
    /// Present only when stage 3 ran. Short-circuit claims omit this entirely.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<serde_json::Value>,
    pub prev_hash: String,
    pub entry_hash: String,
}

pub struct ClaimLedger {
    path: PathBuf,
}

impl ClaimLedger {
    pub fn open(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        if !path.exists() {
            fs::File::create(&path)?;
        }
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn entries(&self) -> std::io::Result<Vec<ClaimReceipt>> {
        let file = fs::File::open(&self.path)?;
        let reader = BufReader::new(file);
        let mut out = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let entry: ClaimReceipt = serde_json::from_str(&line)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            out.push(entry);
        }
        Ok(out)
    }

    pub fn head_hash(&self) -> std::io::Result<String> {
        let entries = self.entries()?;
        Ok(entries
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_else(|| genesis_hash()))
    }

    pub fn append(
        &self,
        claim_id: &str,
        verdict: ClaimVerdict,
        kind_name: &str,
        verification: Option<serde_json::Value>,
    ) -> std::io::Result<ClaimReceipt> {
        let entries = self.entries()?;
        let seq = entries.last().map(|e| e.seq + 1).unwrap_or(1);
        let prev_hash = entries
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_else(genesis_hash);
        let ts = chrono::Utc::now().to_rfc3339();
        let mut receipt = ClaimReceipt {
            seq,
            ts: ts.clone(),
            claim_id: claim_id.to_string(),
            verdict,
            kind_name: kind_name.to_string(),
            verification,
            prev_hash: prev_hash.clone(),
            entry_hash: String::new(),
        };
        receipt.entry_hash = hash_receipt(&receipt, &prev_hash);
        let mut file = OpenOptions::new().append(true).open(&self.path)?;
        writeln!(file, "{}", serde_json::to_string(&receipt).unwrap())?;
        Ok(receipt)
    }

    pub fn verify_chain(&self) -> std::io::Result<bool> {
        let entries = self.entries()?;
        let mut prev = genesis_hash();
        for e in entries {
            if e.prev_hash != prev {
                return Ok(false);
            }
            let expected = hash_receipt(&e, &prev);
            if e.entry_hash != expected {
                return Ok(false);
            }
            prev = e.entry_hash;
        }
        Ok(true)
    }
}

fn genesis_hash() -> String {
    "0".repeat(64)
}

fn hash_receipt(r: &ClaimReceipt, prev_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(r.seq.to_string().as_bytes());
    hasher.update(r.ts.as_bytes());
    hasher.update(r.claim_id.as_bytes());
    hasher.update(r.verdict.as_str().as_bytes());
    hasher.update(r.kind_name.as_bytes());
    if let Some(v) = &r.verification {
        hasher.update(v.to_string().as_bytes());
    } else {
        hasher.update(b"<no-verification>");
    }
    hasher.update(prev_hash.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn chain_appends_and_verifies() {
        let dir = TempDir::new().unwrap();
        let ledger = ClaimLedger::open(dir.path().join("claims.jsonl")).unwrap();
        let a = ledger
            .append("c1", ClaimVerdict::Certified, "files_changed", None)
            .unwrap();
        let b = ledger
            .append(
                "c2",
                ClaimVerdict::RefusedNoVerifier,
                "performance_faster",
                None,
            )
            .unwrap();
        assert_eq!(a.seq, 1);
        assert_eq!(b.seq, 2);
        assert_eq!(b.prev_hash, a.entry_hash);
        assert!(ledger.verify_chain().unwrap());
    }
}
