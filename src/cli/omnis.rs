use anyhow::{Result, bail};
use jcode_omnis::client::CheckpointClient;
use jcode_omnis::model::{
    AnchorRequest, PROTOCOL as CHECKPOINT_PROTOCOL, ReceiptLinkWitness, SignedCheckpoint,
};
use jcode_omnis::protocol::Success;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;

use super::args::{OmnisClaimCeilingArg, OmnisCommand};
use crate::omnis::{self, ClaimCeiling, Receipt};

const SEGMENT_REQUEST_PREFIX: &str = "anchor-segment:";

fn print_value<T: Serialize>(value: &T, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(value)?);
    } else {
        println!("{}", serde_json::to_string(value)?);
    }
    Ok(())
}

fn run_status(ledger: Option<&str>, json: bool) -> Result<()> {
    let path = omnis::ledger_path(ledger);
    let result = serde_json::json!({ "ledger": path, "verification": omnis::verify(&path)? });
    print_value(&result, json)
}

fn run_verify(ledger: Option<&str>, json: bool) -> Result<()> {
    let path = omnis::ledger_path(ledger);
    let verification = omnis::verify(&path)?;
    if !verification.valid() {
        bail!("OMNIS_RECEIPT_CHAIN_INVALID: {:?}", verification.errors())
    }
    print_value(
        &serde_json::json!({ "ledger": path, "verification": verification }),
        json,
    )
}

fn run_record(
    event_id: &str,
    kind: &str,
    subject: &str,
    evidence_sha256: &str,
    claim_ceiling: ClaimCeiling,
    ledger: Option<&str>,
    json: bool,
) -> Result<()> {
    let path = omnis::ledger_path(ledger);
    let outcome = omnis::append_idempotent(
        &path,
        event_id,
        kind,
        subject,
        evidence_sha256,
        claim_ceiling,
    )?;
    print_value(
        &serde_json::json!({ "ledger": path, "outcome": outcome }),
        json,
    )
}

fn run_reconcile_safety(json: bool) -> Result<()> {
    let before = crate::safety::receipt_outbox_status()?;
    let flushed = crate::safety::flush_receipt_outbox()?;
    let after = crate::safety::receipt_outbox_status()?;
    print_value(
        &serde_json::json!({
            "flushed": flushed,
            "before": before,
            "after": after,
            "claim_ceiling": "local-record",
            "authority": "none",
            "execution": "not-authorized"
        }),
        json,
    )
}

fn verify_local_checkpoint(checkpoint: &SignedCheckpoint, receipts: &[Receipt]) -> Result<()> {
    let anchored_index = usize::try_from(checkpoint.record.observed_receipt_sequence)
        .map_err(|_| anyhow::anyhow!("OMNIS_CHECKPOINT_INVALID_ANCHORED_SEQUENCE"))?
        .checked_sub(1)
        .ok_or_else(|| anyhow::anyhow!("OMNIS_CHECKPOINT_INVALID_ANCHORED_SEQUENCE"))?;
    let anchored = receipts
        .get(anchored_index)
        .ok_or_else(|| anyhow::anyhow!("OMNIS_CHECKPOINT_LOCAL_ROLLBACK_DETECTED"))?;
    if anchored.sequence() != checkpoint.record.observed_receipt_sequence
        || anchored.receipt_hash() != checkpoint.record.observed_receipt_head
    {
        bail!("OMNIS_CHECKPOINT_LOCAL_CHAIN_DIVERGED")
    }
    Ok(())
}

fn verify_checkpoint_is_local_head(
    checkpoint: &SignedCheckpoint,
    receipts: &[Receipt],
    mismatch_code: &str,
) -> Result<()> {
    verify_local_checkpoint(checkpoint, receipts)?;
    let current = receipts
        .last()
        .ok_or_else(|| anyhow::anyhow!("OMNIS_CHECKPOINT_EMPTY_RECEIPT_CHAIN"))?;
    if current.sequence() != checkpoint.record.observed_receipt_sequence
        || current.receipt_hash() != checkpoint.record.observed_receipt_head
    {
        bail!("{mismatch_code}")
    }
    Ok(())
}

fn build_anchor_request(
    request_id: &str,
    ledger_id: &str,
    receipt_ledger_path: &Path,
    receipts: &[Receipt],
    latest: Option<&SignedCheckpoint>,
) -> Result<AnchorRequest> {
    let receipt_ledger_path = receipt_ledger_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("OMNIS_CHECKPOINT_RECEIPT_LEDGER_PATH_NOT_UTF8"))?;
    let observed = receipts
        .last()
        .ok_or_else(|| anyhow::anyhow!("OMNIS_CHECKPOINT_EMPTY_RECEIPT_CHAIN"))?;
    let start = match latest {
        Some(checkpoint) => {
            verify_local_checkpoint(checkpoint, receipts)?;
            usize::try_from(checkpoint.record.observed_receipt_sequence)
                .map_err(|_| anyhow::anyhow!("OMNIS_CHECKPOINT_SEQUENCE_OVERFLOW"))?
        }
        None => 0,
    };
    if start >= receipts.len() {
        bail!("OMNIS_CHECKPOINT_RECEIPT_NO_ADVANCE")
    }
    let continuity = receipts[start..]
        .iter()
        .map(|receipt| ReceiptLinkWitness {
            sequence: receipt.sequence(),
            parent_hash: receipt.parent_hash().map(str::to_string),
            receipt_hash: receipt.receipt_hash().to_string(),
        })
        .collect();
    let request = AnchorRequest {
        protocol: CHECKPOINT_PROTOCOL.to_string(),
        request_id: request_id.to_string(),
        ledger_id: ledger_id.to_string(),
        receipt_ledger_path: receipt_ledger_path.to_string(),
        prior_checkpoint_hash: latest.map(|checkpoint| checkpoint.record_hash.clone()),
        observed_receipt_sequence: observed.sequence(),
        observed_receipt_head: observed.receipt_hash().to_string(),
        continuity,
    };
    jcode_omnis::model::validate_anchor_request(&request)?;
    Ok(request)
}

fn latest_from_status(result: Success) -> Result<Option<SignedCheckpoint>> {
    match result {
        Success::Status { latest, .. } => Ok(latest),
        Success::Anchor { .. } => bail!("OMNIS_CHECKPOINT_STATUS_OPERATION_MISMATCH"),
    }
}

fn segment_request_id(request_id: &str, observed_sequence: u64) -> String {
    let mut digest = Sha256::new();
    digest.update(b"jourdanlabs.omnis-checkpoint.cli-segment.v1");
    digest.update((request_id.len() as u64).to_be_bytes());
    digest.update(request_id.as_bytes());
    format!(
        "{SEGMENT_REQUEST_PREFIX}{observed_sequence:016x}:{}",
        hex::encode(digest.finalize())
    )
}

fn run_anchor(request_id: &str, json: bool) -> Result<()> {
    jcode_omnis::model::validate_request_id(request_id)?;
    if request_id.starts_with(SEGMENT_REQUEST_PREFIX) {
        bail!("OMNIS_CHECKPOINT_RESERVED_SEGMENT_REQUEST_ID")
    }
    let client = CheckpointClient::production()?;
    let ledger_id = client.allowed_ledger_id()?.to_string();
    let ledger = client.receipt_ledger_path()?.to_path_buf();
    client.validate_receipt_ledger_boundary()?;
    let before = omnis::verified_receipts(&ledger)?;
    if let Some(checkpoint) = client.lookup(request_id)? {
        let latest = latest_from_status(client.status("status:anchor-replay")?)?
            .ok_or_else(|| anyhow::anyhow!("OMNIS_CHECKPOINT_LOOKUP_WITHOUT_CHAIN"))?;
        client.validate_receipt_ledger_boundary()?;
        let after = omnis::verified_receipts(&ledger)?;
        verify_local_checkpoint(&latest, &after)?;
        verify_checkpoint_is_local_head(
            &checkpoint,
            &after,
            "OMNIS_CHECKPOINT_REQUEST_ID_REUSED_FOR_DIFFERENT_LOCAL_HEAD",
        )?;
        return print_value(
            &serde_json::json!({
                "ledger": ledger,
                "ledger_id": ledger_id,
                "disposition": jcode_omnis::model::AppendDisposition::Existing,
                "checkpoint": checkpoint,
                "segments_processed": 0,
                "claim_ceiling": "separately-retained-local-head-assertion",
                "authority": "checkpoint-only",
                "execution": "not-authorized"
            }),
            json,
        );
    }
    let mut latest = latest_from_status(client.status("status:anchor")?)?;
    let mut segments_processed = 0_u64;
    let (disposition, checkpoint) = loop {
        if let Some(checkpoint) = latest.as_ref() {
            verify_local_checkpoint(checkpoint, &before)?;
        }
        let start = match latest.as_ref() {
            Some(checkpoint) => usize::try_from(checkpoint.record.observed_receipt_sequence)
                .map_err(|_| anyhow::anyhow!("OMNIS_CHECKPOINT_SEQUENCE_OVERFLOW"))?,
            None => 0,
        };
        if start >= before.len() {
            bail!("OMNIS_CHECKPOINT_RECEIPT_NO_ADVANCE")
        }
        let end = start
            .saturating_add(jcode_omnis::model::MAX_CONTINUITY_LINKS)
            .min(before.len());
        let segment_id = if end == before.len() {
            request_id.to_string()
        } else {
            segment_request_id(request_id, before[end - 1].sequence())
        };
        let request = build_anchor_request(
            &segment_id,
            &ledger_id,
            &ledger,
            &before[..end],
            latest.as_ref(),
        )?;
        let outcome = match client.anchor(request)? {
            Success::Anchor {
                disposition,
                checkpoint,
            } => (disposition, checkpoint),
            Success::Status { .. } => bail!("OMNIS_CHECKPOINT_ANCHOR_OPERATION_MISMATCH"),
        };
        segments_processed = segments_processed
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("OMNIS_CHECKPOINT_SEGMENT_COUNT_OVERFLOW"))?;
        if end == before.len() {
            break outcome;
        }
        latest = Some(outcome.1);
    };

    // Re-read after the authority replies. The signed snapshot must equal the
    // current valid local head; a raced suffix or rewrite never earns success.
    client.validate_receipt_ledger_boundary()?;
    let after = omnis::verified_receipts(&ledger)?;
    verify_checkpoint_is_local_head(
        &checkpoint,
        &after,
        "OMNIS_CHECKPOINT_LOCAL_CHAIN_ADVANCED_DURING_ANCHOR",
    )?;
    print_value(
        &serde_json::json!({
            "ledger": ledger,
            "ledger_id": ledger_id,
            "disposition": disposition,
            "checkpoint": checkpoint,
            "segments_processed": segments_processed,
            "claim_ceiling": "separately-retained-local-head-assertion",
            "authority": "checkpoint-only",
            "execution": "not-authorized"
        }),
        json,
    )
}

fn run_verify_anchored(json: bool) -> Result<()> {
    let client = CheckpointClient::production()?;
    let ledger = client.receipt_ledger_path()?.to_path_buf();
    let checkpoint = latest_from_status(client.status("status:verify-anchored")?)?
        .ok_or_else(|| anyhow::anyhow!("OMNIS_CHECKPOINT_NOT_YET_ANCHORED"))?;
    client.validate_receipt_ledger_boundary()?;
    let receipts = omnis::verified_receipts(&ledger)?;
    verify_local_checkpoint(&checkpoint, &receipts)?;
    print_value(
        &serde_json::json!({
            "ledger": ledger,
            "valid": true,
            "checkpoint": checkpoint,
            "local_receipt_entries": receipts.len(),
            "claim_ceiling": "separately-retained-local-head-assertion",
            "authority": "checkpoint-only",
            "execution": "not-authorized"
        }),
        json,
    )
}

pub(crate) fn run_command(action: OmnisCommand) -> Result<()> {
    match action {
        OmnisCommand::Status { ledger, json } => run_status(ledger.as_deref(), json),
        OmnisCommand::Verify { ledger, json } => run_verify(ledger.as_deref(), json),
        OmnisCommand::ReconcileSafety { json } => run_reconcile_safety(json),
        OmnisCommand::Anchor { request_id, json } => run_anchor(&request_id, json),
        OmnisCommand::VerifyAnchored { json } => run_verify_anchored(json),
        OmnisCommand::Record {
            event_id,
            kind,
            subject,
            evidence_sha256,
            claim_ceiling,
            ledger,
            json,
        } => {
            let ceiling = match claim_ceiling {
                OmnisClaimCeilingArg::LocalRecord => ClaimCeiling::LocalRecord,
                OmnisClaimCeilingArg::LocalVerification => ClaimCeiling::LocalVerification,
            };
            run_record(
                &event_id,
                &kind,
                &subject,
                &evidence_sha256,
                ceiling,
                ledger.as_deref(),
                json,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn private_tempdir() -> TempDir {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        directory
    }

    fn append_receipt(
        directory: &TempDir,
        event_id: &str,
        evidence: char,
    ) -> crate::omnis::Receipt {
        let ledger = directory.path().join("receipts.jsonl");
        crate::omnis::append_idempotent(
            &ledger,
            event_id,
            "safety.decision",
            event_id,
            &evidence.to_string().repeat(64),
            ClaimCeiling::LocalRecord,
        )
        .unwrap()
        .receipt()
        .clone()
    }

    fn signed_checkpoint(request: &AnchorRequest) -> SignedCheckpoint {
        use jcode_omnis::model::CheckpointRecord;

        SignedCheckpoint {
            record: CheckpointRecord {
                protocol: CHECKPOINT_PROTOCOL.to_string(),
                authority_id: jcode_omnis::daemon::AUTHORITY_ID.to_string(),
                checkpoint_sequence: 1,
                parent_checkpoint_hash: None,
                request_id: request.request_id.clone(),
                request_digest: format!("sha256:{}", "c".repeat(64)),
                peer_uid: 501,
                ledger_id: request.ledger_id.clone(),
                receipt_ledger_path: request.receipt_ledger_path.clone(),
                observed_receipt_sequence: request.observed_receipt_sequence,
                observed_receipt_head: request.observed_receipt_head.clone(),
                issued_at_unix_ms: 1,
                signing_key_id: format!("sha256:{}", "d".repeat(64)),
            },
            record_hash: format!("sha256:{}", "e".repeat(64)),
            signature_ed25519: "00".repeat(64),
        }
    }

    #[test]
    fn anchor_request_covers_genesis_and_only_the_unanchored_extension() {
        let directory = private_tempdir();
        let first = append_receipt(&directory, "event:one", 'a');
        let second = append_receipt(&directory, "event:two", 'b');
        let receipts = vec![first, second];
        let ledger = std::path::PathBuf::from("/Users/test/.jcode/state/omnis-key/receipts.jsonl");

        let genesis =
            build_anchor_request("anchor:one", "ledger:test", &ledger, &receipts, None).unwrap();
        assert_eq!(genesis.continuity.len(), 2);
        assert_eq!(
            genesis.receipt_ledger_path,
            ledger
                .to_str()
                .expect("temporary ledger path must be UTF-8")
        );
        assert_eq!(genesis.continuity[0].sequence, 1);
        assert!(genesis.continuity[0].parent_hash.is_none());

        let first_only =
            build_anchor_request("anchor:first", "ledger:test", &ledger, &receipts[..1], None)
                .unwrap();
        let checkpoint = signed_checkpoint(&first_only);
        let extension = build_anchor_request(
            "anchor:two",
            "ledger:test",
            &ledger,
            &receipts,
            Some(&checkpoint),
        )
        .unwrap();
        assert_eq!(extension.continuity.len(), 1);
        assert_eq!(extension.continuity[0].sequence, 2);
        assert_eq!(
            extension.continuity[0].parent_hash.as_deref(),
            Some(receipts[0].receipt_hash())
        );
    }

    #[test]
    fn anchor_request_refuses_local_rollback_divergence_and_no_advance() {
        let directory = private_tempdir();
        let first = append_receipt(&directory, "event:one", 'a');
        let receipts = vec![first];
        let ledger = std::path::PathBuf::from("/Users/test/.jcode/state/omnis-key/receipts.jsonl");
        let request =
            build_anchor_request("anchor:first", "ledger:test", &ledger, &receipts, None).unwrap();
        let checkpoint = signed_checkpoint(&request);
        verify_checkpoint_is_local_head(
            &checkpoint,
            &receipts,
            "OMNIS_CHECKPOINT_LOCAL_CHAIN_ADVANCED_DURING_ANCHOR",
        )
        .unwrap();

        assert!(
            build_anchor_request(
                "anchor:no-advance",
                "ledger:test",
                &ledger,
                &receipts,
                Some(&checkpoint)
            )
            .unwrap_err()
            .to_string()
            .contains("NO_ADVANCE")
        );

        let empty = Vec::new();
        assert!(
            verify_local_checkpoint(&checkpoint, &empty)
                .unwrap_err()
                .to_string()
                .contains("ROLLBACK")
        );

        let second = append_receipt(&directory, "event:two", 'b');
        let extended = vec![receipts[0].clone(), second];
        assert!(
            verify_checkpoint_is_local_head(
                &checkpoint,
                &extended,
                "OMNIS_CHECKPOINT_REQUEST_ID_REUSED_FOR_DIFFERENT_LOCAL_HEAD",
            )
            .unwrap_err()
            .to_string()
            .contains("REQUEST_ID_REUSED_FOR_DIFFERENT_LOCAL_HEAD")
        );

        let mut drifted = checkpoint;
        drifted.record.observed_receipt_head = format!("sha256:{}", "f".repeat(64));
        assert!(
            verify_local_checkpoint(&drifted, &receipts)
                .unwrap_err()
                .to_string()
                .contains("DIVERGED")
        );
    }

    #[test]
    fn intermediate_segment_ids_are_stable_bounded_and_request_specific() {
        let segment_end = jcode_omnis::model::MAX_CONTINUITY_LINKS as u64;
        let first = segment_request_id("anchor:release/1", segment_end);
        assert_eq!(first, segment_request_id("anchor:release/1", segment_end));
        assert_ne!(first, segment_request_id("anchor:release/2", segment_end));
        assert_ne!(
            first,
            segment_request_id("anchor:release/1", segment_end * 2)
        );
        assert!(first.len() <= jcode_omnis::model::MAX_REQUEST_ID_BYTES);
        jcode_omnis::model::validate_request_id(&first).unwrap();
    }

    #[test]
    fn malformed_or_reserved_final_id_refuses_before_authority_access() {
        assert!(
            run_anchor("contains a space", false)
                .unwrap_err()
                .to_string()
                .contains("INVALID_REQUEST_ID")
        );
        assert!(
            run_anchor("anchor-segment:caller-controlled", false)
                .unwrap_err()
                .to_string()
                .contains("RESERVED_SEGMENT_REQUEST_ID")
        );
    }
}
