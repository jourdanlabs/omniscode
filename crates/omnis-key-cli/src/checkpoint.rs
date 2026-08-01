use anyhow::{Context, Result, bail};
use jcode_base::omnis::{self, Receipt};
use jcode_omnis::client::CheckpointClient;
use jcode_omnis::model::{
    AnchorRequest, AppendDisposition, PROTOCOL, ReceiptLinkWitness, SignedCheckpoint,
};
use jcode_omnis::protocol::Success;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::Path;

use crate::output::{self, CheckpointAnchorData, CheckpointVerifyData};

const SEGMENT_REQUEST_PREFIX: &str = "anchor-segment:";

pub(crate) fn anchor(
    request_id: &str,
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    if jcode_omnis::model::validate_request_id(request_id).is_err()
        || request_id.starts_with(SEGMENT_REQUEST_PREFIX)
    {
        return output::emit::<()>(
            json,
            "checkpoint.anchor",
            false,
            "CHECKPOINT_REFUSED",
            None,
            3,
            (stdout, stderr),
        );
    }
    let client = match CheckpointClient::production() {
        Ok(client) => client,
        Err(error) => {
            return emit_checkpoint_error("checkpoint.anchor", &error, json, stdout, stderr);
        }
    };
    match anchor_with_client(&client, request_id) {
        Ok(data) => {
            let code = if data.disposition == "APPENDED" {
                "CHECKPOINT_ANCHORED"
            } else {
                "CHECKPOINT_EXISTING"
            };
            output::emit(
                json,
                "checkpoint.anchor",
                true,
                code,
                Some(&data),
                0,
                (stdout, stderr),
            )
        }
        Err(error) => emit_checkpoint_error("checkpoint.anchor", &error, json, stdout, stderr),
    }
}

pub(crate) fn verify_anchored(json: bool, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let client = match CheckpointClient::production() {
        Ok(client) => client,
        Err(error) => {
            return emit_checkpoint_error(
                "checkpoint.verify-anchored",
                &error,
                json,
                stdout,
                stderr,
            );
        }
    };
    match verify_with_client(&client) {
        Ok(data) => output::emit(
            json,
            "checkpoint.verify-anchored",
            true,
            "CHECKPOINT_VERIFIED",
            Some(&data),
            0,
            (stdout, stderr),
        ),
        Err(error) => {
            emit_checkpoint_error("checkpoint.verify-anchored", &error, json, stdout, stderr)
        }
    }
}

fn anchor_with_client(client: &CheckpointClient, request_id: &str) -> Result<CheckpointAnchorData> {
    let ledger_id = client.allowed_ledger_id()?.to_string();
    let ledger = client.receipt_ledger_path()?.to_path_buf();
    client.validate_receipt_ledger_boundary()?;
    let before = omnis::verified_receipts(&ledger)?;
    if let Some(checkpoint) = client.lookup(request_id)? {
        let latest = latest_from_status(client.status("status:anchor-replay")?)?
            .context("OMNIS_CHECKPOINT_LOOKUP_WITHOUT_CHAIN")?;
        client.validate_receipt_ledger_boundary()?;
        let after = omnis::verified_receipts(&ledger)?;
        verify_local_checkpoint(&latest, &after)?;
        verify_checkpoint_is_local_head(
            &checkpoint,
            &after,
            "OMNIS_CHECKPOINT_REQUEST_ID_REUSED_FOR_DIFFERENT_LOCAL_HEAD",
        )?;
        return anchor_data(AppendDisposition::Existing, &checkpoint);
    }

    let mut latest = latest_from_status(client.status("status:anchor")?)?;
    let (disposition, checkpoint) = loop {
        if let Some(checkpoint) = latest.as_ref() {
            verify_local_checkpoint(checkpoint, &before)?;
        }
        let start = match latest.as_ref() {
            Some(checkpoint) => usize::try_from(checkpoint.record.observed_receipt_sequence)
                .context("OMNIS_CHECKPOINT_SEQUENCE_OVERFLOW")?,
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
        if end == before.len() {
            break outcome;
        }
        latest = Some(outcome.1);
    };

    client.validate_receipt_ledger_boundary()?;
    let after = omnis::verified_receipts(&ledger)?;
    verify_checkpoint_is_local_head(
        &checkpoint,
        &after,
        "OMNIS_CHECKPOINT_LOCAL_CHAIN_ADVANCED_DURING_ANCHOR",
    )?;
    anchor_data(disposition, &checkpoint)
}

fn verify_with_client(client: &CheckpointClient) -> Result<CheckpointVerifyData> {
    let ledger = client.receipt_ledger_path()?.to_path_buf();
    let checkpoint = latest_from_status(client.status("status:verify-anchored")?)?
        .context("OMNIS_CHECKPOINT_NOT_YET_ANCHORED")?;
    client.validate_receipt_ledger_boundary()?;
    let receipts = omnis::verified_receipts(&ledger)?;
    verify_local_checkpoint(&checkpoint, &receipts)?;
    Ok(CheckpointVerifyData {
        checkpoint_sequence: checkpoint.record.checkpoint_sequence,
        checkpoint_sha256: output::bare_sha256(&checkpoint.record_hash)?,
        observed_receipt_sequence: checkpoint.record.observed_receipt_sequence,
        observed_receipt_head_sha256: output::bare_sha256(
            &checkpoint.record.observed_receipt_head,
        )?,
    })
}

fn anchor_data(
    disposition: AppendDisposition,
    checkpoint: &SignedCheckpoint,
) -> Result<CheckpointAnchorData> {
    Ok(CheckpointAnchorData {
        disposition: match disposition {
            AppendDisposition::Appended => "APPENDED",
            AppendDisposition::Existing => "EXISTING",
        },
        checkpoint_sequence: checkpoint.record.checkpoint_sequence,
        checkpoint_sha256: output::bare_sha256(&checkpoint.record_hash)?,
        observed_receipt_sequence: checkpoint.record.observed_receipt_sequence,
        observed_receipt_head_sha256: output::bare_sha256(
            &checkpoint.record.observed_receipt_head,
        )?,
    })
}

fn verify_local_checkpoint(checkpoint: &SignedCheckpoint, receipts: &[Receipt]) -> Result<()> {
    let index = usize::try_from(checkpoint.record.observed_receipt_sequence)
        .context("OMNIS_CHECKPOINT_INVALID_ANCHORED_SEQUENCE")?
        .checked_sub(1)
        .context("OMNIS_CHECKPOINT_INVALID_ANCHORED_SEQUENCE")?;
    let anchored = receipts
        .get(index)
        .context("OMNIS_CHECKPOINT_LOCAL_ROLLBACK_DETECTED")?;
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
        .context("OMNIS_CHECKPOINT_EMPTY_RECEIPT_CHAIN")?;
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
        .context("OMNIS_CHECKPOINT_RECEIPT_LEDGER_PATH_NOT_UTF8")?;
    let observed = receipts
        .last()
        .context("OMNIS_CHECKPOINT_EMPTY_RECEIPT_CHAIN")?;
    let start = match latest {
        Some(checkpoint) => {
            verify_local_checkpoint(checkpoint, receipts)?;
            usize::try_from(checkpoint.record.observed_receipt_sequence)
                .context("OMNIS_CHECKPOINT_SEQUENCE_OVERFLOW")?
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
        protocol: PROTOCOL.to_string(),
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
        "{SEGMENT_REQUEST_PREFIX}{observed_sequence:016x}:{:x}",
        digest.finalize()
    )
}

pub(crate) fn emit_checkpoint_error(
    command: &str,
    error: &anyhow::Error,
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let text = format!("{error:#}");
    let (code, exit) = if authority_is_unavailable(&text) {
        ("CHECKPOINT_AUTHORITY_UNAVAILABLE", 4)
    } else if text.contains("SIGNATURE")
        || text.contains("SIGNING_KEY")
        || text.contains("PUBLIC_KEY")
    {
        ("CHECKPOINT_SIGNATURE_INVALID", 3)
    } else if text.contains("LOCAL_ROLLBACK") {
        ("CHECKPOINT_LOCAL_ROLLBACK_DETECTED", 3)
    } else if command == "checkpoint.verify-anchored" {
        ("CHECKPOINT_CHAIN_DIVERGED", 3)
    } else {
        ("CHECKPOINT_REFUSED", 3)
    };
    output::emit::<()>(json, command, false, code, None, exit, (stdout, stderr))
}

fn authority_is_unavailable(text: &str) -> bool {
    let invalid_activation = [
        "INVALID_JSON",
        "MISMATCH",
        "DRIFT",
        "SYMLINK",
        "IDENTITY_OR_MODE",
        "EXTENDED_ACL",
        "SIZE_REFUSED",
        "READ_DRIFT",
    ]
    .iter()
    .any(|marker| text.contains(marker));
    !invalid_activation
        && [
            "UNSUPPORTED_PLATFORM",
            "No such file or directory",
            "not found",
            "Connection refused",
            "connect checkpoint socket",
            "inspect checkpoint socket",
            "TRANSPORT_UNSUPPORTED",
        ]
        .iter()
        .any(|marker| text.contains(marker))
}
