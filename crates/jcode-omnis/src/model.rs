use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

pub const PROTOCOL: &str = "jourdanlabs.omnis-checkpoint.v1";
pub const DEFAULT_LEDGER_ID: &str = "jourdanlabs.jcode.omnis.default-receipts.v1";
pub const MAX_REQUEST_ID_BYTES: usize = 256;
pub const MAX_LEDGER_ID_BYTES: usize = 256;
pub const MAX_LEDGER_PATH_BYTES: usize = 4096;
/// Chosen so a worst-case request remains below the protocol's 1 MiB frame.
pub const MAX_CONTINUITY_LINKS: usize = 4_900;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptLinkWitness {
    pub sequence: u64,
    pub parent_hash: Option<String>,
    pub receipt_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorRequest {
    pub protocol: String,
    pub request_id: String,
    pub ledger_id: String,
    pub receipt_ledger_path: String,
    pub prior_checkpoint_hash: Option<String>,
    pub observed_receipt_sequence: u64,
    pub observed_receipt_head: String,
    pub continuity: Vec<ReceiptLinkWitness>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointRecord {
    pub protocol: String,
    pub authority_id: String,
    pub checkpoint_sequence: u64,
    pub parent_checkpoint_hash: Option<String>,
    pub request_id: String,
    pub request_digest: String,
    pub peer_uid: u32,
    pub ledger_id: String,
    pub receipt_ledger_path: String,
    pub observed_receipt_sequence: u64,
    pub observed_receipt_head: String,
    pub issued_at_unix_ms: u64,
    pub signing_key_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCheckpoint {
    pub record: CheckpointRecord,
    pub record_hash: String,
    pub signature_ed25519: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppendDisposition {
    Appended,
    Existing,
}

pub fn validate_protocol(protocol: &str) -> Result<()> {
    if protocol != PROTOCOL {
        bail!("OMNIS_CHECKPOINT_PROTOCOL_MISMATCH")
    }
    Ok(())
}

pub fn validate_request_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_REQUEST_ID_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'/')
        })
    {
        bail!("OMNIS_CHECKPOINT_INVALID_REQUEST_ID")
    }
    Ok(())
}

pub fn validate_ledger_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_LEDGER_ID_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'/')
        })
    {
        bail!("OMNIS_CHECKPOINT_INVALID_LEDGER_ID")
    }
    Ok(())
}

pub fn validate_receipt_ledger_path(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_LEDGER_PATH_BYTES
        || value.chars().any(char::is_control)
    {
        bail!("OMNIS_CHECKPOINT_INVALID_RECEIPT_LEDGER_PATH")
    }
    let mut components = value.split('/');
    if components.next() != Some("")
        || components.clone().next().is_none()
        || components.any(|component| component.is_empty() || component == "." || component == "..")
    {
        bail!("OMNIS_CHECKPOINT_INVALID_RECEIPT_LEDGER_PATH")
    }
    Ok(())
}

pub fn validate_digest(value: &str, code: &str) -> Result<()> {
    let Some(raw) = value.strip_prefix("sha256:") else {
        bail!("{code}: digest prefix missing")
    };
    if raw.len() != 64
        || !raw.bytes().all(|byte| byte.is_ascii_hexdigit())
        || raw.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        bail!("{code}: digest must be 64 lowercase hexadecimal characters")
    }
    Ok(())
}

pub fn validate_anchor_request(request: &AnchorRequest) -> Result<()> {
    validate_protocol(&request.protocol)?;
    validate_request_id(&request.request_id)?;
    validate_ledger_id(&request.ledger_id)?;
    validate_receipt_ledger_path(&request.receipt_ledger_path)?;
    if let Some(parent) = request.prior_checkpoint_hash.as_deref() {
        validate_digest(parent, "OMNIS_CHECKPOINT_INVALID_PRIOR_HASH")?;
    }
    if request.observed_receipt_sequence == 0 {
        bail!("OMNIS_CHECKPOINT_EMPTY_RECEIPT_CHAIN")
    }
    validate_digest(
        &request.observed_receipt_head,
        "OMNIS_CHECKPOINT_INVALID_OBSERVED_HEAD",
    )?;
    if request.continuity.is_empty() || request.continuity.len() > MAX_CONTINUITY_LINKS {
        bail!("OMNIS_CHECKPOINT_INVALID_CONTINUITY_LENGTH")
    }
    for link in &request.continuity {
        if link.sequence == 0 {
            bail!("OMNIS_CHECKPOINT_INVALID_RECEIPT_SEQUENCE")
        }
        if let Some(parent) = link.parent_hash.as_deref() {
            validate_digest(parent, "OMNIS_CHECKPOINT_INVALID_RECEIPT_PARENT")?;
        }
        validate_digest(&link.receipt_hash, "OMNIS_CHECKPOINT_INVALID_RECEIPT_HASH")?;
    }
    let continuity_len = u64::try_from(request.continuity.len())
        .map_err(|_| anyhow::anyhow!("OMNIS_CHECKPOINT_CONTINUITY_LENGTH_OVERFLOW"))?;
    let expected_first = request
        .observed_receipt_sequence
        .checked_sub(continuity_len - 1)
        .ok_or_else(|| anyhow::anyhow!("OMNIS_CHECKPOINT_CONTINUITY_SEQUENCE_UNDERFLOW"))?;
    let Some(first) = request.continuity.first() else {
        bail!("OMNIS_CHECKPOINT_INVALID_CONTINUITY_LENGTH")
    };
    if first.sequence != expected_first {
        bail!("OMNIS_CHECKPOINT_CONTINUITY_START_MISMATCH")
    }
    match request.prior_checkpoint_hash.as_deref() {
        None if first.sequence != 1 || first.parent_hash.is_some() => {
            bail!("OMNIS_CHECKPOINT_GENESIS_CONTINUITY_MISMATCH")
        }
        Some(_) if first.sequence == 1 || first.parent_hash.is_none() => {
            bail!("OMNIS_CHECKPOINT_EXTENSION_CONTINUITY_MISMATCH")
        }
        _ => {}
    }
    for window in request.continuity.windows(2) {
        let expected_sequence = window[0]
            .sequence
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("OMNIS_CHECKPOINT_RECEIPT_SEQUENCE_OVERFLOW"))?;
        if window[1].sequence != expected_sequence
            || window[1].parent_hash.as_deref() != Some(window[0].receipt_hash.as_str())
        {
            bail!("OMNIS_CHECKPOINT_CONTINUITY_LINK_MISMATCH")
        }
    }
    let Some(last) = request.continuity.last() else {
        bail!("OMNIS_CHECKPOINT_INVALID_CONTINUITY_LENGTH")
    };
    if last.sequence != request.observed_receipt_sequence
        || last.receipt_hash != request.observed_receipt_head
    {
        bail!("OMNIS_CHECKPOINT_CONTINUITY_HEAD_MISMATCH")
    }
    Ok(())
}

pub fn validate_checkpoint_record(record: &CheckpointRecord) -> Result<()> {
    validate_protocol(&record.protocol)?;
    validate_ledger_id(&record.authority_id)?;
    if record.checkpoint_sequence == 0 || record.observed_receipt_sequence == 0 {
        bail!("OMNIS_CHECKPOINT_INVALID_SEQUENCE")
    }
    if record.peer_uid == 0 {
        bail!("OMNIS_CHECKPOINT_ZERO_PEER_UID_REFUSED")
    }
    if record.issued_at_unix_ms == 0 {
        bail!("OMNIS_CHECKPOINT_INVALID_ISSUED_AT")
    }
    if (record.checkpoint_sequence == 1 && record.parent_checkpoint_hash.is_some())
        || (record.checkpoint_sequence > 1 && record.parent_checkpoint_hash.is_none())
    {
        bail!("OMNIS_CHECKPOINT_PARENT_PRESENCE_MISMATCH")
    }
    if let Some(parent) = record.parent_checkpoint_hash.as_deref() {
        validate_digest(parent, "OMNIS_CHECKPOINT_INVALID_PARENT_HASH")?;
    }
    validate_request_id(&record.request_id)?;
    validate_digest(
        &record.request_digest,
        "OMNIS_CHECKPOINT_INVALID_REQUEST_DIGEST",
    )?;
    validate_ledger_id(&record.ledger_id)?;
    validate_receipt_ledger_path(&record.receipt_ledger_path)?;
    validate_digest(
        &record.observed_receipt_head,
        "OMNIS_CHECKPOINT_INVALID_OBSERVED_HEAD",
    )?;
    validate_digest(
        &record.signing_key_id,
        "OMNIS_CHECKPOINT_INVALID_SIGNING_KEY_ID",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    #[test]
    fn request_validation_is_bounded_and_canonical() {
        let request = AnchorRequest {
            protocol: PROTOCOL.to_string(),
            request_id: "anchor:test/1".to_string(),
            ledger_id: DEFAULT_LEDGER_ID.to_string(),
            receipt_ledger_path: "/Users/test/.jcode/state/omnis-key/receipts.jsonl".to_string(),
            prior_checkpoint_hash: None,
            observed_receipt_sequence: 1,
            observed_receipt_head: digest('a'),
            continuity: vec![ReceiptLinkWitness {
                sequence: 1,
                parent_hash: None,
                receipt_hash: digest('a'),
            }],
        };
        validate_anchor_request(&request).unwrap();

        let mut uppercase = request.clone();
        uppercase.observed_receipt_head = digest('A');
        assert!(validate_anchor_request(&uppercase).is_err());

        for invalid_path in [
            "relative/receipts.jsonl",
            "/Users/test/../attacker/receipts.jsonl",
            "/Users/test//.jcode/receipts.jsonl",
            "/Users/test/.jcode/receipts\nforged.jsonl",
            "/",
        ] {
            let mut alternate = request.clone();
            alternate.receipt_ledger_path = invalid_path.to_string();
            assert!(
                validate_anchor_request(&alternate).is_err(),
                "path should be refused: {invalid_path}"
            );
        }

        let mut unknown: serde_json::Value = serde_json::to_value(request).unwrap();
        unknown["extra"] = serde_json::json!(true);
        assert!(serde_json::from_value::<AnchorRequest>(unknown).is_err());
    }
}
