use crate::model::{
    AnchorRequest, CheckpointRecord, SignedCheckpoint, validate_anchor_request,
    validate_checkpoint_record, validate_digest,
};
use anyhow::{Context, Result, bail};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use sha2::{Digest, Sha256};

#[cfg(test)]
use ring::rand::SystemRandom;

const REQUEST_DIGEST_DOMAIN: &str = "jourdanlabs.omnis-checkpoint.request-digest.v1";
const RECORD_HASH_DOMAIN: &str = "jourdanlabs.omnis-checkpoint.record-hash.v1";
const SIGNATURE_DOMAIN: &str = "jourdanlabs.omnis-checkpoint.signature.v1";
const KEY_ID_DOMAIN: &str = "jourdanlabs.omnis-checkpoint.signing-key.v1";

pub(crate) struct SigningIdentity {
    key_pair: Ed25519KeyPair,
    key_id: String,
}

impl std::fmt::Debug for SigningIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SigningIdentity")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl SigningIdentity {
    pub(crate) fn from_pkcs8(bytes: &[u8]) -> Result<Self> {
        let key_pair = Ed25519KeyPair::from_pkcs8(bytes)
            .map_err(|_| anyhow::anyhow!("OMNIS_CHECKPOINT_INVALID_PRIVATE_KEY"))?;
        let key_id = signing_key_id(key_pair.public_key().as_ref());
        Ok(Self { key_pair, key_id })
    }

    pub(crate) fn key_id(&self) -> &str {
        &self.key_id
    }

    pub(crate) fn public_key_bytes(&self) -> &[u8] {
        self.key_pair.public_key().as_ref()
    }

    pub(crate) fn sign(&self, record: CheckpointRecord) -> Result<SignedCheckpoint> {
        validate_checkpoint_record(&record)?;
        if record.signing_key_id != self.key_id {
            bail!("OMNIS_CHECKPOINT_SIGNING_KEY_ID_MISMATCH")
        }
        let record_hash = checkpoint_record_hash(&record)?;
        let message = signature_message(&record_hash)?;
        let signature_ed25519 = hex::encode(self.key_pair.sign(&message).as_ref());
        Ok(SignedCheckpoint {
            record,
            record_hash,
            signature_ed25519,
        })
    }
}

pub fn request_digest(request: &AnchorRequest) -> Result<String> {
    validate_anchor_request(request)?;
    Ok(domain_digest(
        REQUEST_DIGEST_DOMAIN,
        &serde_json::to_vec(request)?,
    ))
}

pub fn checkpoint_record_hash(record: &CheckpointRecord) -> Result<String> {
    validate_checkpoint_record(record)?;
    Ok(domain_digest(
        RECORD_HASH_DOMAIN,
        &serde_json::to_vec(record)?,
    ))
}

pub fn signing_key_id(public_key: &[u8]) -> String {
    domain_digest(KEY_ID_DOMAIN, public_key)
}

pub fn encode_public_key(public_key: &[u8]) -> Result<Vec<u8>> {
    if public_key.len() != 32 {
        bail!("OMNIS_CHECKPOINT_INVALID_PUBLIC_KEY_LENGTH")
    }
    Ok(format!("ed25519:{}\n", hex::encode(public_key)).into_bytes())
}

pub fn parse_public_key(bytes: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(bytes).context("OMNIS_CHECKPOINT_PUBLIC_KEY_NOT_UTF8")?;
    let Some(encoded) = text
        .strip_suffix('\n')
        .and_then(|line| line.strip_prefix("ed25519:"))
    else {
        bail!("OMNIS_CHECKPOINT_INVALID_PUBLIC_KEY_ENCODING")
    };
    if encoded.len() != 64
        || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit())
        || encoded.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        bail!("OMNIS_CHECKPOINT_INVALID_PUBLIC_KEY_ENCODING")
    }
    let public_key =
        hex::decode(encoded).context("OMNIS_CHECKPOINT_INVALID_PUBLIC_KEY_ENCODING")?;
    if public_key.len() != 32 {
        bail!("OMNIS_CHECKPOINT_INVALID_PUBLIC_KEY_LENGTH")
    }
    Ok(public_key)
}

pub fn verify_checkpoint(checkpoint: &SignedCheckpoint, public_key: &[u8]) -> Result<()> {
    validate_checkpoint_record(&checkpoint.record)?;
    validate_digest(
        &checkpoint.record_hash,
        "OMNIS_CHECKPOINT_INVALID_RECORD_HASH",
    )?;
    let expected_key_id = signing_key_id(public_key);
    if checkpoint.record.signing_key_id != expected_key_id {
        bail!("OMNIS_CHECKPOINT_UNTRUSTED_SIGNING_KEY")
    }
    let expected_hash = checkpoint_record_hash(&checkpoint.record)?;
    if checkpoint.record_hash != expected_hash {
        bail!("OMNIS_CHECKPOINT_RECORD_HASH_MISMATCH")
    }
    let signature = hex::decode(&checkpoint.signature_ed25519)
        .context("OMNIS_CHECKPOINT_INVALID_SIGNATURE_ENCODING")?;
    if checkpoint.signature_ed25519.len() != 128
        || checkpoint
            .signature_ed25519
            .bytes()
            .any(|byte| byte.is_ascii_uppercase())
        || signature.len() != 64
    {
        bail!("OMNIS_CHECKPOINT_INVALID_SIGNATURE_LENGTH")
    }
    let message = signature_message(&checkpoint.record_hash)?;
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&message, &signature)
        .map_err(|_| anyhow::anyhow!("OMNIS_CHECKPOINT_SIGNATURE_INVALID"))
}

fn signature_message(record_hash: &str) -> Result<Vec<u8>> {
    validate_digest(record_hash, "OMNIS_CHECKPOINT_INVALID_RECORD_HASH")?;
    let mut message = Vec::new();
    message.extend_from_slice(&(SIGNATURE_DOMAIN.len() as u64).to_be_bytes());
    message.extend_from_slice(SIGNATURE_DOMAIN.as_bytes());
    message.extend_from_slice(&(record_hash.len() as u64).to_be_bytes());
    message.extend_from_slice(record_hash.as_bytes());
    Ok(message)
}

fn domain_digest(domain: &str, bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update((domain.len() as u64).to_be_bytes());
    digest.update(domain.as_bytes());
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    format!("sha256:{}", hex::encode(digest.finalize()))
}

#[cfg(test)]
pub(crate) fn generate_test_identity() -> (Vec<u8>, SigningIdentity) {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let bytes = pkcs8.as_ref().to_vec();
    let identity = SigningIdentity::from_pkcs8(&bytes).unwrap();
    (bytes, identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DEFAULT_LEDGER_ID, PROTOCOL};

    #[test]
    fn signature_binds_every_record_field() {
        let (_, identity) = generate_test_identity();
        let record = CheckpointRecord {
            protocol: PROTOCOL.to_string(),
            authority_id: "jourdanlabs.omnis-checkpoint-authority.v1".to_string(),
            checkpoint_sequence: 1,
            parent_checkpoint_hash: None,
            request_id: "anchor:test".to_string(),
            request_digest: format!("sha256:{}", "a".repeat(64)),
            peer_uid: 501,
            ledger_id: DEFAULT_LEDGER_ID.to_string(),
            receipt_ledger_path: "/Users/test/.jcode/state/omnis-key/receipts.jsonl".to_string(),
            observed_receipt_sequence: 1,
            observed_receipt_head: format!("sha256:{}", "b".repeat(64)),
            issued_at_unix_ms: 1,
            signing_key_id: identity.key_id().to_string(),
        };
        let public_key = identity.public_key_bytes().to_vec();
        let signed = identity.sign(record).unwrap();
        verify_checkpoint(&signed, &public_key).unwrap();

        let mut mutations = Vec::new();
        let mut changed = signed.clone();
        changed.record.authority_id.push_str(".other");
        mutations.push(changed);
        let mut changed = signed.clone();
        changed.record.checkpoint_sequence = 2;
        mutations.push(changed);
        let mut changed = signed.clone();
        changed.record.request_id.push_str(".other");
        mutations.push(changed);
        let mut changed = signed.clone();
        changed.record.request_digest = format!("sha256:{}", "c".repeat(64));
        mutations.push(changed);
        let mut changed = signed.clone();
        changed.record.peer_uid = 502;
        mutations.push(changed);
        let mut changed = signed.clone();
        changed.record.ledger_id.push_str(".other");
        mutations.push(changed);
        let mut changed = signed.clone();
        changed.record.receipt_ledger_path.push_str(".other");
        mutations.push(changed);
        let mut changed = signed.clone();
        changed.record.observed_receipt_sequence = 2;
        mutations.push(changed);
        let mut changed = signed.clone();
        changed.record.observed_receipt_head = format!("sha256:{}", "d".repeat(64));
        mutations.push(changed);
        let mut changed = signed.clone();
        changed.record.issued_at_unix_ms = 2;
        mutations.push(changed);
        let mut changed = signed.clone();
        changed.record.signing_key_id = format!("sha256:{}", "e".repeat(64));
        mutations.push(changed);
        let mut changed = signed.clone();
        changed.record_hash = format!("sha256:{}", "f".repeat(64));
        mutations.push(changed);
        let mut changed = signed;
        let replacement = if changed.signature_ed25519.starts_with('0') {
            "1"
        } else {
            "0"
        };
        changed.signature_ed25519.replace_range(0..1, replacement);
        mutations.push(changed);

        for mutation in mutations {
            assert!(verify_checkpoint(&mutation, &public_key).is_err());
        }
    }

    #[test]
    fn public_key_file_encoding_is_exact() {
        let (_, identity) = generate_test_identity();
        let encoded = encode_public_key(identity.public_key_bytes()).unwrap();
        assert_eq!(
            parse_public_key(&encoded).unwrap(),
            identity.public_key_bytes()
        );
        let mut uppercase = encoded;
        uppercase[8] = b'A';
        assert!(parse_public_key(&uppercase).is_err());
    }
}
