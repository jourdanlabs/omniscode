//! OMNIS Key's local receipt core.
//!
//! This module deliberately records bounded local provenance only. A valid
//! chain proves that the bytes currently present are internally consistent; it
//! does not authorize actions, validate external evidence, or resist deletion
//! without a separately managed external checkpoint.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const PROTOCOL: &str = "jourdanlabs.omnis-receipt.v1";

mod boundary;
pub(crate) use boundary::validate_existing_directory_ancestor;
pub use boundary::{validate_private_directory, validate_private_file};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClaimCeiling {
    LocalRecord,
    LocalVerification,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    protocol: String,
    sequence: u64,
    parent_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    event_id: Option<String>,
    kind: String,
    subject: String,
    evidence_sha256: String,
    /// Optional recoverable evidence payload. Bound by `evidence_sha256` (not
    /// by `receipt_hash` fields — so old ledgers without this field still verify).
    /// Agent action receipts store redacted shape here (never secrets by default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    evidence: Option<serde_json::Value>,
    claim_ceiling: ClaimCeiling,
    receipt_hash: String,
}

impl Receipt {
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn event_id(&self) -> Option<&str> {
        self.event_id.as_deref()
    }

    pub fn parent_hash(&self) -> Option<&str> {
        self.parent_hash.as_deref()
    }

    pub fn receipt_hash(&self) -> &str {
        &self.receipt_hash
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub fn subject(&self) -> &str {
        &self.subject
    }

    pub fn evidence_sha256(&self) -> &str {
        &self.evidence_sha256
    }

    pub fn evidence(&self) -> Option<&serde_json::Value> {
        self.evidence.as_ref()
    }

    pub fn claim_ceiling(&self) -> ClaimCeiling {
        self.claim_ceiling
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppendDisposition {
    Appended,
    Existing,
}

#[derive(Debug, Serialize)]
pub struct AppendOutcome {
    disposition: AppendDisposition,
    receipt: Receipt,
}

impl AppendOutcome {
    pub fn disposition(&self) -> AppendDisposition {
        self.disposition
    }

    pub fn receipt(&self) -> &Receipt {
        &self.receipt
    }
}

#[derive(Debug, Serialize)]
pub struct Verification {
    valid: bool,
    entries: usize,
    head: Option<String>,
    integrity_scope: &'static str,
    errors: Vec<String>,
}

impl Verification {
    pub fn valid(&self) -> bool {
        self.valid
    }

    pub fn entries(&self) -> usize {
        self.entries
    }

    pub fn head(&self) -> Option<&str> {
        self.head.as_deref()
    }

    pub fn errors(&self) -> &[String] {
        &self.errors
    }
}

pub fn canonical_ledger_path() -> Result<PathBuf> {
    let root = crate::storage::jcode_dir().context("OMNIS_RECEIPT_HOME_UNAVAILABLE")?;
    if !root.is_absolute() {
        bail!("OMNIS_RECEIPT_HOME_NOT_ABSOLUTE")
    }
    Ok(root.join("state").join("omnis-key").join("receipts.jsonl"))
}

fn digest_fields(fields: &[&str]) -> String {
    let mut digest = Sha256::new();
    for field in fields {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field.as_bytes());
    }
    format!("sha256:{}", hex::encode(digest.finalize()))
}

fn receipt_hash(receipt: &Receipt) -> String {
    let sequence = receipt.sequence.to_string();
    let mut fields = vec![
        receipt.protocol.as_str(),
        sequence.as_str(),
        receipt.parent_hash.as_deref().unwrap_or(""),
        receipt.kind.as_str(),
        receipt.subject.as_str(),
        receipt.evidence_sha256.as_str(),
        match receipt.claim_ceiling {
            ClaimCeiling::LocalRecord => "local-record",
            ClaimCeiling::LocalVerification => "local-verification",
        },
    ];
    if let Some(event_id) = receipt.event_id.as_deref() {
        fields.push("event-id");
        fields.push(event_id);
    }
    digest_fields(&fields)
}

fn normalize_digest(value: &str) -> Result<String> {
    let raw = value.strip_prefix("sha256:").unwrap_or(value);
    if raw.len() != 64 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("evidence_sha256 must be exactly 64 hexadecimal characters")
    }
    Ok(format!("sha256:{}", raw.to_ascii_lowercase()))
}

/// Hash a JSON evidence payload the same way writers do (`serde_json::to_vec`).
pub fn evidence_payload_digest(payload: &serde_json::Value) -> Result<String> {
    let bytes = serde_json::to_vec(payload).context("serialize evidence payload for digest")?;
    let mut digest = Sha256::new();
    digest.update(&bytes);
    Ok(format!("sha256:{}", hex::encode(digest.finalize())))
}

fn validate_kind(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        bail!("kind must be 1-128 ASCII letters, digits, '.', '-', or '_'")
    }
    Ok(())
}

fn validate_event_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 256
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'/')
        })
    {
        bail!("event_id must be 1-256 ASCII letters, digits, '.', '-', '_', ':', or '/'")
    }
    Ok(())
}

fn validate_subject(value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 4096 || value.contains('\n') || value.contains('\r')
    {
        bail!("subject must be non-empty, single-line, and at most 4096 bytes")
    }
    Ok(())
}

/// Create every **missing** component of `dir` as `0700`.
///
/// Existing directories are not chmod'd — a world-readable parent still fails
/// `validate_private_directory` (fail closed). This only fixes the fresh-install
/// trap where `create_dir_all` used to create `state/` world-readable and then
/// refuse it.
#[cfg(unix)]
pub fn ensure_private_directory_tree(dir: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    // Build list of missing components from leaf up to (not including) existing ancestor.
    let mut missing: Vec<PathBuf> = Vec::new();
    let mut cursor = dir.to_path_buf();
    loop {
        if cursor.exists() {
            break;
        }
        missing.push(cursor.clone());
        match cursor.parent() {
            Some(parent) if parent != cursor => cursor = parent.to_path_buf(),
            _ => break,
        }
    }
    missing.reverse();

    for path in missing {
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(&path)
            .with_context(|| format!("create private OMNIS directory {}", path.display()))?;
    }
    // Existing ancestors (and the final dir if pre-existing) must already be private.
    validate_private_directory(dir, "OMNIS_RECEIPT_DIRECTORY")?;
    Ok(())
}

#[cfg(not(unix))]
pub fn ensure_private_directory_tree(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)
        .with_context(|| format!("create OMNIS receipt directory {}", dir.display()))?;
    Ok(())
}

fn resolved_ledger_path(
    path: &Path,
    create_parent: bool,
    enforce_private: bool,
) -> Result<Option<PathBuf>> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("resolve current directory for OMNIS receipt ledger")?
            .join(path)
    };
    let parent = absolute
        .parent()
        .context("OMNIS_RECEIPT_LEDGER_MISSING_PARENT")?;
    if create_parent {
        validate_existing_directory_ancestor(parent)?;
        #[cfg(unix)]
        if enforce_private {
            // Propagate IDENTITY_OR_MODE_DRIFT codes without wrapping them away
            // from callers that match on the error string.
            ensure_private_directory_tree(parent)?;
        } else {
            fs::create_dir_all(parent)
                .with_context(|| format!("create OMNIS receipt directory {}", parent.display()))?;
        }
        #[cfg(not(unix))]
        fs::create_dir_all(parent)
            .with_context(|| format!("create OMNIS receipt directory {}", parent.display()))?;
    } else if !parent.exists() {
        validate_existing_directory_ancestor(parent)?;
        return Ok(None);
    }
    let canonical_parent = fs::canonicalize(parent)
        .with_context(|| format!("resolve OMNIS receipt directory {}", parent.display()))?;
    #[cfg(unix)]
    if !paths_equivalent(parent, &canonical_parent) {
        bail!(
            "OMNIS_RECEIPT_DIRECTORY_SYMLINK_REFUSED: {} -> {}",
            parent.display(),
            canonical_parent.display()
        )
    }
    if enforce_private {
        validate_private_directory(&canonical_parent, "OMNIS_RECEIPT_DIRECTORY")?;
    }
    let filename = absolute
        .file_name()
        .context("OMNIS_RECEIPT_LEDGER_MISSING_FILENAME")?;
    let resolved = canonical_parent.join(filename);
    match fs::symlink_metadata(&resolved) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!("OMNIS_RECEIPT_SYMLINK_REFUSED: {}", resolved.display())
        }
        Ok(metadata) if !metadata.is_file() => {
            bail!("OMNIS_RECEIPT_NOT_REGULAR_FILE: {}", resolved.display())
        }
        Ok(_) => {
            if enforce_private {
                validate_private_file(&resolved, "OMNIS_RECEIPT")?;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect OMNIS receipt ledger {}", resolved.display()));
        }
    }
    Ok(Some(resolved))
}

#[cfg(unix)]
fn paths_equivalent(requested: &Path, actual: &Path) -> bool {
    if requested == actual {
        return true;
    }
    #[cfg(target_os = "macos")]
    {
        for (logical, physical) in [("/tmp", "/private/tmp"), ("/var", "/private/var")] {
            let logical = Path::new(logical);
            if let Ok(suffix) = requested.strip_prefix(logical)
                && actual == Path::new(physical).join(suffix)
            {
                return true;
            }
        }
    }
    false
}

fn open_options_nofollow(options: &mut OpenOptions) -> &mut OpenOptions {
    #[cfg(unix)]
    {
        options
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .mode(0o600);
    }
    options
}

fn open_lock(path: &Path) -> Result<File> {
    let lock_path = path.with_extension("jsonl.lock");
    match fs::symlink_metadata(&lock_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!(
                "OMNIS_RECEIPT_LOCK_SYMLINK_REFUSED: {}",
                lock_path.display()
            )
        }
        Ok(metadata) if !metadata.is_file() => {
            bail!(
                "OMNIS_RECEIPT_LOCK_NOT_REGULAR_FILE: {}",
                lock_path.display()
            )
        }
        Ok(_) => validate_private_file(&lock_path, "OMNIS_RECEIPT_LOCK")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect OMNIS receipt lock {}", lock_path.display()));
        }
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    let file = open_options_nofollow(&mut options)
        .open(&lock_path)
        .with_context(|| format!("open OMNIS receipt lock {}", lock_path.display()))?;
    if !file.metadata()?.is_file() {
        bail!(
            "OMNIS_RECEIPT_LOCK_NOT_REGULAR_FILE: {}",
            lock_path.display()
        )
    }
    validate_private_file(&lock_path, "OMNIS_RECEIPT_LOCK")?;
    file.lock()
        .with_context(|| format!("OMNIS_RECEIPT_LOCK_UNAVAILABLE: {}", lock_path.display()))?;
    Ok(file)
}

fn read_receipts_from(file: &mut File, path: &Path) -> Result<Vec<Receipt>> {
    file.seek(SeekFrom::Start(0))
        .with_context(|| format!("seek OMNIS receipt ledger {}", path.display()))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .with_context(|| format!("read OMNIS receipt ledger {}", path.display()))?;
    if !contents.is_empty() && !contents.ends_with('\n') {
        bail!("OMNIS_RECEIPT_PARTIAL_TAIL")
    }
    contents
        .lines()
        .enumerate()
        .map(|(index, line)| {
            serde_json::from_str(line)
                .with_context(|| format!("OMNIS_RECEIPT_INVALID_JSON at line {}", index + 1))
        })
        .collect()
}

fn sync_ledger(file: &File, path: &Path) -> Result<()> {
    file.sync_all()
        .with_context(|| format!("sync OMNIS receipt ledger {}", path.display()))?;
    #[cfg(unix)]
    File::open(
        path.parent()
            .context("OMNIS_RECEIPT_LEDGER_MISSING_PARENT_AFTER_APPEND")?,
    )
    .and_then(|directory| directory.sync_all())
    .with_context(|| format!("sync OMNIS receipt directory {}", path.display()))?;
    Ok(())
}

#[cfg(unix)]
fn publish_with_appended_line(file: &mut File, path: &Path, line: &[u8]) -> Result<()> {
    file.seek(SeekFrom::Start(0))
        .with_context(|| format!("seek OMNIS receipt ledger {}", path.display()))?;
    let mut existing = Vec::new();
    file.read_to_end(&mut existing)
        .with_context(|| format!("read OMNIS receipt ledger {}", path.display()))?;

    let temporary = path.with_extension(format!(
        "tmp.{}.{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .mode(0o600);
        let mut replacement = options
            .open(&temporary)
            .with_context(|| format!("create OMNIS receipt temp {}", temporary.display()))?;
        validate_private_file(&temporary, "OMNIS_RECEIPT_TEMP")?;
        replacement
            .write_all(&existing)
            .with_context(|| format!("copy OMNIS receipt ledger {}", path.display()))?;
        replacement
            .write_all(line)
            .with_context(|| format!("append OMNIS receipt temp {}", temporary.display()))?;
        replacement
            .sync_all()
            .with_context(|| format!("sync OMNIS receipt temp {}", temporary.display()))?;
        fs::rename(&temporary, path).with_context(|| {
            format!(
                "atomically publish OMNIS receipt ledger {} -> {}",
                temporary.display(),
                path.display()
            )
        })?;
        File::open(
            path.parent()
                .context("OMNIS_RECEIPT_LEDGER_MISSING_PARENT_AFTER_PUBLISH")?,
        )?
        .sync_all()
        .with_context(|| format!("sync OMNIS receipt directory {}", path.display()))?;
        Ok(())
    })();
    if let Err(error) = result {
        match fs::remove_file(&temporary) {
            Ok(()) => {}
            Err(cleanup_error) if cleanup_error.kind() == std::io::ErrorKind::NotFound => {}
            Err(cleanup_error) => {
                bail!(
                    "OMNIS_RECEIPT_PUBLISH_AND_CLEANUP_FAILED: \
                     publish={error:#}; cleanup={cleanup_error}"
                )
            }
        }
        return Err(error);
    }
    Ok(())
}

#[cfg(not(unix))]
fn publish_with_appended_line(file: &mut File, path: &Path, line: &[u8]) -> Result<()> {
    file.write_all(line)
        .with_context(|| format!("append OMNIS receipt ledger {}", path.display()))?;
    sync_ledger(file, path)
}

fn verify_receipts(receipts: &[Receipt]) -> Verification {
    let mut errors = Vec::new();
    let mut parent = None;
    let mut event_ids = HashSet::new();
    for (index, receipt) in receipts.iter().enumerate() {
        if receipt.protocol != PROTOCOL {
            errors.push(format!("entry {} protocol mismatch", index + 1));
        }
        if receipt.sequence != index as u64 + 1 {
            errors.push(format!("entry {} sequence mismatch", index + 1));
        }
        if receipt.parent_hash != parent {
            errors.push(format!("entry {} parent hash mismatch", index + 1));
        }
        if receipt.receipt_hash != receipt_hash(receipt) {
            errors.push(format!("entry {} receipt hash mismatch", index + 1));
        }
        if let Err(error) = validate_kind(&receipt.kind) {
            errors.push(format!("entry {} invalid kind: {}", index + 1, error));
        }
        if let Err(error) = validate_subject(&receipt.subject) {
            errors.push(format!("entry {} invalid subject: {}", index + 1, error));
        }
        match normalize_digest(&receipt.evidence_sha256) {
            Ok(normalized) if normalized == receipt.evidence_sha256 => {}
            _ => errors.push(format!("entry {} invalid evidence digest", index + 1)),
        }
        // If recoverable evidence is present, it must match evidence_sha256.
        if let Some(payload) = receipt.evidence.as_ref() {
            match evidence_payload_digest(payload) {
                Ok(digest) if digest == receipt.evidence_sha256 => {}
                Ok(_) => errors.push(format!(
                    "entry {} evidence payload does not match evidence_sha256",
                    index + 1
                )),
                Err(error) => errors.push(format!(
                    "entry {} evidence payload unhashable: {}",
                    index + 1,
                    error
                )),
            }
        }
        if let Some(event_id) = receipt.event_id.as_deref() {
            if let Err(error) = validate_event_id(event_id) {
                errors.push(format!("entry {} invalid event id: {}", index + 1, error));
            } else if !event_ids.insert(event_id) {
                errors.push(format!("entry {} duplicate event id", index + 1));
            }
        }
        parent = Some(receipt.receipt_hash.clone());
    }
    Verification {
        valid: errors.is_empty(),
        entries: receipts.len(),
        head: parent,
        integrity_scope: "local-chain-only; external evidence and rollback require separate verification",
        errors,
    }
}

pub fn verify(path: &Path) -> Result<Verification> {
    let Some(path) = resolved_ledger_path(path, false, true)? else {
        return Ok(verify_receipts(&[]));
    };
    if !path.exists() {
        return Ok(verify_receipts(&[]));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    let mut file = open_options_nofollow(&mut options)
        .open(&path)
        .with_context(|| format!("open OMNIS receipt ledger {}", path.display()))?;
    let receipts = read_receipts_from(&mut file, &path)?;
    Ok(verify_receipts(&receipts))
}

pub fn verified_receipts(path: &Path) -> Result<Vec<Receipt>> {
    let Some(path) = resolved_ledger_path(path, false, true)? else {
        return Ok(Vec::new());
    };
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    let mut file = open_options_nofollow(&mut options)
        .open(&path)
        .with_context(|| format!("open OMNIS receipt ledger {}", path.display()))?;
    let receipts = read_receipts_from(&mut file, &path)?;
    let verification = verify_receipts(&receipts);
    if !verification.valid {
        bail!("OMNIS_RECEIPT_CHAIN_INVALID: {:?}", verification.errors)
    }
    Ok(receipts)
}

fn append_inner(
    path: &Path,
    event_id: Option<&str>,
    kind: &str,
    subject: &str,
    evidence_sha256: &str,
    claim_ceiling: ClaimCeiling,
    evidence: Option<serde_json::Value>,
) -> Result<AppendOutcome> {
    if let Some(event_id) = event_id {
        validate_event_id(event_id)?;
    }
    validate_kind(kind)?;
    validate_subject(subject)?;
    let evidence_sha256 = normalize_digest(evidence_sha256)?;
    if let Some(payload) = evidence.as_ref() {
        let bound = evidence_payload_digest(payload)?;
        if bound != evidence_sha256 {
            bail!("OMNIS_RECEIPT_EVIDENCE_DIGEST_MISMATCH")
        }
    }
    let path = resolved_ledger_path(path, true, true)?
        .context("OMNIS_RECEIPT_LEDGER_MISSING_AFTER_DIRECTORY_CREATION")?;
    let _lock = open_lock(&path)?;
    let mut options = OpenOptions::new();
    options.read(true).append(true).create(true);
    let mut file = open_options_nofollow(&mut options)
        .open(&path)
        .with_context(|| format!("open OMNIS receipt ledger {}", path.display()))?;
    if !file.metadata()?.is_file() {
        bail!("OMNIS_RECEIPT_NOT_REGULAR_FILE: {}", path.display())
    }
    validate_private_file(&path, "OMNIS_RECEIPT")?;
    let receipts = read_receipts_from(&mut file, &path)?;
    let before = verify_receipts(&receipts);
    if !before.valid {
        bail!(
            "OMNIS_RECEIPT_CHAIN_INVALID_BEFORE_APPEND: {:?}",
            before.errors
        )
    }
    if let Some(event_id) = event_id
        && let Some(existing) = receipts
            .iter()
            .find(|receipt| receipt.event_id.as_deref() == Some(event_id))
    {
        if existing.kind == kind
            && existing.subject == subject
            && existing.evidence_sha256 == evidence_sha256
            && existing.claim_ceiling == claim_ceiling
            && existing.evidence == evidence
        {
            sync_ledger(&file, &path)?;
            return Ok(AppendOutcome {
                disposition: AppendDisposition::Existing,
                receipt: existing.clone(),
            });
        }
        bail!("OMNIS_RECEIPT_IDEMPOTENCY_COLLISION: {}", event_id)
    }
    let mut receipt = Receipt {
        protocol: PROTOCOL.to_string(),
        sequence: before.entries as u64 + 1,
        parent_hash: before.head,
        event_id: event_id.map(str::to_string),
        kind: kind.to_string(),
        subject: subject.to_string(),
        evidence_sha256,
        evidence,
        claim_ceiling,
        receipt_hash: String::new(),
    };
    receipt.receipt_hash = receipt_hash(&receipt);
    let line = format!("{}\n", serde_json::to_string(&receipt)?);
    publish_with_appended_line(&mut file, &path, line.as_bytes())?;
    Ok(AppendOutcome {
        disposition: AppendDisposition::Appended,
        receipt,
    })
}

pub fn append(
    path: &Path,
    kind: &str,
    subject: &str,
    evidence_sha256: &str,
    claim_ceiling: ClaimCeiling,
) -> Result<Receipt> {
    Ok(append_inner(
        path,
        None,
        kind,
        subject,
        evidence_sha256,
        claim_ceiling,
        None,
    )?
    .receipt)
}

pub fn append_idempotent(
    path: &Path,
    event_id: &str,
    kind: &str,
    subject: &str,
    evidence_sha256: &str,
    claim_ceiling: ClaimCeiling,
) -> Result<AppendOutcome> {
    append_inner(
        path,
        Some(event_id),
        kind,
        subject,
        evidence_sha256,
        claim_ceiling,
        None,
    )
}

/// Append with recoverable evidence payload (must hash to `evidence_sha256`).
pub fn append_idempotent_with_evidence(
    path: &Path,
    event_id: &str,
    kind: &str,
    subject: &str,
    evidence_sha256: &str,
    claim_ceiling: ClaimCeiling,
    evidence: serde_json::Value,
) -> Result<AppendOutcome> {
    append_inner(
        path,
        Some(event_id),
        kind,
        subject,
        evidence_sha256,
        claim_ceiling,
        Some(evidence),
    )
}

pub fn ledger_path(path: Option<&str>) -> PathBuf {
    path.map(PathBuf::from).unwrap_or_else(|| {
        canonical_ledger_path().unwrap_or_else(|_| {
            #[cfg(unix)]
            {
                PathBuf::from("/__omnis_key_canonical_state_unavailable__/receipts.jsonl")
            }
            #[cfg(not(unix))]
            {
                PathBuf::from(r"C:\__omnis_key_canonical_state_unavailable__\receipts.jsonl")
            }
        })
    })
}

#[cfg(test)]
mod tests;
