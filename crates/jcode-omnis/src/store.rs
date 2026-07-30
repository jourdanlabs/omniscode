use crate::crypto::{SigningIdentity, parse_public_key, request_digest, verify_checkpoint};
use crate::model::{
    AnchorRequest, AppendDisposition, CheckpointRecord, SignedCheckpoint, validate_anchor_request,
    validate_ledger_id, validate_receipt_ledger_path, validate_request_id,
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

const MAX_KEY_BYTES: u64 = 16 * 1024;
const MAX_RECORD_BYTES: u64 = 8 * 1024 * 1024;
const RECORD_SUFFIX: &str = ".checkpoint.json";
const TEMP_PREFIX: &str = ".checkpoint-tmp-";

static TEMP_NONCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug)]
pub(crate) struct StorePaths {
    pub authority_root: PathBuf,
    pub records_dir: PathBuf,
    pub signing_key_path: PathBuf,
    pub trust_public_key_path: PathBuf,
}

#[derive(Clone, Debug)]
pub(crate) struct StoreConfig {
    pub paths: StorePaths,
    pub authority_id: String,
    pub service_uid: u32,
    pub service_primary_gid: u32,
    pub trust_owner_uid: u32,
    pub trust_owner_gid: u32,
    pub allowed_peer_uid: u32,
    pub allowed_ledger_id: String,
    pub allowed_receipt_ledger_path: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AnchorOutcome {
    pub disposition: AppendDisposition,
    pub checkpoint: SignedCheckpoint,
}

impl AnchorOutcome {
    pub(crate) fn checkpoint(&self) -> &SignedCheckpoint {
        &self.checkpoint
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredCheckpoint {
    request: AnchorRequest,
    checkpoint: SignedCheckpoint,
}

pub(crate) struct AuthorityStore {
    config: StoreConfig,
    signing_identity: SigningIdentity,
    private_key_bytes: Vec<u8>,
    trust_file_bytes: Vec<u8>,
    public_key: Vec<u8>,
}

impl std::fmt::Debug for AuthorityStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorityStore")
            .field("paths", &self.config.paths)
            .field("authority_id", &self.config.authority_id)
            .field("signing_key_id", &self.signing_identity.key_id())
            .field("allowed_peer_uid", &self.config.allowed_peer_uid)
            .field("allowed_ledger_id", &self.config.allowed_ledger_id)
            .field(
                "allowed_receipt_ledger_path",
                &self.config.allowed_receipt_ledger_path,
            )
            .finish_non_exhaustive()
    }
}

impl AuthorityStore {
    pub(crate) fn open(config: StoreConfig) -> Result<Self> {
        #[cfg(not(unix))]
        {
            drop(config);
            bail!("OMNIS_CHECKPOINT_STORE_UNSUPPORTED_PLATFORM")
        }

        #[cfg(unix)]
        {
            validate_config(&config)?;
            validate_authority_paths(&config)?;
            let private_key_bytes = read_bounded_file(
                &config.paths.signing_key_path,
                MAX_KEY_BYTES,
                "OMNIS_CHECKPOINT_PRIVATE_KEY",
                Some((config.service_uid, config.service_primary_gid, 0o400)),
            )?;
            let trust_file_bytes = read_bounded_file(
                &config.paths.trust_public_key_path,
                MAX_KEY_BYTES,
                "OMNIS_CHECKPOINT_PUBLIC_TRUST",
                Some((config.trust_owner_uid, config.trust_owner_gid, 0o444)),
            )?;
            let signing_identity = SigningIdentity::from_pkcs8(&private_key_bytes)?;
            let public_key = parse_public_key(&trust_file_bytes)?;
            if signing_identity.public_key_bytes() != public_key {
                bail!("OMNIS_CHECKPOINT_TRUST_KEY_MISMATCH")
            }
            let store = Self {
                config,
                signing_identity,
                private_key_bytes,
                trust_file_bytes,
                public_key,
            };
            store.load_chain()?;
            Ok(store)
        }
    }

    pub(crate) fn signing_key_id(&self) -> &str {
        self.signing_identity.key_id()
    }

    pub(crate) fn latest(&self) -> Result<Option<SignedCheckpoint>> {
        Ok(self
            .load_chain()?
            .last()
            .map(|stored| stored.checkpoint.clone()))
    }

    pub(crate) fn lookup_request(&self, request_id: &str) -> Result<Option<SignedCheckpoint>> {
        validate_request_id(request_id)?;
        Ok(self
            .load_chain()?
            .into_iter()
            .find(|stored| stored.request.request_id == request_id)
            .map(|stored| stored.checkpoint))
    }

    pub(crate) fn anchor_at(
        &self,
        peer_uid: u32,
        request: &AnchorRequest,
        issued_at_unix_ms: u64,
    ) -> Result<AnchorOutcome> {
        self.validate_live_authority()?;
        validate_anchor_request(request)?;
        if issued_at_unix_ms == 0 {
            bail!("OMNIS_CHECKPOINT_INVALID_ISSUED_AT")
        }
        if peer_uid != self.config.allowed_peer_uid {
            bail!(
                "OMNIS_CHECKPOINT_PEER_UID_MISMATCH: expected {}, found {}",
                self.config.allowed_peer_uid,
                peer_uid
            )
        }
        if request.ledger_id != self.config.allowed_ledger_id {
            bail!("OMNIS_CHECKPOINT_LEDGER_ID_MISMATCH")
        }
        if request.receipt_ledger_path != self.config.allowed_receipt_ledger_path {
            bail!("OMNIS_CHECKPOINT_RECEIPT_LEDGER_PATH_MISMATCH")
        }

        let chain = self.load_chain()?;
        if let Some(existing) = chain
            .iter()
            .find(|stored| stored.request.request_id == request.request_id)
        {
            if existing.request == *request && existing.checkpoint.record.peer_uid == peer_uid {
                return Ok(AnchorOutcome {
                    disposition: AppendDisposition::Existing,
                    checkpoint: existing.checkpoint.clone(),
                });
            }
            bail!(
                "OMNIS_CHECKPOINT_REQUEST_ID_COLLISION: {}",
                request.request_id
            )
        }

        validate_request_advance(request, chain.last())?;
        if chain.last().is_some_and(|previous| {
            previous.checkpoint.record.issued_at_unix_ms > issued_at_unix_ms
        }) {
            bail!("OMNIS_CHECKPOINT_CLOCK_ROLLBACK_REFUSED")
        }
        let checkpoint_sequence = u64::try_from(chain.len())
            .context("OMNIS_CHECKPOINT_SEQUENCE_OVERFLOW")?
            .checked_add(1)
            .context("OMNIS_CHECKPOINT_SEQUENCE_OVERFLOW")?;
        let record = CheckpointRecord {
            protocol: crate::model::PROTOCOL.to_string(),
            authority_id: self.config.authority_id.clone(),
            checkpoint_sequence,
            parent_checkpoint_hash: chain
                .last()
                .map(|stored| stored.checkpoint.record_hash.clone()),
            request_id: request.request_id.clone(),
            request_digest: request_digest(request)?,
            peer_uid,
            ledger_id: request.ledger_id.clone(),
            receipt_ledger_path: request.receipt_ledger_path.clone(),
            observed_receipt_sequence: request.observed_receipt_sequence,
            observed_receipt_head: request.observed_receipt_head.clone(),
            issued_at_unix_ms,
            signing_key_id: self.signing_identity.key_id().to_string(),
        };
        let checkpoint = self.signing_identity.sign(record)?;
        let stored = StoredCheckpoint {
            request: request.clone(),
            checkpoint: checkpoint.clone(),
        };

        if !publish_record(&self.config, checkpoint_sequence, &stored)? {
            let raced = self.load_chain()?;
            if let Some(existing) = raced
                .iter()
                .find(|candidate| candidate.request.request_id == request.request_id)
                && existing.request == *request
                && existing.checkpoint.record.peer_uid == peer_uid
            {
                return Ok(AnchorOutcome {
                    disposition: AppendDisposition::Existing,
                    checkpoint: existing.checkpoint.clone(),
                });
            }
            bail!(
                "OMNIS_CHECKPOINT_PUBLISH_COLLISION: sequence {}",
                checkpoint_sequence
            )
        }

        let published = self.load_chain()?;
        let latest = published
            .last()
            .context("OMNIS_CHECKPOINT_PUBLISHED_RECORD_MISSING")?;
        if latest.checkpoint != checkpoint || latest.request != *request {
            bail!("OMNIS_CHECKPOINT_PUBLISHED_RECORD_DRIFT")
        }
        Ok(AnchorOutcome {
            disposition: AppendDisposition::Appended,
            checkpoint,
        })
    }

    fn validate_live_authority(&self) -> Result<()> {
        #[cfg(not(unix))]
        bail!("OMNIS_CHECKPOINT_STORE_UNSUPPORTED_PLATFORM");

        #[cfg(unix)]
        {
            validate_authority_paths(&self.config)?;
            let private_key_bytes = read_bounded_file(
                &self.config.paths.signing_key_path,
                MAX_KEY_BYTES,
                "OMNIS_CHECKPOINT_PRIVATE_KEY",
                Some((
                    self.config.service_uid,
                    self.config.service_primary_gid,
                    0o400,
                )),
            )?;
            if private_key_bytes != self.private_key_bytes {
                bail!("OMNIS_CHECKPOINT_PRIVATE_KEY_DRIFT")
            }
            let trust_file_bytes = read_bounded_file(
                &self.config.paths.trust_public_key_path,
                MAX_KEY_BYTES,
                "OMNIS_CHECKPOINT_PUBLIC_TRUST",
                Some((
                    self.config.trust_owner_uid,
                    self.config.trust_owner_gid,
                    0o444,
                )),
            )?;
            if trust_file_bytes != self.trust_file_bytes
                || parse_public_key(&trust_file_bytes)? != self.public_key
            {
                bail!("OMNIS_CHECKPOINT_PUBLIC_TRUST_DRIFT")
            }
            Ok(())
        }
    }

    fn load_chain(&self) -> Result<Vec<StoredCheckpoint>> {
        self.validate_live_authority()?;
        let mut records = Vec::new();
        for entry in fs::read_dir(&self.config.paths.records_dir)
            .context("OMNIS_CHECKPOINT_RECORDS_READ_FAILED")?
        {
            let entry = entry.context("OMNIS_CHECKPOINT_RECORD_ENTRY_FAILED")?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("OMNIS_CHECKPOINT_RECORD_NAME_NOT_UTF8"))?;
            if is_temp_name(&name) {
                continue;
            }
            let sequence = parse_record_filename(&name)?;
            records.push((sequence, entry.path()));
        }
        records.sort_by_key(|(sequence, _)| *sequence);

        let mut chain = Vec::with_capacity(records.len());
        let mut request_ids = HashSet::new();
        for (index, (filename_sequence, path)) in records.into_iter().enumerate() {
            let expected_sequence = u64::try_from(index)
                .context("OMNIS_CHECKPOINT_SEQUENCE_OVERFLOW")?
                .checked_add(1)
                .context("OMNIS_CHECKPOINT_SEQUENCE_OVERFLOW")?;
            if filename_sequence != expected_sequence {
                bail!(
                    "OMNIS_CHECKPOINT_SEQUENCE_GAP: expected {}, found {}",
                    expected_sequence,
                    filename_sequence
                )
            }
            validate_record_file(&self.config, &path)?;
            let bytes = read_bounded_file(
                &path,
                MAX_RECORD_BYTES,
                "OMNIS_CHECKPOINT_RECORD",
                Some((
                    self.config.service_uid,
                    self.config.service_primary_gid,
                    0o400,
                )),
            )?;
            let payload = exact_json_line(&bytes)?;
            let stored: StoredCheckpoint =
                serde_json::from_slice(payload).context("OMNIS_CHECKPOINT_RECORD_INVALID_JSON")?;
            validate_stored_checkpoint(
                &self.config,
                &self.public_key,
                expected_sequence,
                chain.last(),
                &stored,
            )?;
            if !request_ids.insert(stored.request.request_id.clone()) {
                bail!(
                    "OMNIS_CHECKPOINT_DUPLICATE_REQUEST_ID: {}",
                    stored.request.request_id
                )
            }
            chain.push(stored);
        }
        Ok(chain)
    }
}

fn validate_request_advance(
    request: &AnchorRequest,
    previous: Option<&StoredCheckpoint>,
) -> Result<()> {
    match previous {
        None => {
            if request.prior_checkpoint_hash.is_some() {
                bail!("OMNIS_CHECKPOINT_GENESIS_PARENT_REFUSED")
            }
        }
        Some(previous) => {
            if request.prior_checkpoint_hash.as_deref()
                != Some(previous.checkpoint.record_hash.as_str())
            {
                bail!("OMNIS_CHECKPOINT_FORK_OR_ROLLBACK_REFUSED")
            }
            if request.observed_receipt_sequence
                <= previous.checkpoint.record.observed_receipt_sequence
            {
                bail!("OMNIS_CHECKPOINT_RECEIPT_NO_ADVANCE")
            }
            let first = request
                .continuity
                .first()
                .context("OMNIS_CHECKPOINT_CONTINUITY_EMPTY")?;
            let expected_first = previous
                .checkpoint
                .record
                .observed_receipt_sequence
                .checked_add(1)
                .context("OMNIS_CHECKPOINT_RECEIPT_SEQUENCE_OVERFLOW")?;
            if first.sequence != expected_first
                || first.parent_hash.as_deref()
                    != Some(previous.checkpoint.record.observed_receipt_head.as_str())
            {
                bail!("OMNIS_CHECKPOINT_RECEIPT_CONTINUITY_FORK")
            }
        }
    }
    Ok(())
}

fn validate_stored_checkpoint(
    config: &StoreConfig,
    public_key: &[u8],
    expected_sequence: u64,
    previous: Option<&StoredCheckpoint>,
    stored: &StoredCheckpoint,
) -> Result<()> {
    validate_anchor_request(&stored.request)?;
    verify_checkpoint(&stored.checkpoint, public_key)?;
    let record = &stored.checkpoint.record;
    if record.checkpoint_sequence != expected_sequence {
        bail!("OMNIS_CHECKPOINT_FILENAME_SEQUENCE_MISMATCH")
    }
    if record.authority_id != config.authority_id {
        bail!("OMNIS_CHECKPOINT_AUTHORITY_ID_MISMATCH")
    }
    if record.issued_at_unix_ms == 0 {
        bail!("OMNIS_CHECKPOINT_INVALID_ISSUED_AT")
    }
    if previous.is_some_and(|previous| {
        previous.checkpoint.record.issued_at_unix_ms > record.issued_at_unix_ms
    }) {
        bail!("OMNIS_CHECKPOINT_STORED_CLOCK_ROLLBACK")
    }
    if record.signing_key_id != crate::crypto::signing_key_id(public_key) {
        bail!("OMNIS_CHECKPOINT_SIGNING_KEY_DRIFT")
    }
    if stored.request.request_id != record.request_id
        || request_digest(&stored.request)? != record.request_digest
        || stored.request.ledger_id != record.ledger_id
        || stored.request.receipt_ledger_path != record.receipt_ledger_path
        || stored.request.observed_receipt_sequence != record.observed_receipt_sequence
        || stored.request.observed_receipt_head != record.observed_receipt_head
    {
        bail!("OMNIS_CHECKPOINT_REQUEST_RECORD_BINDING_MISMATCH")
    }
    if record.peer_uid != config.allowed_peer_uid {
        bail!("OMNIS_CHECKPOINT_STORED_PEER_UID_MISMATCH")
    }
    if record.ledger_id != config.allowed_ledger_id {
        bail!("OMNIS_CHECKPOINT_STORED_LEDGER_ID_MISMATCH")
    }
    if record.receipt_ledger_path != config.allowed_receipt_ledger_path {
        bail!("OMNIS_CHECKPOINT_STORED_RECEIPT_LEDGER_PATH_MISMATCH")
    }
    let expected_parent = previous.map(|value| value.checkpoint.record_hash.as_str());
    if record.parent_checkpoint_hash.as_deref() != expected_parent
        || stored.request.prior_checkpoint_hash.as_deref() != expected_parent
    {
        bail!("OMNIS_CHECKPOINT_CHAIN_FORK_OR_ROLLBACK")
    }
    validate_request_advance(&stored.request, previous)
}

fn exact_json_line(bytes: &[u8]) -> Result<&[u8]> {
    let Some(payload) = bytes.strip_suffix(b"\n") else {
        bail!("OMNIS_CHECKPOINT_RECORD_PARTIAL")
    };
    if payload.is_empty() || payload.contains(&b'\n') || payload.contains(&b'\r') {
        bail!("OMNIS_CHECKPOINT_RECORD_NOT_EXACTLY_ONE_LINE")
    }
    Ok(payload)
}

fn record_filename(sequence: u64) -> String {
    format!("{sequence:020}{RECORD_SUFFIX}")
}

fn parse_record_filename(name: &str) -> Result<u64> {
    let Some(number) = name.strip_suffix(RECORD_SUFFIX) else {
        bail!("OMNIS_CHECKPOINT_UNKNOWN_RECORD_ENTRY: {name}")
    };
    if number.len() != 20 || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("OMNIS_CHECKPOINT_INVALID_RECORD_FILENAME: {name}")
    }
    let sequence = number
        .parse::<u64>()
        .context("OMNIS_CHECKPOINT_INVALID_RECORD_FILENAME")?;
    if sequence == 0 || record_filename(sequence) != name {
        bail!("OMNIS_CHECKPOINT_INVALID_RECORD_FILENAME: {name}")
    }
    Ok(sequence)
}

fn is_temp_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix(TEMP_PREFIX) else {
        return false;
    };
    let mut parts = rest.split('-');
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some(sequence), Some(pid), Some(nonce), None)
            if sequence.len() == 20
                && [sequence, pid, nonce]
                    .iter()
                    .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    )
}

fn publish_record(config: &StoreConfig, sequence: u64, stored: &StoredCheckpoint) -> Result<bool> {
    let final_path = config.paths.records_dir.join(record_filename(sequence));
    let nonce = TEMP_NONCE.fetch_add(1, Ordering::Relaxed);
    let temp_name = format!("{TEMP_PREFIX}{sequence:020}-{}-{nonce}", std::process::id());
    let temporary = config.paths.records_dir.join(temp_name);
    let mut bytes = serde_json::to_vec(stored)?;
    bytes.push(b'\n');

    #[cfg(not(unix))]
    {
        drop((final_path, temporary, bytes));
        bail!("OMNIS_CHECKPOINT_STORE_UNSUPPORTED_PLATFORM")
    }

    #[cfg(unix)]
    {
        let result = (|| -> Result<bool> {
            let mut options = OpenOptions::new();
            options
                .write(true)
                .create_new(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .mode(0o400);
            let mut file = options
                .open(&temporary)
                .context("OMNIS_CHECKPOINT_TEMP_CREATE_FAILED")?;
            file.write_all(&bytes)
                .context("OMNIS_CHECKPOINT_TEMP_WRITE_FAILED")?;
            file.sync_all()
                .context("OMNIS_CHECKPOINT_TEMP_SYNC_FAILED")?;
            assert_unix_metadata(
                &file.metadata()?,
                config.service_uid,
                config.service_primary_gid,
                0o400,
                "OMNIS_CHECKPOINT_TEMP",
            )?;
            assert_no_extended_acl(&temporary)?;
            match fs::hard_link(&temporary, &final_path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    return Ok(false);
                }
                Err(error) => {
                    return Err(error).context("OMNIS_CHECKPOINT_HARD_LINK_PUBLISH_FAILED");
                }
            }
            sync_directory(&config.paths.records_dir)?;
            Ok(true)
        })();
        let cleanup_result = match fs::remove_file(&temporary) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("OMNIS_CHECKPOINT_TEMP_CLEANUP_FAILED"),
        };
        let resync_result = sync_directory(&config.paths.records_dir);
        match result {
            Ok(published) => {
                cleanup_result?;
                resync_result?;
                Ok(published)
            }
            Err(error) => {
                if let Err(cleanup_error) = cleanup_result {
                    bail!(
                        "OMNIS_CHECKPOINT_PUBLISH_AND_CLEANUP_FAILED: \
                         publish={error:#}; cleanup={cleanup_error:#}"
                    )
                }
                if let Err(resync_error) = resync_result {
                    bail!(
                        "OMNIS_CHECKPOINT_PUBLISH_AND_RESYNC_FAILED: \
                         publish={error:#}; resync={resync_error:#}"
                    )
                }
                Err(error)
            }
        }
    }
}

fn validate_config(config: &StoreConfig) -> Result<()> {
    validate_ledger_id(&config.authority_id)?;
    validate_ledger_id(&config.allowed_ledger_id)?;
    validate_receipt_ledger_path(&config.allowed_receipt_ledger_path)?;
    if config.service_uid == 0 || config.service_primary_gid == 0 || config.allowed_peer_uid == 0 {
        bail!("OMNIS_CHECKPOINT_ZERO_IDENTITY_REFUSED")
    }
    if config.service_uid == config.allowed_peer_uid {
        bail!("OMNIS_CHECKPOINT_SERVICE_CLIENT_UID_NOT_DISTINCT")
    }
    for path in [
        &config.paths.authority_root,
        &config.paths.records_dir,
        &config.paths.signing_key_path,
        &config.paths.trust_public_key_path,
    ] {
        if !path.is_absolute() {
            bail!("OMNIS_CHECKPOINT_PATH_NOT_ABSOLUTE: {}", path.display())
        }
    }
    if config.paths.records_dir.parent() != Some(config.paths.authority_root.as_path())
        || config.paths.signing_key_path.parent() != Some(config.paths.authority_root.as_path())
    {
        bail!("OMNIS_CHECKPOINT_AUTHORITY_PATH_LAYOUT_MISMATCH")
    }
    Ok(())
}

#[cfg(unix)]
fn validate_authority_paths(config: &StoreConfig) -> Result<()> {
    validate_no_symlink_components(&config.paths.authority_root)?;
    validate_no_symlink_components(&config.paths.records_dir)?;
    validate_no_symlink_components(&config.paths.signing_key_path)?;
    validate_no_symlink_components(&config.paths.trust_public_key_path)?;
    assert_no_extended_acl(&config.paths.authority_root)?;
    assert_no_extended_acl(&config.paths.records_dir)?;
    assert_no_extended_acl(&config.paths.signing_key_path)?;
    assert_no_extended_acl(&config.paths.trust_public_key_path)?;

    assert_unix_metadata(
        &fs::symlink_metadata(&config.paths.authority_root)?,
        config.service_uid,
        config.service_primary_gid,
        0o700,
        "OMNIS_CHECKPOINT_AUTHORITY_ROOT",
    )?;
    if !fs::metadata(&config.paths.authority_root)?.is_dir() {
        bail!("OMNIS_CHECKPOINT_AUTHORITY_ROOT_NOT_DIRECTORY")
    }
    assert_unix_metadata(
        &fs::symlink_metadata(&config.paths.records_dir)?,
        config.service_uid,
        config.service_primary_gid,
        0o700,
        "OMNIS_CHECKPOINT_RECORDS_DIRECTORY",
    )?;
    if !fs::metadata(&config.paths.records_dir)?.is_dir() {
        bail!("OMNIS_CHECKPOINT_RECORDS_NOT_DIRECTORY")
    }
    validate_regular_file(
        &config.paths.signing_key_path,
        config.service_uid,
        config.service_primary_gid,
        0o400,
        "OMNIS_CHECKPOINT_PRIVATE_KEY",
    )?;
    validate_regular_file(
        &config.paths.trust_public_key_path,
        config.trust_owner_uid,
        config.trust_owner_gid,
        0o444,
        "OMNIS_CHECKPOINT_PUBLIC_TRUST",
    )
}

#[cfg(unix)]
fn validate_record_file(config: &StoreConfig, path: &Path) -> Result<()> {
    validate_no_symlink_components(path)?;
    assert_no_extended_acl(path)?;
    validate_regular_file(
        path,
        config.service_uid,
        config.service_primary_gid,
        0o400,
        "OMNIS_CHECKPOINT_RECORD",
    )
}

#[cfg(unix)]
fn validate_regular_file(path: &Path, uid: u32, gid: u32, mode: u32, code: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("{code}_MISSING: {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("{code}_SYMLINK_REFUSED: {}", path.display())
    }
    if !metadata.is_file() {
        bail!("{code}_NOT_REGULAR_FILE: {}", path.display())
    }
    assert_unix_metadata(&metadata, uid, gid, mode, code)
}

#[cfg(unix)]
fn assert_unix_metadata(
    metadata: &fs::Metadata,
    uid: u32,
    gid: u32,
    mode: u32,
    code: &str,
) -> Result<()> {
    if metadata.uid() != uid || metadata.gid() != gid {
        bail!(
            "{code}_OWNERSHIP_MISMATCH: expected {}:{}, found {}:{}",
            uid,
            gid,
            metadata.uid(),
            metadata.gid()
        )
    }
    let actual_mode = metadata.permissions().mode() & 0o7777;
    if actual_mode != mode {
        bail!(
            "{code}_MODE_MISMATCH: expected {:04o}, found {:04o}",
            mode,
            actual_mode
        )
    }
    Ok(())
}

#[cfg(unix)]
fn validate_no_symlink_components(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("OMNIS_CHECKPOINT_PATH_NOT_ABSOLUTE: {}", path.display())
    }
    let mut cursor = Some(path);
    while let Some(component) = cursor {
        let metadata = fs::symlink_metadata(component)
            .with_context(|| format!("OMNIS_CHECKPOINT_PATH_MISSING: {}", component.display()))?;
        if metadata.file_type().is_symlink() {
            bail!(
                "OMNIS_CHECKPOINT_PATH_SYMLINK_REFUSED: {}",
                component.display()
            )
        }
        cursor = component.parent();
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn assert_no_extended_acl(path: &Path) -> Result<()> {
    let output = std::process::Command::new("/bin/ls")
        .env_clear()
        .env("LC_ALL", "C")
        .args(["-lde"])
        .arg(path)
        .output()
        .with_context(|| format!("OMNIS_CHECKPOINT_ACL_INSPECTION_FAILED: {}", path.display()))?;
    if !output.status.success() {
        bail!("OMNIS_CHECKPOINT_ACL_INSPECTION_FAILED: {}", path.display())
    }
    let output =
        String::from_utf8(output.stdout).context("OMNIS_CHECKPOINT_ACL_INSPECTION_NOT_UTF8")?;
    let mut lines = output.lines();
    let metadata_line = lines
        .next()
        .context("OMNIS_CHECKPOINT_ACL_INSPECTION_EMPTY")?;
    let marker = metadata_line
        .split_whitespace()
        .next()
        .and_then(|mode| mode.chars().nth(10));
    let numbered_acl_entry = lines.any(|line| {
        line.trim_start().split_once(':').is_some_and(|(index, _)| {
            !index.is_empty() && index.bytes().all(|byte| byte.is_ascii_digit())
        })
    });
    if marker == Some('+') || numbered_acl_entry {
        bail!("OMNIS_CHECKPOINT_EXTENDED_ACL_REFUSED: {}", path.display())
    }
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn assert_no_extended_acl(_path: &Path) -> Result<()> {
    bail!("OMNIS_CHECKPOINT_ACL_INSPECTION_UNSUPPORTED_PLATFORM")
}

fn read_bounded_file(
    path: &Path,
    maximum: u64,
    code: &str,
    expected_identity: Option<(u32, u32, u32)>,
) -> Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options
        .open(path)
        .with_context(|| format!("{code}_OPEN_FAILED: {}", path.display()))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        bail!("{code}_NOT_REGULAR_FILE: {}", path.display())
    }
    #[cfg(unix)]
    if let Some((uid, gid, mode)) = expected_identity {
        assert_unix_metadata(&metadata, uid, gid, mode, code)?;
    }
    #[cfg(not(unix))]
    let _expected_identity = expected_identity;
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("{code}_READ_FAILED: {}", path.display()))?;
    if bytes.len() as u64 > maximum {
        bail!("{code}_TOO_LARGE: {}", path.display())
    }
    Ok(bytes)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?
        .sync_all()
        .with_context(|| format!("OMNIS_CHECKPOINT_DIRECTORY_SYNC_FAILED: {}", path.display()))
}

#[cfg(all(test, target_os = "macos"))]
mod tests;
