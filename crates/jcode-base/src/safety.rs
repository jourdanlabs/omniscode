use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

use crate::storage;

/// Hook invoked to deliver a permission-request notification.
///
/// Args: `(action, description, request_id)`.
type PermissionNotifier = fn(&str, &str, &str);

static PERMISSION_NOTIFIER: OnceLock<PermissionNotifier> = OnceLock::new();

/// Register the permission-request notification dispatcher.
///
/// This inverts the historical `safety -> notifications` dependency: the
/// `notifications` layer (which already depends on `safety` types like
/// [`AmbientTranscript`]) registers its dispatcher here at startup, so
/// `safety` no longer needs to construct a `NotificationDispatcher`.
pub fn register_permission_notifier(notifier: PermissionNotifier) {
    let _ = PERMISSION_NOTIFIER.set(notifier);
}

fn dispatch_permission_notification(action: &str, description: &str, request_id: &str) {
    if let Some(notifier) = PERMISSION_NOTIFIER.get() {
        notifier(action, description, request_id);
    }
}

// ---------------------------------------------------------------------------
// Action classification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionTier {
    AutoAllowed,
    RequiresPermission,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Urgency {
    Low,
    Normal,
    High,
}

// ---------------------------------------------------------------------------
// Permission request / result / decision
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionRequest {
    pub id: String,
    pub action: String,
    pub description: String,
    pub rationale: String,
    pub urgency: Urgency,
    pub wait: bool,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PermissionResult {
    Approved { message: Option<String> },
    Denied { reason: Option<String> },
    Queued { request_id: String },
    Timeout,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_id: Option<String>,
    pub request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<PermissionRequest>,
    pub approved: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<DecisionOutcome>,
    pub decided_at: DateTime<Utc>,
    pub decided_via: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub omnis_evidence_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub omnis_receipt_hash: Option<String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionOutcome {
    Approved,
    Denied,
    Expired,
}

// ---------------------------------------------------------------------------
// Action log / transcript
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionLog {
    pub action_type: String,
    pub description: String,
    pub tier: ActionTier,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptStatus {
    Complete,
    Interrupted,
    Incomplete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmbientTranscript {
    pub session_id: String,
    pub started_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<DateTime<Utc>>,
    pub status: TranscriptStatus,
    pub provider: String,
    pub model: String,
    pub actions: Vec<ActionLog>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_permissions: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    pub compactions: u32,
    pub memories_modified: u32,
    /// Full conversation transcript (markdown) for email notifications
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation: Option<String>,
}

// ---------------------------------------------------------------------------
// Tier-1 (auto-allowed) action names
// ---------------------------------------------------------------------------

const AUTO_ALLOWED: &[&str] = &[
    "read",
    "glob",
    "grep",
    "ls",
    "memory",
    "todo",
    "todowrite",
    "todoread",
    "conversation_search",
    "session_search",
    "codesearch",
];

// ---------------------------------------------------------------------------
// SafetySystem
// ---------------------------------------------------------------------------

pub struct SafetySystem {
    actions: Mutex<Vec<ActionLog>>,
}

const SAFETY_STATE_SCHEMA_VERSION: u32 = 1;
const SAFETY_EVIDENCE_PROTOCOL: &str = "jourdanlabs.safety-decision-evidence.v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReceiptOutboxEntry {
    event_id: String,
    decision_id: String,
    kind: String,
    subject: String,
    evidence_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SafetyState {
    schema_version: u32,
    queue: Vec<PermissionRequest>,
    history: Vec<Decision>,
    receipt_outbox: Vec<ReceiptOutboxEntry>,
}

#[derive(Debug, Serialize)]
pub struct ReceiptOutboxStatus {
    pending: usize,
    oldest_event_id: Option<String>,
    acknowledged_receipts: usize,
    integrity_scope: &'static str,
}

impl ReceiptOutboxStatus {
    pub fn pending(&self) -> usize {
        self.pending
    }

    pub fn acknowledged_receipts(&self) -> usize {
        self.acknowledged_receipts
    }
}

#[derive(Debug, Serialize)]
pub struct ReceiptReconciliation {
    pending_before: usize,
    appended: usize,
    existing: usize,
    pending_after: usize,
}

impl ReceiptReconciliation {
    pub fn pending_before(&self) -> usize {
        self.pending_before
    }

    pub fn appended(&self) -> usize {
        self.appended
    }

    pub fn existing(&self) -> usize {
        self.existing
    }

    pub fn pending_after(&self) -> usize {
        self.pending_after
    }

    pub fn acknowledged(&self) -> usize {
        self.appended + self.existing
    }
}

#[derive(Debug, Serialize)]
pub struct DecisionReceiptVerification {
    valid: bool,
    acknowledged_receipts: usize,
    ledger_entries: usize,
    integrity_scope: &'static str,
}

mod receipt_binding;
pub use receipt_binding::{
    flush_receipt_outbox, receipt_outbox_status, reconcile_receipt_outbox, verify_decision_receipts,
};

impl Default for SafetyState {
    fn default() -> Self {
        Self {
            schema_version: SAFETY_STATE_SCHEMA_VERSION,
            queue: Vec::new(),
            history: Vec::new(),
            receipt_outbox: Vec::new(),
        }
    }
}

impl SafetySystem {
    /// Create a safety handle. Durable state is loaded under an interprocess
    /// lock for each operation so live and file-based callers cannot diverge.
    pub fn new() -> Self {
        let system = SafetySystem {
            actions: Mutex::new(Vec::new()),
        };
        if let Err(error) = flush_receipt_outbox() {
            crate::logging::warn(&format!(
                "Safety decision receipt reconciliation remains pending: {}",
                error
            ));
        }
        system
    }

    /// Classify an action name into a tier.
    pub fn classify(&self, action: &str) -> ActionTier {
        let lower = action.to_lowercase();
        if AUTO_ALLOWED.iter().any(|&a| a == lower) {
            ActionTier::AutoAllowed
        } else {
            ActionTier::RequiresPermission
        }
    }

    /// Submit a permission request. Returns `Queued` with the request id.
    pub fn request_permission(&self, request: PermissionRequest) -> Result<PermissionResult> {
        validate_request_id(&request.id)?;
        let request_id = request.id.clone();
        let action = request.action.clone();
        let description = request.description.clone();
        mutate_state(|state| {
            if state.queue.iter().any(|pending| pending.id == request_id)
                || state
                    .history
                    .iter()
                    .any(|decision| decision.request_id == request_id)
            {
                bail!("SAFETY_PERMISSION_REQUEST_ID_COLLISION: {}", request_id)
            }
            state.queue.push(request);
            Ok(())
        })?;
        // Send high-priority notification for permission request via the
        // registered dispatcher (inverts the safety -> notifications edge).
        dispatch_permission_notification(&action, &description, &request_id);
        Ok(PermissionResult::Queued { request_id })
    }

    /// Expire pending permission requests that can no longer be serviced
    /// because their originating session is no longer active.
    pub fn expire_dead_session_requests(&self, via: &str) -> Result<Vec<String>> {
        validate_decision_via(via)?;
        let expired = mutate_state(|state| {
            let mut expired = Vec::new();
            let mut retained = Vec::with_capacity(state.queue.len());
            for req in state.queue.drain(..) {
                if let Some(reason) = stale_request_reason(&req) {
                    let message = Some(format!(
                        "Expired automatically: {}. Original agent is no longer active.",
                        reason
                    ));
                    let (decision, outbox) =
                        build_decision_transition(&req, DecisionOutcome::Expired, via, message)?;
                    expired.push(req.id.clone());
                    state.history.push(decision);
                    state.receipt_outbox.push(outbox);
                } else {
                    retained.push(req);
                }
            }
            state.queue = retained;
            Ok(expired)
        })?;
        if !expired.is_empty() {
            flush_receipt_outbox().with_context(|| {
                format!(
                    "SAFETY_DECISIONS_COMMITTED_RECEIPTS_PENDING: {} expired decision(s)",
                    expired.len()
                )
            })?;
        }
        Ok(expired)
    }

    /// Record a user decision (approve / deny) for a pending request.
    pub fn record_decision(
        &self,
        request_id: &str,
        approved: bool,
        via: &str,
        message: Option<String>,
    ) -> Result<Decision> {
        let outcome = if approved {
            DecisionOutcome::Approved
        } else {
            DecisionOutcome::Denied
        };
        commit_decision_transition(request_id, outcome, via, message)
    }

    /// Return all pending permission requests.
    pub fn pending_requests(&self) -> Result<Vec<PermissionRequest>> {
        read_state(|state| Ok(state.queue.clone()))
    }

    /// Append an action to the in-memory log.
    pub fn log_action(&self, log: ActionLog) {
        if let Ok(mut actions) = self.actions.lock() {
            actions.push(log);
        }
    }

    /// Generate a human-readable summary of logged actions.
    pub fn generate_summary(&self) -> Result<String> {
        let actions = self
            .actions
            .lock()
            .map_err(|_| anyhow::anyhow!("SAFETY_ACTION_LOG_LOCK_POISONED"))?
            .clone();
        let pending = self.pending_requests()?;

        let mut lines: Vec<String> = Vec::new();

        if actions.is_empty() && pending.is_empty() {
            return Ok("No actions recorded.".to_string());
        }

        // Separate auto vs permission-required
        let auto: Vec<&ActionLog> = actions
            .iter()
            .filter(|a| a.tier == ActionTier::AutoAllowed)
            .collect();
        let perm: Vec<&ActionLog> = actions
            .iter()
            .filter(|a| a.tier == ActionTier::RequiresPermission)
            .collect();

        if !auto.is_empty() {
            lines.push("Done (auto-allowed):".to_string());
            for a in &auto {
                lines.push(format!("- {} — {}", a.action_type, a.description));
            }
        }

        if !perm.is_empty() {
            lines.push(String::new());
            lines.push("Done (with permission):".to_string());
            for a in &perm {
                lines.push(format!("- {} — {}", a.action_type, a.description));
            }
        }

        if !pending.is_empty() {
            lines.push(String::new());
            lines.push("Needs your review:".to_string());
            for r in &pending {
                lines.push(format!(
                    "- [{:?}] {} — {}",
                    r.urgency, r.action, r.description
                ));
            }
        }

        Ok(lines.join("\n"))
    }

    /// Persist a transcript to ~/.jcode/ambient/transcripts/{timestamp}.json
    pub fn save_transcript(&self, transcript: &AmbientTranscript) -> Result<()> {
        let dir = storage::jcode_dir()?.join("ambient").join("transcripts");
        storage::ensure_dir(&dir)?;

        let filename = transcript.started_at.format("%Y-%m-%d-%H%M%S").to_string();
        let path = dir.join(format!("{}.json", filename));
        storage::write_json(&path, transcript)
    }
}

impl Default for SafetySystem {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Persistence helpers
// ---------------------------------------------------------------------------

fn safety_dir() -> Result<PathBuf> {
    let directory = storage::jcode_dir()?.join("safety");
    if !directory.is_absolute() {
        bail!("SAFETY_STATE_ROOT_NOT_ABSOLUTE")
    }
    Ok(directory)
}

fn state_path() -> Result<PathBuf> {
    Ok(safety_dir()?.join("state.v1.json"))
}

fn state_lock_path() -> Result<PathBuf> {
    Ok(safety_dir()?.join("state.v1.lock"))
}

fn state_initialization_marker_path() -> Result<PathBuf> {
    Ok(safety_dir()?.join("state.v1.initialized"))
}

fn queue_path() -> Result<PathBuf> {
    Ok(storage::jcode_dir()?.join("safety").join("queue.json"))
}

fn history_path() -> Result<PathBuf> {
    Ok(storage::jcode_dir()?.join("safety").join("history.json"))
}

fn validate_request_id(request_id: &str) -> Result<()> {
    if request_id.trim().is_empty()
        || request_id.len() > 256
        || request_id.contains('\n')
        || request_id.contains('\r')
    {
        bail!("SAFETY_INVALID_REQUEST_ID")
    }
    Ok(())
}

fn validate_decision_via(via: &str) -> Result<()> {
    if via.trim().is_empty() || via.len() > 128 || via.contains('\n') || via.contains('\r') {
        bail!("SAFETY_INVALID_DECISION_VIA")
    }
    Ok(())
}

fn validate_decision_message(message: Option<&str>) -> Result<()> {
    if let Some(message) = message
        && (message.len() > 4096 || message.contains('\0'))
    {
        bail!("SAFETY_INVALID_DECISION_MESSAGE")
    }
    Ok(())
}

fn inspect_regular_file_or_missing(path: &Path, code: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!("{}_SYMLINK_REFUSED: {}", code, path.display())
        }
        Ok(metadata) if !metadata.is_file() => {
            bail!("{}_NOT_REGULAR_FILE: {}", code, path.display())
        }
        Ok(_) => crate::omnis::validate_private_file(path, code),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspect {}", path.display())),
    }
}

fn acquire_state_lock() -> Result<File> {
    let directory = safety_dir()?;
    crate::omnis::validate_existing_directory_ancestor(&directory)?;
    match fs::symlink_metadata(&directory) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!(
                "SAFETY_STATE_DIRECTORY_SYMLINK_REFUSED: {}",
                directory.display()
            )
        }
        Ok(metadata) if !metadata.is_dir() => {
            bail!(
                "SAFETY_STATE_DIRECTORY_NOT_DIRECTORY: {}",
                directory.display()
            )
        }
        Ok(_) => crate::omnis::validate_private_directory(&directory, "SAFETY_STATE_DIRECTORY")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(unix)]
            {
                let mut builder = fs::DirBuilder::new();
                builder.recursive(true).mode(0o700);
                builder.create(&directory)?;
            }
            #[cfg(not(unix))]
            storage::ensure_dir(&directory)?;
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!("inspect safety state directory {}", directory.display())
            });
        }
    }
    crate::omnis::validate_private_directory(&directory, "SAFETY_STATE_DIRECTORY")?;
    let path = state_lock_path()?;
    inspect_regular_file_or_missing(&path, "SAFETY_STATE_LOCK")?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    options
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(0o600);
    let file = options
        .open(&path)
        .with_context(|| format!("open safety state lock {}", path.display()))?;
    if !file.metadata()?.is_file() {
        bail!("SAFETY_STATE_LOCK_NOT_REGULAR_FILE: {}", path.display())
    }
    crate::omnis::validate_private_file(&path, "SAFETY_STATE_LOCK")?;
    file.lock()
        .with_context(|| format!("SAFETY_STATE_LOCK_UNAVAILABLE: {}", path.display()))?;
    Ok(file)
}

fn read_json_strict<T: serde::de::DeserializeOwned>(path: &Path, code: &str) -> Result<T> {
    inspect_regular_file_or_missing(path, code)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options
        .open(path)
        .with_context(|| format!("{}_READ_FAILED: {}", code, path.display()))?;
    if !file.metadata()?.is_file() {
        bail!("{}_NOT_REGULAR_FILE: {}", code, path.display())
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .with_context(|| format!("{}_READ_FAILED: {}", code, path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("{}_INVALID_JSON: {}", code, path.display()))
}

fn publish_initialization_marker() -> Result<()> {
    let path = state_initialization_marker_path()?;
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!("SAFETY_STATE_MARKER_SYMLINK_REFUSED: {}", path.display())
        }
        Ok(metadata) if !metadata.is_file() => {
            bail!("SAFETY_STATE_MARKER_NOT_REGULAR_FILE: {}", path.display())
        }
        Ok(_) => {
            crate::omnis::validate_private_file(&path, "SAFETY_STATE_MARKER")?;
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect safety state marker {}", path.display()));
        }
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(0o600);
    let mut file = options
        .open(&path)
        .with_context(|| format!("create safety state marker {}", path.display()))?;
    crate::omnis::validate_private_file(&path, "SAFETY_STATE_MARKER")?;
    file.write_all(b"jourdanlabs.safety-state.initialized.v1\n")?;
    file.sync_all()?;
    #[cfg(unix)]
    File::open(
        path.parent()
            .context("SAFETY_STATE_MARKER_MISSING_PARENT")?,
    )?
    .sync_all()
    .context("SAFETY_STATE_MARKER_DIRECTORY_SYNC_FAILED")?;
    Ok(())
}

fn validate_state(state: &SafetyState) -> Result<()> {
    if state.schema_version != SAFETY_STATE_SCHEMA_VERSION {
        bail!(
            "SAFETY_STATE_SCHEMA_MISMATCH: expected {}, found {}",
            SAFETY_STATE_SCHEMA_VERSION,
            state.schema_version
        )
    }

    let mut request_ids = std::collections::HashSet::new();
    for request in &state.queue {
        validate_request_id(&request.id)?;
        if !request_ids.insert(request.id.as_str()) {
            bail!("SAFETY_STATE_DUPLICATE_PENDING_REQUEST: {}", request.id)
        }
    }
    let mut decision_ids = std::collections::HashSet::new();
    for decision in &state.history {
        validate_request_id(&decision.request_id)?;
        if !request_ids.insert(decision.request_id.as_str()) {
            bail!(
                "SAFETY_STATE_DUPLICATE_OR_NONTERMINAL_REQUEST: {}",
                decision.request_id
            )
        }
        let new_field_count = usize::from(decision.decision_id.is_some())
            + usize::from(decision.request.is_some())
            + usize::from(decision.outcome.is_some())
            + usize::from(decision.omnis_evidence_sha256.is_some());
        if new_field_count != 0 && new_field_count != 4 {
            bail!(
                "SAFETY_STATE_PARTIAL_BOUND_DECISION: {}",
                decision.request_id
            )
        }
        if let Some(decision_id) = decision.decision_id.as_deref() {
            if !decision_ids.insert(decision_id) {
                bail!("SAFETY_STATE_DUPLICATE_DECISION_ID: {}", decision_id)
            }
        } else if decision.omnis_receipt_hash.is_some() {
            bail!(
                "SAFETY_STATE_LEGACY_DECISION_HAS_RECEIPT: {}",
                decision.request_id
            )
        }
        if let Some(request) = decision.request.as_ref()
            && request.id != decision.request_id
        {
            bail!(
                "SAFETY_STATE_DECISION_REQUEST_MISMATCH: {}",
                decision.request_id
            )
        }
        if let Some(outcome) = decision.outcome {
            let expected_approved = outcome == DecisionOutcome::Approved;
            if decision.approved != expected_approved {
                bail!(
                    "SAFETY_STATE_DECISION_OUTCOME_MISMATCH: {}",
                    decision.request_id
                )
            }
        }
        if let Some(receipt_hash) = decision.omnis_receipt_hash.as_deref() {
            let raw = receipt_hash.strip_prefix("sha256:").unwrap_or("");
            if raw.len() != 64 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                bail!("SAFETY_STATE_INVALID_RECEIPT_HASH: {}", decision.request_id)
            }
        }
        if let (Some(request), Some(evidence_sha256)) = (
            decision.request.as_ref(),
            decision.omnis_evidence_sha256.as_deref(),
        ) && decision_evidence_digest(request, decision)? != evidence_sha256
        {
            bail!(
                "SAFETY_STATE_DECISION_EVIDENCE_DRIFT: {}",
                decision.request_id
            )
        }
    }
    let mut event_ids = std::collections::HashSet::new();
    let mut outbox_decision_ids = std::collections::HashSet::new();
    for outbox in &state.receipt_outbox {
        if !event_ids.insert(outbox.event_id.as_str()) {
            bail!("SAFETY_STATE_DUPLICATE_OUTBOX_EVENT: {}", outbox.event_id)
        }
        let Some(decision) = state
            .history
            .iter()
            .find(|decision| decision.decision_id.as_deref() == Some(&outbox.decision_id))
        else {
            bail!("SAFETY_STATE_ORPHANED_OUTBOX_EVENT: {}", outbox.event_id)
        };
        if decision.omnis_receipt_hash.is_some() {
            bail!(
                "SAFETY_STATE_ACKNOWLEDGED_DECISION_STILL_IN_OUTBOX: {}",
                outbox.decision_id
            )
        }
        outbox_decision_ids.insert(outbox.decision_id.as_str());
        let request = decision
            .request
            .as_ref()
            .context("SAFETY_STATE_OUTBOX_REQUEST_MISSING")?;
        let expected = outbox_for_decision(request, decision)?;
        if &expected != outbox {
            bail!("SAFETY_STATE_OUTBOX_BINDING_MISMATCH: {}", outbox.event_id)
        }
    }
    for decision in &state.history {
        let Some(decision_id) = decision.decision_id.as_deref() else {
            continue;
        };
        match (
            decision.omnis_receipt_hash.is_some(),
            outbox_decision_ids.contains(decision_id),
        ) {
            (true, false) | (false, true) => {}
            (false, false) => {
                bail!("SAFETY_STATE_DECISION_MISSING_OUTBOX: {}", decision_id)
            }
            (true, true) => {
                bail!(
                    "SAFETY_STATE_DECISION_HAS_RECEIPT_AND_OUTBOX: {}",
                    decision_id
                )
            }
        }
    }
    Ok(())
}

fn persist_state(state: &SafetyState) -> Result<()> {
    validate_state(state)?;
    let path = state_path()?;
    inspect_regular_file_or_missing(&path, "SAFETY_STATE")?;
    let bytes = serde_json::to_vec(state)?;

    #[cfg(unix)]
    {
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
            let mut file = options
                .open(&temporary)
                .with_context(|| format!("create safety state temp {}", temporary.display()))?;
            crate::omnis::validate_private_file(&temporary, "SAFETY_STATE_TEMP")?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            let mode = file.metadata()?.permissions().mode() & 0o777;
            if mode != 0o600 {
                bail!(
                    "SAFETY_STATE_TEMP_MODE_MISMATCH: {} has {:o}",
                    temporary.display(),
                    mode
                )
            }
            fs::rename(&temporary, &path).with_context(|| {
                format!(
                    "atomically publish safety state {} -> {}",
                    temporary.display(),
                    path.display()
                )
            })?;
            File::open(
                path.parent()
                    .context("SAFETY_STATE_PATH_MISSING_PARENT_AFTER_WRITE")?,
            )?
            .sync_all()
            .context("SAFETY_STATE_DIRECTORY_SYNC_FAILED")?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result.context("SAFETY_STATE_WRITE_FAILED")
    }

    #[cfg(not(unix))]
    storage::write_json_secret(&path, state).context("SAFETY_STATE_WRITE_FAILED")
}

fn load_state_locked() -> Result<SafetyState> {
    let path = state_path()?;
    if path.exists() {
        let state: SafetyState = read_json_strict(&path, "SAFETY_STATE")?;
        validate_state(&state)?;
        publish_initialization_marker()?;
        return Ok(state);
    }
    let backup = path.with_extension("bak");
    let marker = state_initialization_marker_path()?;
    if backup.exists() || marker.exists() {
        bail!(
            "SAFETY_STATE_RECOVERY_REQUIRED: primary {} missing while prior-state witness exists",
            path.display()
        )
    }

    let queue_path = queue_path()?;
    let history_path = history_path()?;
    let queue = if queue_path.exists() {
        read_json_strict(&queue_path, "SAFETY_LEGACY_QUEUE")?
    } else {
        Vec::new()
    };
    let history = if history_path.exists() {
        read_json_strict(&history_path, "SAFETY_LEGACY_HISTORY")?
    } else {
        Vec::new()
    };
    let state = SafetyState {
        schema_version: SAFETY_STATE_SCHEMA_VERSION,
        queue,
        history,
        receipt_outbox: Vec::new(),
    };
    validate_state(&state)?;
    persist_state(&state)?;
    publish_initialization_marker()?;
    Ok(state)
}

fn read_state<T>(read: impl FnOnce(&SafetyState) -> Result<T>) -> Result<T> {
    let _lock = acquire_state_lock()?;
    let state = load_state_locked()?;
    read(&state)
}

fn mutate_state<T>(mutate: impl FnOnce(&mut SafetyState) -> Result<T>) -> Result<T> {
    let _lock = acquire_state_lock()?;
    let mut state = load_state_locked()?;
    let result = mutate(&mut state)?;
    persist_state(&state)?;
    Ok(result)
}

fn canonicalize_json(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(canonicalize_json).collect())
        }
        serde_json::Value::Object(values) => {
            let mut entries: Vec<_> = values.into_iter().collect();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            let mut canonical = serde_json::Map::new();
            for (key, value) in entries {
                canonical.insert(key, canonicalize_json(value));
            }
            serde_json::Value::Object(canonical)
        }
        scalar => scalar,
    }
}

fn decision_evidence_digest(request: &PermissionRequest, decision: &Decision) -> Result<String> {
    let value = serde_json::json!({
        "protocol": SAFETY_EVIDENCE_PROTOCOL,
        "request": request,
        "decision": {
            "decision_id": decision.decision_id,
            "request_id": decision.request_id,
            "approved": decision.approved,
            "outcome": decision.outcome,
            "decided_at": decision.decided_at,
            "decided_via": decision.decided_via,
            "message": decision.message,
        }
    });
    let bytes = serde_json::to_vec(&canonicalize_json(value))?;
    let mut digest = Sha256::new();
    digest.update((SAFETY_EVIDENCE_PROTOCOL.len() as u64).to_be_bytes());
    digest.update(SAFETY_EVIDENCE_PROTOCOL.as_bytes());
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    Ok(format!("sha256:{}", hex::encode(digest.finalize())))
}

fn build_decision_transition(
    request: &PermissionRequest,
    outcome: DecisionOutcome,
    via: &str,
    message: Option<String>,
) -> Result<(Decision, ReceiptOutboxEntry)> {
    validate_decision_via(via)?;
    validate_decision_message(message.as_deref())?;
    let decision_id = crate::id::new_id("decision");
    let mut decision = Decision {
        decision_id: Some(decision_id.clone()),
        request_id: request.id.clone(),
        request: Some(request.clone()),
        approved: outcome == DecisionOutcome::Approved,
        outcome: Some(outcome),
        decided_at: Utc::now(),
        decided_via: via.to_string(),
        message,
        omnis_evidence_sha256: None,
        omnis_receipt_hash: None,
    };
    decision.omnis_evidence_sha256 = Some(decision_evidence_digest(request, &decision)?);
    let outbox = outbox_for_decision(request, &decision)?;
    Ok((decision, outbox))
}

fn outbox_for_decision(
    request: &PermissionRequest,
    decision: &Decision,
) -> Result<ReceiptOutboxEntry> {
    let decision_id = decision
        .decision_id
        .as_deref()
        .context("SAFETY_DECISION_ID_MISSING")?;
    let outcome = decision
        .outcome
        .context("SAFETY_DECISION_OUTCOME_MISSING")?;
    let kind = match outcome {
        DecisionOutcome::Approved => "safety.permission.approved",
        DecisionOutcome::Denied => "safety.permission.denied",
        DecisionOutcome::Expired => "safety.permission.expired",
    };
    let evidence_sha256 = decision
        .omnis_evidence_sha256
        .as_deref()
        .context("SAFETY_DECISION_EVIDENCE_MISSING")?;
    if decision_evidence_digest(request, decision)? != evidence_sha256 {
        bail!("SAFETY_DECISION_EVIDENCE_DRIFT")
    }
    Ok(ReceiptOutboxEntry {
        event_id: format!("safety-decision:{}", decision_id),
        decision_id: decision_id.to_string(),
        kind: kind.to_string(),
        subject: format!(
            "request={} decision={} observation=local-terminal-decision",
            request.id, decision_id
        ),
        evidence_sha256: evidence_sha256.to_string(),
    })
}

fn commit_decision_transition(
    request_id: &str,
    outcome: DecisionOutcome,
    via: &str,
    message: Option<String>,
) -> Result<Decision> {
    validate_request_id(request_id)?;
    validate_decision_via(via)?;
    validate_decision_message(message.as_deref())?;
    let decision = mutate_state(|state| {
        if state
            .history
            .iter()
            .any(|decision| decision.request_id == request_id)
        {
            bail!("SAFETY_PERMISSION_ALREADY_FINAL: {}", request_id)
        }
        let Some(position) = state
            .queue
            .iter()
            .position(|request| request.id == request_id)
        else {
            bail!("SAFETY_PERMISSION_REQUEST_NOT_FOUND: {}", request_id)
        };
        let request = state.queue.remove(position);
        let (decision, outbox) = build_decision_transition(&request, outcome, via, message)?;
        state.history.push(decision.clone());
        state.receipt_outbox.push(outbox);
        Ok(decision)
    })?;
    flush_receipt_outbox()
        .with_context(|| format!("SAFETY_DECISION_COMMITTED_RECEIPT_PENDING: {}", request_id))?;
    read_state(|state| {
        state
            .history
            .iter()
            .find(|candidate| candidate.decision_id == decision.decision_id)
            .cloned()
            .context("SAFETY_DECISION_MISSING_AFTER_RECEIPT_ACK")
    })
}

// ---------------------------------------------------------------------------
// File-based permission decision (for IMAP poller / external callers)
// ---------------------------------------------------------------------------

/// Record a permission decision through the same atomic state transition used
/// by the live SafetySystem.
pub fn record_permission_via_file(
    request_id: &str,
    approved: bool,
    via: &str,
    message: Option<String>,
) -> Result<Decision> {
    let outcome = if approved {
        DecisionOutcome::Approved
    } else {
        DecisionOutcome::Denied
    };
    commit_decision_transition(request_id, outcome, via, message)
}

/// Expire stale permission requests through the canonical transition.
pub fn expire_stale_permissions_via_file(via: &str) -> Result<Vec<String>> {
    SafetySystem::new().expire_dead_session_requests(via)
}

fn stale_request_reason(request: &PermissionRequest) -> Option<String> {
    let session_id = request_session_id(request)?;
    let mut session = match crate::session::Session::load(&session_id) {
        Ok(s) => s,
        Err(_) => return Some(format!("owner session '{}' was not found", session_id)),
    };

    // Refresh crash status based on PID if needed.
    if session.detect_crash() {
        let _ = session.save();
    }

    if session.status == crate::session::SessionStatus::Active {
        None
    } else {
        Some(format!(
            "owner session '{}' is {}",
            session_id,
            session.status.display()
        ))
    }
}

fn request_session_id(request: &PermissionRequest) -> Option<String> {
    let context = request.context.as_ref()?;

    context
        .get("session_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            context
                .get("requester")
                .and_then(|r| r.get("session_id"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
}

// ---------------------------------------------------------------------------
// ID generation helper
// ---------------------------------------------------------------------------

/// Generate a unique permission request id: `req_{timestamp}_{random}`
pub fn new_request_id() -> String {
    crate::id::new_id("req")
}

#[cfg(test)]
#[path = "safety/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "safety/adversarial_tests.rs"]
mod adversarial_tests;
