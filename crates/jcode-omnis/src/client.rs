use crate::model::AnchorRequest;
use crate::protocol::{Request, Response, Success, read_frame, write_frame};
use anyhow::{Context, Result, bail};
use std::net::Shutdown;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(unix)]
use std::fs;
#[cfg(target_os = "macos")]
use std::fs::OpenOptions;
#[cfg(target_os = "macos")]
use std::io::Read;
#[cfg(target_os = "macos")]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::net::UnixStream;

const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
pub struct CheckpointClient {
    socket_path: PathBuf,
    expected_server_uid: u32,
    expected_server_gid: u32,
    io_timeout: Duration,
    trusted_public_key: Option<Vec<u8>>,
    allowed_ledger_id: Option<String>,
    receipt_ledger_path: Option<PathBuf>,
    activated_client_uid: Option<u32>,
}

impl CheckpointClient {
    #[cfg(test)]
    pub(crate) fn new(
        socket_path: impl Into<PathBuf>,
        expected_server_uid: u32,
        expected_server_gid: u32,
    ) -> Result<Self> {
        if expected_server_uid == 0 || expected_server_gid == 0 {
            bail!("OMNIS_CLIENT_SERVER_IDENTITY_ZERO_REFUSED")
        }
        Ok(Self {
            socket_path: socket_path.into(),
            expected_server_uid,
            expected_server_gid,
            io_timeout: DEFAULT_IO_TIMEOUT,
            trusted_public_key: None,
            allowed_ledger_id: None,
            receipt_ledger_path: None,
            activated_client_uid: None,
        })
    }

    pub fn production() -> Result<Self> {
        #[cfg(not(target_os = "macos"))]
        bail!("OMNIS_CHECKPOINT_AUTHORITY_UNSUPPORTED_PLATFORM");

        #[cfg(target_os = "macos")]
        {
            let config = crate::daemon::DaemonConfig::production()?;
            let activation_bytes =
                read_root_owned_file(&config.activation_path, 1024 * 1024, "ACTIVATION")?;
            let activation: crate::daemon::ActivationManifest =
                serde_json::from_slice(&activation_bytes)
                    .context("OMNIS_ACTIVATION_INVALID_JSON")?;
            crate::daemon::validate_activation_contract(&config, &activation)?;
            if activation.allowed_client_uid != unsafe { libc::geteuid() } {
                bail!("OMNIS_CLIENT_ACTIVATED_UID_MISMATCH")
            }
            let trust_bytes =
                read_root_owned_file(&config.trust_public_key_path, 4096, "TRUST_PUBLIC_KEY")?;
            let trusted_public_key = crate::crypto::parse_public_key(&trust_bytes)?;
            Ok(Self {
                socket_path: config.socket_path,
                expected_server_uid: activation.service_uid,
                expected_server_gid: activation.service_primary_gid,
                io_timeout: DEFAULT_IO_TIMEOUT,
                trusted_public_key: Some(trusted_public_key),
                allowed_ledger_id: Some(activation.allowed_ledger_id),
                receipt_ledger_path: Some(PathBuf::from(activation.receipt_ledger_path)),
                activated_client_uid: Some(activation.allowed_client_uid),
            })
        }
    }

    pub fn trust_public_key(&self) -> Result<&[u8]> {
        self.trusted_public_key
            .as_deref()
            .context("OMNIS_CLIENT_TRUST_NOT_LOADED")
    }

    pub fn allowed_ledger_id(&self) -> Result<&str> {
        self.allowed_ledger_id
            .as_deref()
            .context("OMNIS_CLIENT_LEDGER_AUTHORITY_NOT_LOADED")
    }

    pub fn receipt_ledger_path(&self) -> Result<&Path> {
        self.receipt_ledger_path
            .as_deref()
            .context("OMNIS_CLIENT_RECEIPT_LEDGER_AUTHORITY_NOT_LOADED")
    }

    pub fn validate_receipt_ledger_boundary(&self) -> Result<()> {
        #[cfg(not(target_os = "macos"))]
        bail!("OMNIS_CHECKPOINT_AUTHORITY_UNSUPPORTED_PLATFORM");

        #[cfg(target_os = "macos")]
        {
            let path = self.receipt_ledger_path()?;
            let activated_client_uid = self
                .activated_client_uid
                .context("OMNIS_CLIENT_ACTIVATED_UID_NOT_LOADED")?;
            crate::daemon::assert_no_symlink_components(path)?;
            let metadata = fs::symlink_metadata(path)
                .with_context(|| format!("inspect activated receipt ledger {}", path.display()))?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                bail!("OMNIS_CLIENT_RECEIPT_LEDGER_TYPE_REFUSED")
            }
            if metadata.uid() != activated_client_uid
                || metadata.permissions().mode() & 0o7777 != 0o600
            {
                bail!("OMNIS_CLIENT_RECEIPT_LEDGER_IDENTITY_OR_MODE_DRIFT")
            }
            crate::daemon::assert_no_extended_acl(path)?;

            let parent = path
                .parent()
                .context("OMNIS_CLIENT_RECEIPT_LEDGER_PARENT_MISSING")?;
            let parent_metadata = fs::symlink_metadata(parent)?;
            if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
                bail!("OMNIS_CLIENT_RECEIPT_LEDGER_PARENT_TYPE_REFUSED")
            }
            if parent_metadata.uid() != activated_client_uid
                || parent_metadata.permissions().mode() & 0o7777 != 0o700
            {
                bail!("OMNIS_CLIENT_RECEIPT_LEDGER_PARENT_IDENTITY_OR_MODE_DRIFT")
            }
            crate::daemon::assert_no_extended_acl(parent)?;
            Ok(())
        }
    }

    pub fn status(&self, request_id: impl Into<String>) -> Result<Success> {
        self.exchange(Request::status(request_id.into())?)
    }

    pub fn lookup(
        &self,
        request_id: impl Into<String>,
    ) -> Result<Option<crate::model::SignedCheckpoint>> {
        let request = Request::lookup(request_id)?;
        request.validate_envelope()?;
        let expected_request_id = request.request_id().to_string();
        let response = self.exchange_response(&request)?;
        if response.protocol() != crate::protocol::IPC_PROTOCOL {
            bail!("OMNIS_CLIENT_PROTOCOL_MISMATCH")
        }
        match response {
            Response::LookupOk {
                request_id,
                checkpoint,
                ..
            } => {
                if request_id != expected_request_id {
                    bail!("OMNIS_CLIENT_RESPONSE_REQUEST_ID_MISMATCH")
                }
                let checkpoint = checkpoint.map(|value| *value);
                self.validate_trusted_lookup(&expected_request_id, checkpoint.as_ref())?;
                Ok(checkpoint)
            }
            Response::Ok { .. } => bail!("OMNIS_CHECKPOINT_LOOKUP_OPERATION_MISMATCH"),
            Response::Error {
                request_id, error, ..
            } => {
                if request_id
                    .as_deref()
                    .is_some_and(|id| id != expected_request_id)
                {
                    bail!("OMNIS_CLIENT_ERROR_REQUEST_ID_MISMATCH")
                }
                bail!("{}: {}", error.code, error.message)
            }
        }
    }

    pub fn anchor(&self, request: AnchorRequest) -> Result<Success> {
        if self
            .allowed_ledger_id
            .as_deref()
            .is_some_and(|allowed| request.ledger_id != allowed)
        {
            bail!("OMNIS_CLIENT_LEDGER_ID_REFUSED")
        }
        if self
            .receipt_ledger_path
            .as_deref()
            .is_some_and(|allowed| Path::new(&request.receipt_ledger_path) != allowed)
        {
            bail!("OMNIS_CLIENT_RECEIPT_LEDGER_PATH_REFUSED")
        }
        self.exchange(Request::anchor(request))
    }

    fn exchange(&self, request: Request) -> Result<Success> {
        request.validate_envelope()?;
        let request_id = request.request_id().to_string();
        let response = self.exchange_response(&request)?;
        if response.protocol() != crate::protocol::IPC_PROTOCOL {
            bail!("OMNIS_CLIENT_PROTOCOL_MISMATCH")
        }
        match response {
            Response::Ok {
                request_id: response_id,
                result,
                ..
            } => {
                if response_id != request_id {
                    bail!("OMNIS_CLIENT_RESPONSE_REQUEST_ID_MISMATCH")
                }
                self.validate_trusted_success(&request, &result)?;
                Ok(*result)
            }
            Response::LookupOk { .. } => bail!("OMNIS_CLIENT_RESPONSE_OPERATION_MISMATCH"),
            Response::Error {
                request_id: response_id,
                error,
                ..
            } => {
                if response_id.as_deref().is_some_and(|id| id != request_id) {
                    bail!("OMNIS_CLIENT_ERROR_REQUEST_ID_MISMATCH")
                }
                bail!("{}: {}", error.code, error.message)
            }
        }
    }

    fn validate_trusted_success(&self, request: &Request, result: &Success) -> Result<()> {
        if !matches!(
            (request, result),
            (Request::Status { .. }, Success::Status { .. })
                | (Request::Anchor { .. }, Success::Anchor { .. })
        ) {
            bail!("OMNIS_CLIENT_RESPONSE_OPERATION_MISMATCH")
        }
        let (
            Some(public_key),
            Some(allowed_ledger_id),
            Some(receipt_ledger_path),
            Some(activated_client_uid),
        ) = (
            self.trusted_public_key.as_deref(),
            self.allowed_ledger_id.as_deref(),
            self.receipt_ledger_path.as_deref(),
            self.activated_client_uid,
        )
        else {
            return Ok(());
        };
        match result {
            Success::Status {
                authority_id,
                ledger_id,
                receipt_ledger_path: response_ledger_path,
                signing_key_id,
                latest,
            } => {
                if authority_id != crate::daemon::AUTHORITY_ID {
                    bail!("OMNIS_CLIENT_AUTHORITY_ID_MISMATCH")
                }
                if ledger_id != allowed_ledger_id {
                    bail!("OMNIS_CLIENT_LEDGER_ID_MISMATCH")
                }
                if Path::new(response_ledger_path) != receipt_ledger_path {
                    bail!("OMNIS_CLIENT_RECEIPT_LEDGER_PATH_MISMATCH")
                }
                if signing_key_id != &crate::crypto::signing_key_id(public_key) {
                    bail!("OMNIS_CLIENT_SIGNING_KEY_ID_MISMATCH")
                }
                if let Some(checkpoint) = latest {
                    validate_checkpoint_authority(
                        checkpoint,
                        allowed_ledger_id,
                        receipt_ledger_path,
                        activated_client_uid,
                    )?;
                    crate::crypto::verify_checkpoint(checkpoint, public_key)?;
                }
            }
            Success::Anchor { checkpoint, .. } => {
                let Request::Anchor {
                    request: anchor_request,
                    ..
                } = request
                else {
                    unreachable!("operation match checked above")
                };
                validate_checkpoint_authority(
                    checkpoint,
                    allowed_ledger_id,
                    receipt_ledger_path,
                    activated_client_uid,
                )?;
                if checkpoint.record.request_id != anchor_request.request_id
                    || checkpoint.record.request_digest
                        != crate::crypto::request_digest(anchor_request)?
                    || checkpoint.record.parent_checkpoint_hash
                        != anchor_request.prior_checkpoint_hash
                    || checkpoint.record.observed_receipt_sequence
                        != anchor_request.observed_receipt_sequence
                    || checkpoint.record.observed_receipt_head
                        != anchor_request.observed_receipt_head
                {
                    bail!("OMNIS_CLIENT_ANCHOR_RESPONSE_BINDING_MISMATCH")
                }
                crate::crypto::verify_checkpoint(checkpoint, public_key)?;
            }
        }
        Ok(())
    }

    fn validate_trusted_lookup(
        &self,
        request_id: &str,
        checkpoint: Option<&crate::model::SignedCheckpoint>,
    ) -> Result<()> {
        let public_key = self.trust_public_key()?;
        let allowed_ledger_id = self.allowed_ledger_id()?;
        let receipt_ledger_path = self.receipt_ledger_path()?;
        let activated_client_uid = self
            .activated_client_uid
            .context("OMNIS_CLIENT_ACTIVATED_UID_NOT_LOADED")?;
        if let Some(checkpoint) = checkpoint {
            validate_checkpoint_authority(
                checkpoint,
                allowed_ledger_id,
                receipt_ledger_path,
                activated_client_uid,
            )?;
            if checkpoint.record.request_id != request_id {
                bail!("OMNIS_CLIENT_LOOKUP_REQUEST_ID_MISMATCH")
            }
            crate::crypto::verify_checkpoint(checkpoint, public_key)?;
        }
        Ok(())
    }

    #[cfg(unix)]
    fn exchange_response(&self, request: &Request) -> Result<Response> {
        assert_socket_leaf(
            &self.socket_path,
            self.expected_server_uid,
            self.expected_server_gid,
        )?;
        let mut stream = UnixStream::connect(&self.socket_path)
            .with_context(|| format!("connect checkpoint socket {}", self.socket_path.display()))?;
        stream.set_read_timeout(Some(self.io_timeout))?;
        stream.set_write_timeout(Some(self.io_timeout))?;
        let peer = crate::daemon::peer_credentials(&stream)?;
        if peer.uid != self.expected_server_uid || peer.gid != self.expected_server_gid {
            bail!(
                "OMNIS_CLIENT_SERVER_IDENTITY_MISMATCH: expected {}:{}, found {}:{}",
                self.expected_server_uid,
                self.expected_server_gid,
                peer.uid,
                peer.gid
            )
        }
        write_frame(&mut stream, request)?;
        stream
            .shutdown(Shutdown::Write)
            .context("close checkpoint request write half")?;
        read_frame(&mut stream).context("read checkpoint response")
    }

    #[cfg(not(unix))]
    fn exchange_response(&self, _request: &Request) -> Result<Response> {
        bail!("OMNIS_CHECKPOINT_TRANSPORT_UNSUPPORTED")
    }
}

fn validate_checkpoint_authority(
    checkpoint: &crate::model::SignedCheckpoint,
    allowed_ledger_id: &str,
    receipt_ledger_path: &Path,
    activated_client_uid: u32,
) -> Result<()> {
    if checkpoint.record.authority_id != crate::daemon::AUTHORITY_ID {
        bail!("OMNIS_CLIENT_CHECKPOINT_AUTHORITY_ID_MISMATCH")
    }
    if checkpoint.record.ledger_id != allowed_ledger_id {
        bail!("OMNIS_CLIENT_CHECKPOINT_LEDGER_ID_MISMATCH")
    }
    if Path::new(&checkpoint.record.receipt_ledger_path) != receipt_ledger_path {
        bail!("OMNIS_CLIENT_CHECKPOINT_RECEIPT_LEDGER_PATH_MISMATCH")
    }
    if checkpoint.record.peer_uid != activated_client_uid {
        bail!("OMNIS_CLIENT_CHECKPOINT_PEER_UID_MISMATCH")
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn read_root_owned_file(path: &Path, maximum_bytes: u64, label: &str) -> Result<Vec<u8>> {
    crate::daemon::assert_no_symlink_components(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open fixed {} {}", label, path.display()))?;
    let metadata = file.metadata()?;
    crate::daemon::assert_regular_owner_mode(&metadata, 0, 0, 0o444, label)?;
    crate::daemon::assert_no_extended_acl(path)?;
    if metadata.len() == 0 || metadata.len() > maximum_bytes {
        bail!("OMNIS_{label}_SIZE_REFUSED")
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > maximum_bytes {
        bail!("OMNIS_{label}_READ_DRIFT")
    }
    Ok(bytes)
}

#[cfg(unix)]
fn assert_socket_leaf(path: &Path, expected_uid: u32, expected_gid: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect checkpoint socket {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("OMNIS_CLIENT_SOCKET_SYMLINK_REFUSED: {}", path.display())
    }
    if !metadata.file_type().is_socket() {
        bail!("OMNIS_CLIENT_SOCKET_NOT_SOCKET: {}", path.display())
    }
    if metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.permissions().mode() & 0o7777 != 0o660
    {
        bail!("OMNIS_CLIENT_SOCKET_IDENTITY_OR_MODE_DRIFT")
    }
    #[cfg(target_os = "macos")]
    crate::daemon::assert_no_extended_acl(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        AppendDisposition, CheckpointRecord, DEFAULT_LEDGER_ID, PROTOCOL, ReceiptLinkWitness,
    };

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn anchor_request(request_id: &str) -> AnchorRequest {
        AnchorRequest {
            protocol: PROTOCOL.to_string(),
            request_id: request_id.to_string(),
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
        }
    }

    #[test]
    fn trusted_anchor_response_is_bound_to_the_exact_request() {
        let (_, identity) = crate::crypto::generate_test_identity();
        let public_key = identity.public_key_bytes().to_vec();
        let request = anchor_request("anchor:one");
        let record = CheckpointRecord {
            protocol: PROTOCOL.to_string(),
            authority_id: crate::daemon::AUTHORITY_ID.to_string(),
            checkpoint_sequence: 1,
            parent_checkpoint_hash: None,
            request_id: request.request_id.clone(),
            request_digest: crate::crypto::request_digest(&request).unwrap(),
            peer_uid: 501,
            ledger_id: request.ledger_id.clone(),
            receipt_ledger_path: request.receipt_ledger_path.clone(),
            observed_receipt_sequence: request.observed_receipt_sequence,
            observed_receipt_head: request.observed_receipt_head.clone(),
            issued_at_unix_ms: 1,
            signing_key_id: identity.key_id().to_string(),
        };
        let checkpoint = identity.sign(record).unwrap();
        let lookup_checkpoint = checkpoint.clone();
        let result = Success::Anchor {
            disposition: AppendDisposition::Appended,
            checkpoint,
        };
        let mut client = CheckpointClient::new("/tmp/unused.sock", 502, 503).unwrap();
        client.trusted_public_key = Some(public_key);
        client.allowed_ledger_id = Some(DEFAULT_LEDGER_ID.to_string());
        client.receipt_ledger_path = Some(PathBuf::from(
            "/Users/test/.jcode/state/omnis-key/receipts.jsonl",
        ));
        client.activated_client_uid = Some(501);

        client
            .validate_trusted_success(&Request::anchor(request), &result)
            .unwrap();
        let error = client
            .validate_trusted_success(&Request::anchor(anchor_request("anchor:other")), &result)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("ANCHOR_RESPONSE_BINDING_MISMATCH")
        );

        let mut alternate_path = anchor_request("anchor:alternate-path");
        alternate_path.receipt_ledger_path = "/tmp/attacker/receipts.jsonl".to_string();
        assert!(
            client
                .anchor(alternate_path)
                .unwrap_err()
                .to_string()
                .contains("RECEIPT_LEDGER_PATH_REFUSED")
        );

        client
            .validate_trusted_lookup("anchor:absent", None)
            .unwrap();
        let lookup_error = client
            .validate_trusted_lookup("anchor:different", Some(&lookup_checkpoint))
            .unwrap_err();
        assert!(
            lookup_error
                .to_string()
                .contains("LOOKUP_REQUEST_ID_MISMATCH")
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn activated_receipt_ledger_requires_private_owned_file_and_parent() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let parent = root.join("omnis-key");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let ledger = parent.join("receipts.jsonl");
        fs::write(&ledger, b"{}\n").unwrap();
        fs::set_permissions(&ledger, fs::Permissions::from_mode(0o600)).unwrap();

        let mut client = CheckpointClient::new("/tmp/unused.sock", 502, 503).unwrap();
        client.receipt_ledger_path = Some(ledger.clone());
        client.activated_client_uid = Some(unsafe { libc::geteuid() });
        client.validate_receipt_ledger_boundary().unwrap();

        fs::set_permissions(&ledger, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            client
                .validate_receipt_ledger_boundary()
                .unwrap_err()
                .to_string()
                .contains("IDENTITY_OR_MODE_DRIFT")
        );
        fs::set_permissions(&ledger, fs::Permissions::from_mode(0o600)).unwrap();
        fs::remove_file(&ledger).unwrap();
        std::os::unix::fs::symlink("/dev/null", &ledger).unwrap();
        assert!(
            client
                .validate_receipt_ledger_boundary()
                .unwrap_err()
                .to_string()
                .contains("SYMLINK_REFUSED")
        );
    }
}
