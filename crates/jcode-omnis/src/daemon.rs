use crate::protocol::{Request, Response, Success, read_frame, write_frame};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::Shutdown;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(target_os = "macos")]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};

pub const ACTIVATION_PROTOCOL: &str = "jourdanlabs.omnis-checkpoint-activation.v1";
pub const AUTHORITY_ID: &str = "jourdanlabs.omnis-checkpoint-authority.v1";
pub const AUTHORITY_ROOT: &str =
    "/Library/Application Support/JourdanLabs/OMNIS Key/Checkpoint Authority/v1";
pub const ACTIVATION_PATH: &str =
    "/Library/Application Support/JourdanLabs/OMNIS Key/Checkpoint Authority/activation.v1.json";
pub const RECORDS_PATH: &str =
    "/Library/Application Support/JourdanLabs/OMNIS Key/Checkpoint Authority/v1/records";
pub const PRIVATE_KEY_PATH: &str = "/Library/Application Support/JourdanLabs/OMNIS Key/Checkpoint Authority/v1/authority.ed25519.pk8";
pub const TRUST_PUBLIC_KEY_PATH: &str =
    "/Library/Application Support/JourdanLabs/OMNIS Key/Checkpoint Authority/authority.ed25519.pub";
pub const SOCKET_PATH: &str = "/var/run/jourdanlabs/omnis-checkpointd.sock";

const ACTIVATION_MAX_BYTES: u64 = 1024 * 1024;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationManifest {
    pub schema_version: u32,
    pub protocol: String,
    pub service_uid: u32,
    pub service_primary_gid: u32,
    pub service_groups: Vec<u32>,
    pub allowed_client_uid: u32,
    pub allowed_ledger_id: String,
    pub receipt_ledger_path: String,
    pub socket_path: String,
    pub records_path: String,
    pub private_key_path: String,
    pub trust_public_key_path: String,
}

#[derive(Clone, Debug)]
pub(crate) struct DaemonConfig {
    pub activation_path: PathBuf,
    pub authority_root: PathBuf,
    pub socket_path: PathBuf,
    pub records_path: PathBuf,
    pub private_key_path: PathBuf,
    pub trust_public_key_path: PathBuf,
    activation_owner_uid: u32,
    activation_owner_gid: u32,
    socket_parent_owner_uid: u32,
    enforce_fixed_paths: bool,
    enforce_process_identity: bool,
    enforce_acl: bool,
    allow_same_service_and_client_uid: bool,
}

impl DaemonConfig {
    pub(crate) fn production() -> Result<Self> {
        #[cfg(not(target_os = "macos"))]
        bail!("OMNIS_CHECKPOINT_AUTHORITY_UNSUPPORTED_PLATFORM");

        #[cfg(target_os = "macos")]
        Ok(Self {
            activation_path: PathBuf::from(ACTIVATION_PATH),
            authority_root: PathBuf::from(AUTHORITY_ROOT),
            socket_path: PathBuf::from(SOCKET_PATH),
            records_path: PathBuf::from(RECORDS_PATH),
            private_key_path: PathBuf::from(PRIVATE_KEY_PATH),
            trust_public_key_path: PathBuf::from(TRUST_PUBLIC_KEY_PATH),
            activation_owner_uid: 0,
            activation_owner_gid: 0,
            socket_parent_owner_uid: 0,
            enforce_fixed_paths: true,
            enforce_process_identity: true,
            enforce_acl: true,
            allow_same_service_and_client_uid: false,
        })
    }

    #[cfg(test)]
    fn explicit_test(
        root: &Path,
        service_uid: u32,
        service_gid: u32,
        allow_same_service_and_client_uid: bool,
    ) -> Self {
        let authority_root = root.join("authority");
        Self {
            activation_path: root.join("activation.v1.json"),
            socket_path: root.join("socket-parent/omnis-checkpointd.sock"),
            records_path: authority_root.join("records"),
            private_key_path: authority_root.join("authority.ed25519.pk8"),
            trust_public_key_path: root.join("authority.ed25519.pub"),
            authority_root,
            activation_owner_uid: service_uid,
            activation_owner_gid: service_gid,
            socket_parent_owner_uid: service_uid,
            enforce_fixed_paths: false,
            enforce_process_identity: true,
            enforce_acl: true,
            allow_same_service_and_client_uid,
        }
    }
}

pub fn run_production() -> Result<()> {
    let config = DaemonConfig::production()?;
    #[cfg(unix)]
    unsafe {
        // This is a dedicated zero-argument service process. Establish its
        // fixed creation mask once, before any authority path is accessed,
        // and never restore ambient process state.
        libc::umask(0o117);
    }
    run(config)
}

#[cfg(unix)]
fn run(config: DaemonConfig) -> Result<()> {
    let loaded_activation = load_activation(&config)?;
    let store = open_store(&config, &loaded_activation.manifest)?;
    let bound = bind_authority_listener(&config, &loaded_activation.manifest)?;
    for connection in bound.listener.incoming() {
        let mut stream = connection.context("accept checkpoint connection")?;
        if let Err(error) = handle_connection(&mut stream, &config, &loaded_activation, &store)
            && let Err(response_error) =
                send_error(&mut stream, None, "CONNECTION_REFUSED", error.to_string())
        {
            eprintln!(
                "OMNIS_CHECKPOINT_CONNECTION_AND_RESPONSE_REFUSED: \
                 connection={error:#}; response={response_error:#}"
            );
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn run(_config: DaemonConfig) -> Result<()> {
    bail!("OMNIS_CHECKPOINT_AUTHORITY_UNSUPPORTED_PLATFORM")
}

#[cfg(unix)]
struct BoundAuthorityListener {
    listener: UnixListener,
    // The lock must outlive every accepted connection. It intentionally has no
    // separately addressable lock file that could be deleted or replaced.
    _run_lock: AuthorityRunLock,
}

#[cfg(unix)]
fn bind_authority_listener(
    config: &DaemonConfig,
    activation: &ActivationManifest,
) -> Result<BoundAuthorityListener> {
    let run_lock = AuthorityRunLock::acquire(config, activation)?;
    let listener = bind_listener(config, activation)?;
    Ok(BoundAuthorityListener {
        listener,
        _run_lock: run_lock,
    })
}

#[cfg(unix)]
struct AuthorityRunLock {
    directory: File,
}

#[cfg(unix)]
impl AuthorityRunLock {
    fn acquire(config: &DaemonConfig, activation: &ActivationManifest) -> Result<Self> {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let directory = options.open(&config.records_path).with_context(|| {
            format!(
                "OMNIS_CHECKPOINT_RUN_LOCK_OPEN_FAILED: {}",
                config.records_path.display()
            )
        })?;
        let opened = directory.metadata()?;
        assert_directory_owner_mode(
            &opened,
            activation.service_uid,
            activation.service_primary_gid,
            0o700,
            "CHECKPOINT_RUN_LOCK_DIRECTORY",
        )?;
        let named = fs::symlink_metadata(&config.records_path)?;
        if named.file_type().is_symlink()
            || !named.is_dir()
            || named.dev() != opened.dev()
            || named.ino() != opened.ino()
        {
            bail!("OMNIS_CHECKPOINT_RUN_LOCK_DIRECTORY_IDENTITY_DRIFT")
        }
        if config.enforce_acl {
            assert_no_extended_acl(&config.records_path)?;
        }
        let status = unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if status != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                bail!("OMNIS_CHECKPOINT_AUTHORITY_ALREADY_RUNNING")
            }
            return Err(error).context("OMNIS_CHECKPOINT_RUN_LOCK_FAILED");
        }
        let locked = directory.metadata()?;
        let named_after_lock = fs::symlink_metadata(&config.records_path)?;
        if named_after_lock.file_type().is_symlink()
            || !named_after_lock.is_dir()
            || named_after_lock.dev() != locked.dev()
            || named_after_lock.ino() != locked.ino()
        {
            bail!("OMNIS_CHECKPOINT_RUN_LOCK_DIRECTORY_IDENTITY_DRIFT")
        }
        assert_directory_owner_mode(
            &locked,
            activation.service_uid,
            activation.service_primary_gid,
            0o700,
            "CHECKPOINT_RUN_LOCK_DIRECTORY",
        )?;
        if config.enforce_acl {
            assert_no_extended_acl(&config.records_path)?;
        }
        Ok(Self { directory })
    }
}

#[cfg(unix)]
impl Drop for AuthorityRunLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.directory.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn open_store(
    config: &DaemonConfig,
    activation: &ActivationManifest,
) -> Result<crate::store::AuthorityStore> {
    crate::store::AuthorityStore::open(crate::store::StoreConfig {
        paths: crate::store::StorePaths {
            authority_root: config.authority_root.clone(),
            records_dir: config.records_path.clone(),
            signing_key_path: config.private_key_path.clone(),
            trust_public_key_path: config.trust_public_key_path.clone(),
        },
        service_uid: activation.service_uid,
        service_primary_gid: activation.service_primary_gid,
        trust_owner_uid: config.activation_owner_uid,
        trust_owner_gid: config.activation_owner_gid,
        allowed_peer_uid: activation.allowed_client_uid,
        allowed_ledger_id: activation.allowed_ledger_id.clone(),
        allowed_receipt_ledger_path: activation.receipt_ledger_path.clone(),
        authority_id: AUTHORITY_ID.to_string(),
    })
}

#[cfg(unix)]
fn handle_connection(
    stream: &mut UnixStream,
    config: &DaemonConfig,
    startup_activation: &LoadedActivation,
    store: &crate::store::AuthorityStore,
) -> Result<()> {
    stream.set_read_timeout(Some(CONNECTION_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECTION_TIMEOUT))?;
    let live_activation = load_activation(config)?;
    if live_activation != *startup_activation {
        bail!("OMNIS_ACTIVATION_LIVE_DRIFT")
    }
    let activation = &startup_activation.manifest;
    assert_service_identity(activation)?;
    let peer = peer_credentials(stream)?;
    if peer.uid != activation.allowed_client_uid {
        send_error(
            stream,
            None,
            "PEER_UID_REFUSED",
            format!(
                "checkpoint peer UID {} differs from activated UID",
                peer.uid
            ),
        )?;
        return Ok(());
    }

    let request: Request = match read_frame(stream) {
        Ok(request) => request,
        Err(error) => {
            send_error(stream, None, error.code(), error.to_string())?;
            return Ok(());
        }
    };
    let request_id = request.request_id().to_string();
    if let Err(error) = request.validate_envelope() {
        send_error(stream, Some(request_id), error.code(), error.to_string())?;
        return Ok(());
    }
    if let Request::Lookup {
        request_id: lookup_id,
        ..
    } = &request
    {
        match store.lookup_request(lookup_id) {
            Ok(checkpoint) => {
                write_frame(stream, &Response::lookup_success(request_id, checkpoint))?;
                stream.shutdown(Shutdown::Write)?;
            }
            Err(error) => {
                send_error(
                    stream,
                    Some(request_id),
                    "AUTHORITY_OPERATION_REFUSED",
                    error.to_string(),
                )?;
            }
        }
        return Ok(());
    }
    let result = match request {
        Request::Status { .. } => store.latest().map(|latest| Success::Status {
            authority_id: AUTHORITY_ID.to_string(),
            ledger_id: activation.allowed_ledger_id.clone(),
            receipt_ledger_path: activation.receipt_ledger_path.clone(),
            signing_key_id: store.signing_key_id().to_string(),
            latest,
        }),
        Request::Anchor { request, .. } => store
            .anchor_at(peer.uid, &request, unix_time_millis()?)
            .map(|outcome| Success::Anchor {
                disposition: outcome.disposition,
                checkpoint: outcome.checkpoint().clone(),
            }),
        Request::Lookup { .. } => unreachable!("lookup returned above"),
    };
    match result {
        Ok(success) => {
            let response = Response::success(request_id, success);
            write_frame(stream, &response)?;
            stream.shutdown(Shutdown::Write)?;
        }
        Err(error) => {
            send_error(
                stream,
                Some(request_id),
                "AUTHORITY_OPERATION_REFUSED",
                error.to_string(),
            )?;
        }
    }
    Ok(())
}

fn unix_time_millis() -> Result<u64> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("OMNIS_CHECKPOINT_CLOCK_BEFORE_UNIX_EPOCH")?;
    u64::try_from(duration.as_millis()).context("OMNIS_CHECKPOINT_CLOCK_OVERFLOW")
}

#[cfg(not(unix))]
fn handle_connection(
    _stream: &mut (),
    _config: &DaemonConfig,
    _startup_activation: &LoadedActivation,
    _store: &crate::store::AuthorityStore,
) -> Result<()> {
    bail!("OMNIS_CHECKPOINT_TRANSPORT_UNSUPPORTED")
}

#[cfg(unix)]
fn send_error(
    stream: &mut UnixStream,
    request_id: Option<String>,
    code: impl Into<String>,
    message: impl Into<String>,
) -> Result<()> {
    write_frame(stream, &Response::error(request_id, code, message))?;
    stream.shutdown(Shutdown::Write)?;
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LoadedActivation {
    manifest: ActivationManifest,
    bytes: Vec<u8>,
}

fn load_activation(config: &DaemonConfig) -> Result<LoadedActivation> {
    if config.enforce_fixed_paths {
        assert_fixed_config(config)?;
        assert_no_symlink_components(&config.activation_path)?;
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options
        .open(&config.activation_path)
        .with_context(|| format!("open activation {}", config.activation_path.display()))?;
    let metadata = file.metadata()?;
    assert_regular_owner_mode(
        &metadata,
        config.activation_owner_uid,
        config.activation_owner_gid,
        0o444,
        "ACTIVATION",
    )?;
    if config.enforce_acl {
        assert_no_extended_acl(&config.activation_path)?;
    }
    if metadata.len() == 0 || metadata.len() > ACTIVATION_MAX_BYTES {
        bail!("OMNIS_ACTIVATION_SIZE_REFUSED")
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(ACTIVATION_MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > ACTIVATION_MAX_BYTES {
        bail!("OMNIS_ACTIVATION_READ_DRIFT")
    }
    let activation: ActivationManifest =
        serde_json::from_slice(&bytes).context("OMNIS_ACTIVATION_INVALID_JSON")?;
    validate_activation(config, &activation)?;
    Ok(LoadedActivation {
        manifest: activation,
        bytes,
    })
}

fn validate_activation(config: &DaemonConfig, activation: &ActivationManifest) -> Result<()> {
    validate_activation_contract(config, activation)?;
    if config.enforce_process_identity {
        let identity = process_identity()?;
        if identity.uid != activation.service_uid
            || identity.gid != activation.service_primary_gid
            || identity.groups != activation.service_groups
        {
            bail!("OMNIS_ACTIVATION_PROCESS_IDENTITY_DRIFT")
        }
    }
    Ok(())
}

pub(crate) fn validate_activation_contract(
    config: &DaemonConfig,
    activation: &ActivationManifest,
) -> Result<()> {
    if activation.schema_version != 1 || activation.protocol != ACTIVATION_PROTOCOL {
        bail!("OMNIS_ACTIVATION_SCHEMA_OR_PROTOCOL_MISMATCH")
    }
    if activation.service_uid == 0
        || activation.service_primary_gid == 0
        || activation.allowed_client_uid == 0
    {
        bail!("OMNIS_ACTIVATION_ZERO_IDENTITY_REFUSED")
    }
    if !config.allow_same_service_and_client_uid
        && activation.allowed_client_uid == activation.service_uid
    {
        bail!("OMNIS_ACTIVATION_CLIENT_SERVICE_UID_COLLISION")
    }
    if activation.service_groups.is_empty()
        || activation.service_groups.contains(&0)
        || !activation
            .service_groups
            .contains(&activation.service_primary_gid)
        || activation
            .service_groups
            .windows(2)
            .any(|window| window[0] >= window[1])
    {
        bail!("OMNIS_ACTIVATION_GROUP_VECTOR_INVALID")
    }
    validate_ledger_id(&activation.allowed_ledger_id)?;
    crate::model::validate_receipt_ledger_path(&activation.receipt_ledger_path)?;
    for (actual, expected, label) in [
        (
            activation.socket_path.as_str(),
            config
                .socket_path
                .to_str()
                .context("socket path is not UTF-8")?,
            "socket",
        ),
        (
            activation.records_path.as_str(),
            config
                .records_path
                .to_str()
                .context("records path is not UTF-8")?,
            "records",
        ),
        (
            activation.private_key_path.as_str(),
            config
                .private_key_path
                .to_str()
                .context("private key path is not UTF-8")?,
            "private key",
        ),
        (
            activation.trust_public_key_path.as_str(),
            config
                .trust_public_key_path
                .to_str()
                .context("trust public key path is not UTF-8")?,
            "trust public key",
        ),
    ] {
        if actual != expected {
            bail!("OMNIS_ACTIVATION_PATH_DRIFT: {label}")
        }
    }
    Ok(())
}

fn validate_ledger_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 256
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'/')
        })
    {
        bail!("OMNIS_ACTIVATION_LEDGER_ID_INVALID")
    }
    Ok(())
}

fn assert_fixed_config(config: &DaemonConfig) -> Result<()> {
    for (actual, expected, label) in [
        (
            &config.activation_path,
            Path::new(ACTIVATION_PATH),
            "activation",
        ),
        (
            &config.authority_root,
            Path::new(AUTHORITY_ROOT),
            "authority root",
        ),
        (&config.socket_path, Path::new(SOCKET_PATH), "socket"),
        (&config.records_path, Path::new(RECORDS_PATH), "records"),
        (
            &config.private_key_path,
            Path::new(PRIVATE_KEY_PATH),
            "private key",
        ),
        (
            &config.trust_public_key_path,
            Path::new(TRUST_PUBLIC_KEY_PATH),
            "trust public key",
        ),
    ] {
        if actual != expected {
            bail!("OMNIS_PRODUCTION_PATH_DRIFT: {label}")
        }
    }
    Ok(())
}

#[cfg(unix)]
fn bind_listener(config: &DaemonConfig, activation: &ActivationManifest) -> Result<UnixListener> {
    let parent = config
        .socket_path
        .parent()
        .context("OMNIS_SOCKET_PARENT_MISSING")?;
    let parent_metadata = fs::symlink_metadata(parent)
        .with_context(|| format!("inspect socket parent {}", parent.display()))?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        bail!("OMNIS_SOCKET_PARENT_TYPE_REFUSED")
    }
    assert_directory_owner_mode(
        &parent_metadata,
        config.socket_parent_owner_uid,
        activation.service_primary_gid,
        0o770,
        "SOCKET_PARENT",
    )?;
    if config.enforce_acl {
        assert_no_extended_acl(parent)?;
    }
    recover_quarantine_residue(config, activation, parent)?;
    match fs::symlink_metadata(&config.socket_path) {
        Ok(_) => recover_stale_socket(config, activation)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect checkpoint socket leaf"),
    }
    let listener_result = UnixListener::bind(&config.socket_path);
    let listener = listener_result
        .with_context(|| format!("bind checkpoint socket {}", config.socket_path.display()))?;
    let result = (|| -> Result<ReviewedSocket> {
        // Unit tests share a process with unrelated filesystem tests, so the
        // explicit temp-only seam cannot set a process-global umask. Production
        // never chmods by pathname: run_production establishes 0117 once.
        #[cfg(test)]
        if !config.enforce_fixed_paths {
            fs::set_permissions(&config.socket_path, fs::Permissions::from_mode(0o660))
                .context("OMNIS_TEST_SOCKET_LEAF_MODE_SET_FAILED")?;
        }
        if listener.local_addr()?.as_pathname() != Some(config.socket_path.as_path()) {
            bail!("OMNIS_SOCKET_BOUND_PATH_DRIFT")
        }
        let leaf = inspect_socket_leaf(config, activation, &config.socket_path)?;
        prove_bound_listener_path(&listener, &config.socket_path, &leaf)?;
        let after = inspect_socket_leaf(config, activation, &config.socket_path)?;
        if after != leaf {
            bail!("OMNIS_SOCKET_BOUND_PATH_HANDOFF")
        }
        Ok(leaf)
    })();
    if let Err(error) = result {
        drop(listener);
        if let Err(cleanup_error) =
            quarantine_reviewed_socket(config, activation, &config.socket_path, None)
        {
            bail!(
                "OMNIS_SOCKET_BIND_REVIEW_AND_CLEANUP_REFUSED: \
                 review={error:#}; cleanup={cleanup_error:#}"
            )
        }
        return Err(error);
    }
    Ok(listener)
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReviewedSocket {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
}

#[cfg(unix)]
fn inspect_socket_leaf(
    config: &DaemonConfig,
    activation: &ActivationManifest,
    path: &Path,
) -> Result<ReviewedSocket> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect checkpoint socket {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
        bail!("OMNIS_SOCKET_LEAF_TYPE_REFUSED")
    }
    let reviewed = ReviewedSocket {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.permissions().mode() & 0o7777,
        links: metadata.nlink(),
    };
    if reviewed.uid != activation.service_uid
        || reviewed.gid != activation.service_primary_gid
        || reviewed.mode != 0o660
        || reviewed.links != 1
    {
        bail!("OMNIS_SOCKET_LEAF_IDENTITY_OR_MODE_REFUSED")
    }
    if config.enforce_acl {
        assert_no_extended_acl(path)?;
    }
    Ok(reviewed)
}

#[cfg(unix)]
fn prove_no_listener_accepts(path: &Path) -> Result<()> {
    match UnixStream::connect(path) {
        Ok(stream) => {
            // A connect racing the final close of a previous listener can
            // briefly succeed even though its peer is already gone. Only
            // recover when that connection reports HUP/ERR and a fresh
            // connect then receives the kernel's definitive ECONNREFUSED.
            let mut readiness = libc::pollfd {
                fd: stream.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut readiness, 1, 50) };
            let peer_gone = ready > 0
                && readiness.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0;
            drop(stream);
            if peer_gone {
                match UnixStream::connect(path) {
                    Err(error) if error.raw_os_error() == Some(libc::ECONNREFUSED) => return Ok(()),
                    Ok(stream) => drop(stream),
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!("OMNIS_SOCKET_LIVENESS_INDETERMINATE: {}", path.display())
                        });
                    }
                }
            }
            bail!("OMNIS_SOCKET_ACTIVE_LISTENER_REFUSED")
        }
        Err(error) if error.raw_os_error() == Some(libc::ECONNREFUSED) => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("OMNIS_SOCKET_LIVENESS_INDETERMINATE: {}", path.display())),
    }
}

#[cfg(unix)]
fn prove_bound_listener_path(
    listener: &UnixListener,
    path: &Path,
    reviewed: &ReviewedSocket,
) -> Result<()> {
    let mut connector = UnixStream::connect(path)
        .with_context(|| format!("OMNIS_SOCKET_BOUND_SELF_CONNECT_FAILED: {}", path.display()))?;
    let mut readiness = libc::pollfd {
        fd: listener.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let ready = unsafe { libc::poll(&mut readiness, 1, 1_000) };
    if ready != 1 || readiness.revents & libc::POLLIN == 0 {
        bail!("OMNIS_SOCKET_BOUND_SELF_ACCEPT_NOT_READY")
    }
    let (mut accepted, _) = listener
        .accept()
        .context("OMNIS_SOCKET_BOUND_SELF_ACCEPT_FAILED")?;
    accepted.set_read_timeout(Some(Duration::from_secs(1)))?;
    let challenge = b"jourdanlabs.omnis-checkpoint.bound-listener.v1";
    connector.write_all(challenge)?;
    connector.shutdown(Shutdown::Write)?;
    let mut observed = vec![0_u8; challenge.len()];
    accepted.read_exact(&mut observed)?;
    if observed != challenge {
        bail!("OMNIS_SOCKET_BOUND_SELF_PROOF_MISMATCH")
    }
    let after = fs::symlink_metadata(path)?;
    if after.dev() != reviewed.device || after.ino() != reviewed.inode {
        bail!("OMNIS_SOCKET_BOUND_PATH_HANDOFF")
    }
    Ok(())
}

#[cfg(unix)]
fn recover_stale_socket(config: &DaemonConfig, activation: &ActivationManifest) -> Result<()> {
    let reviewed = inspect_socket_leaf(config, activation, &config.socket_path)?;
    prove_no_listener_accepts(&config.socket_path)?;
    quarantine_reviewed_socket(config, activation, &config.socket_path, Some(reviewed))
}

#[cfg(target_os = "macos")]
fn quarantine_reviewed_socket(
    config: &DaemonConfig,
    activation: &ActivationManifest,
    source: &Path,
    expected: Option<ReviewedSocket>,
) -> Result<()> {
    let reviewed = match expected {
        Some(reviewed) => reviewed,
        None => inspect_socket_leaf(config, activation, source)?,
    };
    let parent = source.parent().context("OMNIS_SOCKET_PARENT_MISSING")?;
    // Encoding the reviewed identity in the quarantine name lets a later
    // restart distinguish a clean crash residue from a raced replacement.
    let quarantine = parent.join(quarantine_name(reviewed));
    rename_exclusive(source, &quarantine)?;
    sync_directory(parent)?;

    let moved = inspect_socket_leaf(config, activation, &quarantine)?;
    if moved != reviewed {
        bail!("OMNIS_SOCKET_QUARANTINE_IDENTITY_MISMATCH")
    }
    match fs::symlink_metadata(source) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => bail!("OMNIS_SOCKET_REPLACED_DURING_QUARANTINE"),
        Err(error) => {
            return Err(error).context("OMNIS_SOCKET_SOURCE_RECHECK_FAILED");
        }
    }
    // A listener could have become active after the first liveness check but
    // before the atomic rename. Refuse and preserve the quarantined inode if so.
    prove_no_listener_accepts(&quarantine)?;
    let final_check = inspect_socket_leaf(config, activation, &quarantine)?;
    if final_check != reviewed {
        bail!("OMNIS_SOCKET_QUARANTINE_IDENTITY_MISMATCH")
    }
    fs::remove_file(&quarantine).context("OMNIS_SOCKET_QUARANTINE_UNLINK_FAILED")?;
    sync_directory(parent)?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn quarantine_name(reviewed: ReviewedSocket) -> String {
    format!(".okcs-{:x}-{:x}", reviewed.device, reviewed.inode)
}

#[cfg(target_os = "macos")]
fn parse_quarantine_name(name: &str) -> Result<(u64, u64)> {
    let suffix = name
        .strip_prefix(".okcs-")
        .context("OMNIS_SOCKET_QUARANTINE_NAME_INVALID")?;
    let (device, inode) = suffix
        .split_once('-')
        .context("OMNIS_SOCKET_QUARANTINE_NAME_INVALID")?;
    if device.is_empty()
        || inode.is_empty()
        || inode.contains('-')
        || !device.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !inode.bytes().all(|byte| byte.is_ascii_hexdigit())
        || device.bytes().any(|byte| byte.is_ascii_uppercase())
        || inode.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        bail!("OMNIS_SOCKET_QUARANTINE_NAME_INVALID")
    }
    Ok((
        u64::from_str_radix(device, 16).context("OMNIS_SOCKET_QUARANTINE_NAME_INVALID")?,
        u64::from_str_radix(inode, 16).context("OMNIS_SOCKET_QUARANTINE_NAME_INVALID")?,
    ))
}

#[cfg(target_os = "macos")]
fn recover_quarantine_residue(
    config: &DaemonConfig,
    activation: &ActivationManifest,
    parent: &Path,
) -> Result<()> {
    let mut candidates = Vec::new();
    for entry in fs::read_dir(parent).context("OMNIS_SOCKET_PARENT_READ_FAILED")? {
        let entry = entry.context("OMNIS_SOCKET_PARENT_ENTRY_FAILED")?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("OMNIS_SOCKET_PARENT_NAME_NOT_UTF8"))?;
        if name.starts_with(".okcs-") {
            candidates.push((name, entry.path()));
        }
    }
    if candidates.is_empty() {
        return Ok(());
    }
    if candidates.len() != 1 {
        bail!("OMNIS_SOCKET_MULTIPLE_QUARANTINE_RESIDUES_REFUSED")
    }
    match fs::symlink_metadata(&config.socket_path) {
        Ok(_) => bail!("OMNIS_SOCKET_QUARANTINE_RESIDUE_WITH_SOURCE_REFUSED"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("OMNIS_SOCKET_SOURCE_RECHECK_FAILED"),
    }
    let Some((name, path)) = candidates.pop() else {
        bail!("OMNIS_SOCKET_QUARANTINE_RESIDUE_DISAPPEARED")
    };
    let (expected_device, expected_inode) = parse_quarantine_name(&name)?;
    let reviewed = inspect_socket_leaf(config, activation, &path)?;
    if reviewed.device != expected_device
        || reviewed.inode != expected_inode
        || quarantine_name(reviewed) != name
    {
        bail!("OMNIS_SOCKET_QUARANTINE_RESIDUE_IDENTITY_MISMATCH")
    }
    prove_no_listener_accepts(&path)?;
    let final_check = inspect_socket_leaf(config, activation, &path)?;
    if final_check != reviewed {
        bail!("OMNIS_SOCKET_QUARANTINE_RESIDUE_IDENTITY_MISMATCH")
    }
    fs::remove_file(&path).context("OMNIS_SOCKET_QUARANTINE_RESIDUE_UNLINK_FAILED")?;
    sync_directory(parent)?;
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn recover_quarantine_residue(
    _config: &DaemonConfig,
    _activation: &ActivationManifest,
    _parent: &Path,
) -> Result<()> {
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn quarantine_reviewed_socket(
    _config: &DaemonConfig,
    _activation: &ActivationManifest,
    _source: &Path,
    _expected: Option<ReviewedSocket>,
) -> Result<()> {
    bail!("OMNIS_SOCKET_STALE_RECOVERY_UNSUPPORTED_PLATFORM")
}

#[cfg(target_os = "macos")]
fn rename_exclusive(source: &Path, destination: &Path) -> Result<()> {
    let source = std::ffi::CString::new(source.as_os_str().as_bytes())
        .context("OMNIS_SOCKET_SOURCE_PATH_CONTAINS_NUL")?;
    let destination = std::ffi::CString::new(destination.as_os_str().as_bytes())
        .context("OMNIS_SOCKET_QUARANTINE_PATH_CONTAINS_NUL")?;
    let status =
        unsafe { libc::renamex_np(source.as_ptr(), destination.as_ptr(), libc::RENAME_EXCL) };
    if status != 0 {
        return Err(std::io::Error::last_os_error())
            .context("OMNIS_SOCKET_QUARANTINE_RENAME_FAILED");
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options
        .open(path)
        .with_context(|| format!("open directory for sync {}", path.display()))?
        .sync_all()
        .with_context(|| format!("sync directory {}", path.display()))
}

#[cfg(not(unix))]
fn bind_listener(_config: &DaemonConfig, _activation: &ActivationManifest) -> Result<()> {
    bail!("OMNIS_CHECKPOINT_TRANSPORT_UNSUPPORTED")
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessIdentity {
    uid: u32,
    gid: u32,
    groups: Vec<u32>,
}

#[cfg(unix)]
fn process_identity() -> Result<ProcessIdentity> {
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if count < 0 {
        return Err(std::io::Error::last_os_error()).context("read process group count");
    }
    let mut groups = vec![0 as libc::gid_t; count as usize];
    if count > 0 {
        let loaded = unsafe { libc::getgroups(count, groups.as_mut_ptr()) };
        if loaded != count {
            bail!("OMNIS_PROCESS_GROUP_VECTOR_READ_FAILED")
        }
    }
    let mut groups: Vec<u32> = groups.into_iter().collect();
    groups.push(gid);
    groups.sort_unstable();
    groups.dedup();
    Ok(ProcessIdentity { uid, gid, groups })
}

#[cfg(unix)]
fn assert_service_identity(activation: &ActivationManifest) -> Result<()> {
    let identity = process_identity()?;
    if identity.uid != activation.service_uid
        || identity.gid != activation.service_primary_gid
        || identity.groups != activation.service_groups
        || identity.groups.contains(&0)
    {
        bail!("OMNIS_ACTIVATION_PROCESS_IDENTITY_DRIFT")
    }
    Ok(())
}

#[cfg(not(unix))]
fn process_identity() -> Result<ProcessIdentity> {
    bail!("OMNIS_CHECKPOINT_AUTHORITY_UNSUPPORTED_PLATFORM")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PeerCredentials {
    pub uid: u32,
    pub gid: u32,
}

#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
pub(crate) fn peer_credentials(stream: &UnixStream) -> Result<PeerCredentials> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let status = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if status != 0 {
        return Err(std::io::Error::last_os_error()).context("read checkpoint peer credentials");
    }
    Ok(PeerCredentials { uid, gid })
}

#[cfg(target_os = "linux")]
pub(crate) fn peer_credentials(stream: &UnixStream) -> Result<PeerCredentials> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let status = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut credentials as *mut _ as *mut libc::c_void,
            &mut length,
        )
    };
    if status != 0 || length as usize != std::mem::size_of::<libc::ucred>() {
        return Err(std::io::Error::last_os_error()).context("read checkpoint peer credentials");
    }
    Ok(PeerCredentials {
        uid: credentials.uid,
        gid: credentials.gid,
    })
}

#[cfg(all(
    unix,
    not(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "linux"
    ))
))]
pub(crate) fn peer_credentials(_stream: &UnixStream) -> Result<PeerCredentials> {
    bail!("OMNIS_CHECKPOINT_PEER_CREDENTIALS_UNSUPPORTED")
}

#[cfg(unix)]
pub(crate) fn assert_regular_owner_mode(
    metadata: &fs::Metadata,
    uid: u32,
    gid: u32,
    mode: u32,
    label: &str,
) -> Result<()> {
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.permissions().mode() & 0o7777 != mode
    {
        bail!("OMNIS_{label}_IDENTITY_OR_MODE_DRIFT")
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn assert_regular_owner_mode(
    _metadata: &fs::Metadata,
    _uid: u32,
    _gid: u32,
    _mode: u32,
    _label: &str,
) -> Result<()> {
    bail!("OMNIS_CHECKPOINT_AUTHORITY_UNSUPPORTED_PLATFORM")
}

#[cfg(unix)]
fn assert_directory_owner_mode(
    metadata: &fs::Metadata,
    uid: u32,
    gid: u32,
    mode: u32,
    label: &str,
) -> Result<()> {
    if !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.permissions().mode() & 0o7777 != mode
    {
        bail!("OMNIS_{label}_IDENTITY_OR_MODE_DRIFT")
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn assert_no_symlink_components(path: &Path) -> Result<()> {
    let mut cursor = PathBuf::new();
    for component in path.components() {
        cursor.push(component);
        if cursor == Path::new("/") {
            continue;
        }
        let metadata = fs::symlink_metadata(&cursor)
            .with_context(|| format!("inspect authority path {}", cursor.display()))?;
        if metadata.file_type().is_symlink() {
            bail!("OMNIS_AUTHORITY_PATH_SYMLINK_REFUSED: {}", cursor.display())
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn assert_no_symlink_components(_path: &Path) -> Result<()> {
    bail!("OMNIS_CHECKPOINT_AUTHORITY_UNSUPPORTED_PLATFORM")
}

#[cfg(target_os = "macos")]
pub(crate) fn assert_no_extended_acl(path: &Path) -> Result<()> {
    let output = std::process::Command::new("/bin/ls")
        .env_clear()
        .env("LC_ALL", "C")
        .args(["-lde"])
        .arg(path)
        .output()
        .with_context(|| format!("inspect ACL for {}", path.display()))?;
    if !output.status.success() {
        bail!("OMNIS_AUTHORITY_ACL_INSPECTION_FAILED: {}", path.display())
    }
    let text = String::from_utf8(output.stdout).context("ACL inspection was not UTF-8")?;
    let mut lines = text.lines();
    let first = lines
        .next()
        .context("ACL inspection returned no metadata")?;
    let marker = first
        .split_whitespace()
        .next()
        .and_then(|mode| mode.chars().nth(10));
    if marker == Some('+')
        || lines.any(|line| {
            let trimmed = line.trim_start();
            trimmed
                .split_once(':')
                .is_some_and(|(index, _)| index.bytes().all(|byte| byte.is_ascii_digit()))
        })
    {
        bail!("OMNIS_AUTHORITY_EXTENDED_ACL_REFUSED: {}", path.display())
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn assert_no_extended_acl(_path: &Path) -> Result<()> {
    bail!("OMNIS_CHECKPOINT_ACL_INSPECTION_UNSUPPORTED")
}

#[cfg(test)]
mod tests;
