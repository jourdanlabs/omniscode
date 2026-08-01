use anyhow::{Context, Result, bail};
use jcode_base::omnis::{self, AppendDisposition, ClaimCeiling};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::thread::JoinHandle;
use tempfile::TempDir;

use crate::output::{self, DemoData};

#[cfg(unix)]
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
#[cfg(unix)]
use signal_hook::iterator::{Handle as SignalHandle, Signals};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

const DEMO_ROOT_PREFIX: &str = "omnis-key-demo-";
const DEMO_RANDOM_SUFFIX_LEN: usize = 24;
const ACTIVE_MARKER_NAME: &str = ".fixture-only-active.lock";
const ACTIVE_MARKER_PREAMBLE: &str = "jourdanlabs.omnis-key.fixture-only-active.v1\n";

pub(crate) fn run(json: bool, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    match execute() {
        Ok(data) => output::emit(
            json,
            "demo.integrity",
            true,
            "DEMO_INTEGRITY_PASSED",
            Some(&data),
            0,
            (stdout, stderr),
        ),
        Err(_) => output::emit::<()>(
            json,
            "demo.integrity",
            false,
            "DEMO_INTEGRITY_FAILED",
            None,
            3,
            (stdout, stderr),
        ),
    }
}

fn execute() -> Result<DemoData> {
    let guard = DemoRoot::new()?;
    let result = exercise_fixture(guard.path()?);
    let cleanup = guard.finish();
    let data = result?;
    cleanup?;
    Ok(data)
}

fn exercise_fixture(root: &Path) -> Result<DemoData> {
    let ledger = root.join("original-receipts.jsonl");
    let synthetic_evidence = b"OMNIS KEY fixture-only evidence; no provider or operator state";
    let evidence_sha256 = format!("{:x}", Sha256::digest(synthetic_evidence));

    let first = omnis::append_idempotent(
        &ledger,
        "demo:fixture:integrity",
        "demo.integrity",
        "synthetic fixture-only local evidence",
        &evidence_sha256,
        ClaimCeiling::LocalRecord,
    )?;
    if first.disposition() != AppendDisposition::Appended {
        bail!("demo first append was not appended")
    }
    let replay = omnis::append_idempotent(
        &ledger,
        "demo:fixture:integrity",
        "demo.integrity",
        "synthetic fixture-only local evidence",
        &evidence_sha256,
        ClaimCeiling::LocalRecord,
    )?;
    if replay.disposition() != AppendDisposition::Existing {
        bail!("demo exact replay was not existing")
    }
    let valid = omnis::verify(&ledger)?;
    if !valid.valid() || valid.entries() != 1 || valid.head().is_none() {
        bail!("demo original receipt chain did not verify")
    }

    let original = fs::read(&ledger)?;
    let tampered = root.join("tampered-copy.jsonl");
    fs::copy(&ledger, &tampered)?;
    #[cfg(unix)]
    fs::set_permissions(&tampered, fs::Permissions::from_mode(0o600))?;
    let changed = String::from_utf8(fs::read(&tampered)?)
        .context("demo fixture ledger was not UTF-8")?
        .replacen("demo.integrity", "demo.tampered", 1);
    if changed.as_bytes() == original {
        bail!("demo tamper mutation made no change")
    }
    fs::write(&tampered, changed)?;
    let tampered_verification = omnis::verify(&tampered)?;
    if tampered_verification.valid() {
        bail!("production verifier accepted the tampered copy")
    }
    if fs::read(&ledger)? != original {
        bail!("demo modified its authoritative original fixture")
    }
    let original_after = omnis::verify(&ledger)?;
    if !original_after.valid() || original_after.entries() != 1 {
        bail!("demo original fixture drifted after copy mutation")
    }

    Ok(DemoData {
        fixture_only: true,
        first_append: "APPENDED",
        exact_replay: "EXISTING",
        valid_chain: true,
        tampered_copy_refused: true,
        tamper_refusal_code: "RECEIPT_CHAIN_INVALID",
        execution_authorized: false,
    })
}

struct DemoRoot {
    temporary: Option<TempDir>,
    active_lock: Option<File>,
    #[cfg(unix)]
    signal_handle: Option<SignalHandle>,
    signal_worker: Option<JoinHandle<()>>,
}

impl DemoRoot {
    fn new() -> Result<Self> {
        #[cfg(unix)]
        let mut handled_signal_mask = HandledSignalMask::block()?;
        let base = trusted_temporary_base()?;
        let prefix = format!("{DEMO_ROOT_PREFIX}{}-", std::process::id());
        let mut builder = tempfile::Builder::new();
        builder.prefix(&prefix).rand_bytes(DEMO_RANDOM_SUFFIX_LEN);
        #[cfg(unix)]
        builder.permissions(fs::Permissions::from_mode(0o700));
        let temporary = builder
            .tempdir_in(&base)
            .context("create private fixture-only demo root")?;
        validate_created_root(temporary.path())?;

        #[cfg(unix)]
        {
            let identity = directory_identity(temporary.path())?;
            let mut signals =
                Signals::new([SIGINT, SIGTERM, SIGHUP]).context("install demo cleanup signals")?;
            let signal_handle = signals.handle();
            let path = temporary.path().to_path_buf();
            let signal_worker = std::thread::Builder::new()
                .name("omnis-demo-cleanup".to_string())
                .spawn(move || {
                    if let Some(signal) = signals.forever().next() {
                        if remove_if_same_directory(&path, identity).is_err() {
                            eprintln!("DEMO_CLEANUP_FAILED");
                            std::process::exit(3);
                        }
                        std::process::exit(128 + signal);
                    }
                })
                .context("start demo cleanup signal worker")?;
            let mut root = Self {
                temporary: Some(temporary),
                active_lock: None,
                signal_handle: Some(signal_handle),
                signal_worker: Some(signal_worker),
            };
            root.install_active_marker()?;
            if let Some(signal) = handled_signal_mask.pending_signal()? {
                root.finish()?;
                std::process::exit(128 + signal);
            }
            handled_signal_mask.restore()?;
            Ok(root)
        }
        #[cfg(not(unix))]
        {
            Ok(Self {
                temporary: Some(temporary),
                active_lock: None,
                signal_worker: None,
            })
        }
    }

    fn path(&self) -> Result<&Path> {
        self.temporary
            .as_ref()
            .map(TempDir::path)
            .context("demo root missing before cleanup")
    }

    fn stop_signal_worker(&mut self) -> Result<()> {
        #[cfg(unix)]
        if let Some(handle) = self.signal_handle.take() {
            handle.close();
        }
        if let Some(worker) = self.signal_worker.take() {
            worker
                .join()
                .map_err(|_| anyhow::anyhow!("demo cleanup signal worker panicked"))?;
        }
        Ok(())
    }

    fn cleanup_owned_root(&mut self) -> Result<()> {
        let active_lock = self.active_lock.take();
        let cleanup = match self.temporary.take() {
            Some(temporary) => temporary
                .close()
                .context("remove private fixture-only demo root"),
            None => Ok(()),
        };
        drop(active_lock);
        cleanup
    }

    #[cfg(unix)]
    fn install_active_marker(&mut self) -> Result<()> {
        let path = self.path()?.to_path_buf();
        let marker_bytes = active_marker_bytes(&path, directory_identity(&path)?)?;
        let marker = path.join(ACTIVE_MARKER_NAME);
        let mut options = OpenOptions::new();
        use std::os::unix::fs::OpenOptionsExt;
        options
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .mode(0o600);
        let mut file = options.open(&marker)?;
        file.lock()?;
        file.write_all(&marker_bytes)?;
        file.sync_all()?;
        jcode_base::omnis::validate_private_file(&marker, "OMNIS_DEMO_ACTIVE_MARKER")?;
        self.active_lock = Some(file);
        Ok(())
    }

    fn finish(mut self) -> Result<()> {
        #[cfg(unix)]
        let mut handled_signal_mask = HandledSignalMask::block()?;
        let worker_result = self.stop_signal_worker();
        let cleanup_result = self.cleanup_owned_root();
        worker_result?;
        cleanup_result?;
        #[cfg(unix)]
        {
            if let Some(signal) = handled_signal_mask.pending_signal()? {
                std::process::exit(128 + signal);
            }
            handled_signal_mask.restore()?;
        }
        Ok(())
    }
}

impl Drop for DemoRoot {
    fn drop(&mut self) {
        #[cfg(unix)]
        let mut handled_signal_mask = match HandledSignalMask::block() {
            Ok(mask) => Some(mask),
            Err(_) => {
                eprintln!("DEMO_CLEANUP_FAILED");
                None
            }
        };
        let mut cleanup_failed = self.stop_signal_worker().is_err();
        cleanup_failed |= self.cleanup_owned_root().is_err();
        if cleanup_failed {
            eprintln!("DEMO_CLEANUP_FAILED");
        }
        #[cfg(unix)]
        if let Some(mask) = handled_signal_mask.as_mut() {
            match mask.pending_signal() {
                Ok(Some(_)) if cleanup_failed => std::process::exit(3),
                Ok(Some(signal)) => std::process::exit(128 + signal),
                Ok(None) => {}
                Err(_) => {
                    eprintln!("DEMO_CLEANUP_FAILED");
                }
            }
            if mask.restore().is_err() {
                eprintln!("DEMO_CLEANUP_FAILED");
            }
        }
    }
}

#[cfg(unix)]
struct HandledSignalMask {
    previous: libc::sigset_t,
    restored: bool,
}

#[cfg(unix)]
impl HandledSignalMask {
    fn block() -> Result<Self> {
        let mut handled = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        if unsafe { libc::sigemptyset(&mut handled) } != 0 {
            return Err(std::io::Error::last_os_error()).context("initialize demo signal mask");
        }
        for signal in [SIGHUP, SIGINT, SIGTERM] {
            if unsafe { libc::sigaddset(&mut handled, signal) } != 0 {
                return Err(std::io::Error::last_os_error()).context("populate demo signal mask");
            }
        }

        let mut previous = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        let result = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &handled, &mut previous) };
        if result != 0 {
            return Err(std::io::Error::from_raw_os_error(result))
                .context("block demo cleanup signals");
        }
        Ok(Self {
            previous,
            restored: false,
        })
    }

    fn restore(&mut self) -> Result<()> {
        if self.restored {
            return Ok(());
        }
        let result = unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous, std::ptr::null_mut())
        };
        if result != 0 {
            return Err(std::io::Error::from_raw_os_error(result))
                .context("restore demo signal mask");
        }
        self.restored = true;
        Ok(())
    }

    fn pending_signal(&self) -> Result<Option<i32>> {
        let mut pending = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        if unsafe { libc::sigpending(&mut pending) } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("inspect pending demo cleanup signals");
        }
        for signal in [SIGHUP, SIGINT, SIGTERM] {
            let member = unsafe { libc::sigismember(&pending, signal) };
            if member == 1 {
                return Ok(Some(signal));
            }
            if member == -1 {
                return Err(std::io::Error::last_os_error())
                    .context("inspect pending demo signal membership");
            }
        }
        Ok(None)
    }
}

#[cfg(unix)]
impl Drop for HandledSignalMask {
    fn drop(&mut self) {
        if self.restore().is_err() {
            eprintln!("DEMO_CLEANUP_FAILED");
        }
    }
}

fn trusted_temporary_base() -> Result<PathBuf> {
    #[cfg(unix)]
    {
        fs::canonicalize("/tmp").context("resolve fixed system temporary directory")
    }
    #[cfg(not(unix))]
    {
        fs::canonicalize(std::env::temp_dir()).context("resolve system temporary directory")
    }
}

#[cfg(unix)]
fn active_marker_bytes(path: &Path, identity: DirectoryIdentity) -> Result<Vec<u8>> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("fixture-only demo root name is not UTF-8")?;
    Ok(format!(
        "{ACTIVE_MARKER_PREAMBLE}root={name}\ndevice={}\ninode={}\nowner={}\n",
        identity.device, identity.inode, identity.owner
    )
    .into_bytes())
}

#[cfg(unix)]
fn validate_created_root(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        bail!("fixture-only demo root identity or mode refused")
    }
    jcode_base::omnis::validate_private_directory(path, "OMNIS_DEMO_ROOT")?;
    Ok(())
}

#[cfg(not(unix))]
fn validate_created_root(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("fixture-only demo root type refused")
    }
    Ok(())
}

#[cfg(unix)]
#[derive(Clone, Copy)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
    owner: u32,
}

#[cfg(unix)]
fn directory_identity(path: &Path) -> Result<DirectoryIdentity> {
    let metadata = fs::symlink_metadata(path)?;
    Ok(DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
    })
}

#[cfg(unix)]
fn remove_if_same_directory(path: &Path, expected: DirectoryIdentity) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.dev() != expected.device
        || metadata.ino() != expected.inode
        || metadata.uid() != expected.owner
        || metadata.permissions().mode() & 0o7777 != 0o700
        || jcode_base::omnis::validate_private_directory(path, "OMNIS_DEMO_CLEANUP_ROOT").is_err()
    {
        bail!("demo cleanup identity drift refused")
    }
    fs::remove_dir_all(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{DemoRoot, exercise_fixture, trusted_temporary_base};
    use std::fs;
    use std::sync::Mutex;

    #[cfg(unix)]
    use super::{HandledSignalMask, SIGHUP, SIGINT, SIGTERM};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    static DEMO_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn demo_test_guard() -> std::sync::MutexGuard<'static, ()> {
        DEMO_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn fixture_run_cleans_its_private_root() {
        let _test_guard = demo_test_guard();
        let guard = DemoRoot::new().unwrap();
        let path = guard.path().unwrap().to_path_buf();
        let data = exercise_fixture(guard.path().unwrap()).unwrap();
        guard.finish().unwrap();
        assert!(data.fixture_only);
        assert!(!path.exists());
    }

    #[test]
    fn unwind_cleans_the_private_root() {
        let _test_guard = demo_test_guard();
        let mut observed = None;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let guard = DemoRoot::new().unwrap();
            observed = Some(guard.path().unwrap().to_path_buf());
            panic!("fixture-only cleanup probe");
        }));
        assert!(result.is_err());
        if let Some(path) = observed {
            assert!(!path.exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn handled_signal_mask_is_restored_on_unwind() {
        let before = handled_signal_membership();
        let result = std::panic::catch_unwind(|| {
            let _mask = HandledSignalMask::block().unwrap();
            assert_eq!(handled_signal_membership(), [true, true, true]);
            panic!("fixture-only signal-mask restoration probe");
        });
        assert!(result.is_err());
        assert_eq!(handled_signal_membership(), before);
    }

    #[cfg(unix)]
    #[test]
    fn preplanted_matching_root_is_preserved_byte_for_byte() {
        let _test_guard = demo_test_guard();
        let base = trusted_temporary_base().unwrap();
        let preplanted = base.join("omnis-key-demo-2147483646-AbCdEf0123456789GhIjKlMn");
        fs::create_dir(&preplanted).unwrap();
        fs::set_permissions(&preplanted, fs::Permissions::from_mode(0o700)).unwrap();
        let sentinel = preplanted.join("sentinel");
        fs::write(&sentinel, b"preplanted-fixture-only-sentinel").unwrap();
        fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o600)).unwrap();
        let before = fs::read(&sentinel).unwrap();

        let next = DemoRoot::new().unwrap();
        assert_eq!(fs::read(&sentinel).unwrap(), before);
        next.finish().unwrap();
        assert_eq!(fs::read(&sentinel).unwrap(), before);
        fs::remove_dir_all(preplanted).unwrap();
    }

    #[cfg(unix)]
    fn handled_signal_membership() -> [bool; 3] {
        let mut current = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        let result =
            unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut current) };
        assert_eq!(result, 0);
        [SIGHUP, SIGINT, SIGTERM].map(|signal| unsafe { libc::sigismember(&current, signal) == 1 })
    }
}
