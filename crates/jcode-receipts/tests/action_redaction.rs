//! Secret probe + evidence storage tests (FIX 1 + FIX 2).
//!
//! A test that only asserts "secret absent" while evidence never hits disk cannot fail
//! when redaction is broken. We assert both absence of secrets and presence of safe fields.

use jcode_receipts::{
    BashReceiptInput, EditReceiptInput, program_name, record_bash, record_edit, sha256_hex, verify,
};
use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use tempfile::TempDir;

fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
}

fn with_ledger_home<T>(f: impl FnOnce(&TempDir) -> T) -> T {
    let _g = env_lock();
    let dir = TempDir::new().unwrap();
    let home = dir.path().join("home");
    // Do NOT pre-create state/ — fresh install path must create 0700 parents itself.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::create_dir_all(&home).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[cfg(not(unix))]
    fs::create_dir_all(&home).unwrap();

    let prev = std::env::var_os("JCODE_HOME");
    // SAFETY: tests hold env_lock(); single-threaded mutation of process env.
    unsafe {
        std::env::set_var("JCODE_HOME", &home);
        std::env::remove_var("JCODE_NO_RECEIPTS");
        std::env::remove_var("OMNIS_NO_RECEIPTS");
        std::env::remove_var("JCODE_RECEIPT_FULL_ARGV");
    }
    let out = f(&dir);
    unsafe {
        match prev {
            Some(v) => std::env::set_var("JCODE_HOME", v),
            None => std::env::remove_var("JCODE_HOME"),
        }
    }
    out
}

fn ledger_path() -> PathBuf {
    PathBuf::from(std::env::var("JCODE_HOME").unwrap()).join("state/omnis-key/receipts.jsonl")
}

#[test]
fn secret_probe_full_argv_never_in_ledger_by_default() {
    with_ledger_home(|_| {
        let secret = "sk-ant-SECRET123-must-not-leak";
        let cmd = format!("curl -H \"Authorization: Bearer {secret}\" https://example.com");
        let cwd = PathBuf::from(std::env::var("JCODE_HOME").unwrap());
        record_bash(BashReceiptInput {
            command: &cmd,
            exit_code: 0,
            cwd: &cwd,
            repo_root: &cwd,
        })
        .expect("record bash")
        .expect("some outcome");

        let ledger = ledger_path();
        let body = fs::read_to_string(&ledger).expect("ledger exists");

        // Negative: secrets must not appear.
        assert!(
            !body.contains(secret),
            "SECRET must not appear in ledger:\n{body}"
        );
        assert!(
            !body.contains("Authorization"),
            "raw header must not appear:\n{body}"
        );

        // Positive: safe evidence fields MUST be present (FIX 1+2). Without this,
        // a build that never stores evidence still "passes" the secret check.
        assert!(
            body.contains("\"argv_program\":\"curl\"")
                || body.contains("\"argv_program\": \"curl\""),
            "argv_program must be stored on the ledger line:\n{body}"
        );
        assert!(
            body.contains("argv_sha256"),
            "argv_sha256 must be stored:\n{body}"
        );
        assert!(
            body.contains("\"exit_code\":0") || body.contains("\"exit_code\": 0"),
            "exit_code must be stored:\n{body}"
        );
        assert!(
            body.contains("\"evidence\""),
            "recoverable evidence object must be on the ledger line:\n{body}"
        );
        // argv_full must be absent by default
        assert!(
            !body.contains("argv_full"),
            "argv_full must not be stored without --receipt-full-argv:\n{body}"
        );

        let expected_hash = format!("sha256:{}", sha256_hex(cmd.as_bytes()));
        assert!(
            body.contains(&expected_hash) || body.contains(&expected_hash[7..]),
            "argv_sha256 value should appear in stored evidence:\n{body}"
        );

        // recursive grep of home for secret
        let mut found = false;
        for entry in walkdir_simple(PathBuf::from(std::env::var("JCODE_HOME").unwrap())) {
            if let Ok(t) = fs::read_to_string(&entry) {
                if t.contains(secret) {
                    found = true;
                    break;
                }
            }
        }
        assert!(!found, "secret appeared under JCODE_HOME");
    });
}

fn walkdir_simple(root: PathBuf) -> Vec<PathBuf> {
    let mut out = Vec::new();
    fn rec(p: PathBuf, out: &mut Vec<PathBuf>) {
        if p.is_file() {
            out.push(p);
            return;
        }
        if let Ok(rd) = fs::read_dir(&p) {
            for e in rd.flatten() {
                rec(e.path(), out);
            }
        }
    }
    rec(root, &mut out);
    out
}

#[test]
fn edit_receipt_stores_content_hashes_not_body() {
    with_ledger_home(|_| {
        let cwd = PathBuf::from(std::env::var("JCODE_HOME").unwrap());
        let secret_body = "password=hunter2_should_not_appear";
        record_edit(EditReceiptInput {
            target_repo_relative: "cart.js",
            before: "old",
            after: secret_body,
            cwd: &cwd,
            repo_root: &cwd,
        })
        .unwrap()
        .unwrap();
        let body = fs::read_to_string(ledger_path()).unwrap();
        assert!(!body.contains("hunter2"));
        assert!(body.contains("edit:cart.js") || body.contains("agent.edit"));
        assert!(body.contains("content_before_sha256"));
        assert!(body.contains("content_after_sha256"));
        assert!(
            body.contains("\"target\":\"cart.js\"") || body.contains("\"target\": \"cart.js\"")
        );
        let v = verify(&ledger_path()).unwrap();
        assert!(v.valid());
        assert_eq!(v.entries(), 1);
    });
}

#[test]
fn program_name_only() {
    assert_eq!(
        program_name("curl -H 'Authorization: Bearer sk-ant-SECRET123' https://x"),
        "curl"
    );
}

#[test]
#[cfg(unix)]
fn fresh_jcode_home_creates_private_ledger_parents() {
    use std::os::unix::fs::PermissionsExt;
    with_ledger_home(|_| {
        let cwd = PathBuf::from(std::env::var("JCODE_HOME").unwrap());
        // state/ must not exist yet
        assert!(!cwd.join("state").exists());
        record_bash(BashReceiptInput {
            command: "true",
            exit_code: 0,
            cwd: &cwd,
            repo_root: &cwd,
        })
        .unwrap()
        .unwrap();

        let state = cwd.join("state");
        let omnis = state.join("omnis-key");
        for p in [&state, &omnis] {
            let mode = fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{} mode was {mode:o}, want 700", p.display());
        }
        let v = verify(&ledger_path()).unwrap();
        assert!(v.valid());
    });
}
