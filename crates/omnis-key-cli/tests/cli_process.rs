use serde_json::Value;
use std::ffi::OsStr;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::fd::FromRawFd;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(unix)]
const SIGNAL_SETUP_BARRIER_SOURCE: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int barrier_entered;

static void barrier_after_demo_mkdir(const char *path, mode_t mode, int result) {
    if (result != 0 || path == NULL || (mode & 07777) != 0700) {
        return;
    }
    const char *name = strrchr(path, '/');
    name = name == NULL ? path : name + 1;
    const char *prefix = "omnis-key-demo-";
    if (strncmp(name, prefix, strlen(prefix)) != 0) {
        return;
    }
    if (__sync_lock_test_and_set(&barrier_entered, 1) != 0) {
        return;
    }

    const char *ready = getenv("OMNIS_DEMO_SIGNAL_BARRIER_READY");
    const char *release = getenv("OMNIS_DEMO_SIGNAL_BARRIER_RELEASE");
    if (ready == NULL || release == NULL) {
        _exit(91);
    }
    int ready_fd = open(ready, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (ready_fd < 0) {
        _exit(92);
    }
    if (write(ready_fd, "ready\n", 6) != 6 || close(ready_fd) != 0) {
        _exit(93);
    }
    while (access(release, F_OK) != 0) {
        if (errno != ENOENT) {
            _exit(94);
        }
        usleep(1000);
    }
}

#ifdef __APPLE__
static int omnis_barrier_mkdir(const char *path, mode_t mode) {
    int result = mkdir(path, mode);
    barrier_after_demo_mkdir(path, mode, result);
    return result;
}

static int omnis_barrier_mkdirat(int dirfd, const char *path, mode_t mode) {
    int result = mkdirat(dirfd, path, mode);
    barrier_after_demo_mkdir(path, mode, result);
    return result;
}

#define DYLD_INTERPOSE(replacement, replacee)                                  \
    __attribute__((used)) static struct {                                      \
        const void *replacement;                                               \
        const void *replacee;                                                   \
    } interpose_##replacee __attribute__((section("__DATA,__interpose"))) = {  \
        (const void *)(replacement), (const void *)(replacee)                   \
    }

DYLD_INTERPOSE(omnis_barrier_mkdir, mkdir);
DYLD_INTERPOSE(omnis_barrier_mkdirat, mkdirat);
#else
int mkdir(const char *path, mode_t mode) {
    int (*real_mkdir)(const char *, mode_t) = dlsym(RTLD_NEXT, "mkdir");
    if (real_mkdir == NULL) {
        errno = ENOSYS;
        return -1;
    }
    int result = real_mkdir(path, mode);
    barrier_after_demo_mkdir(path, mode, result);
    return result;
}

int mkdirat(int dirfd, const char *path, mode_t mode) {
    int (*real_mkdirat)(int, const char *, mode_t) = dlsym(RTLD_NEXT, "mkdirat");
    if (real_mkdirat == NULL) {
        errno = ENOSYS;
        return -1;
    }
    int result = real_mkdirat(dirfd, path, mode);
    barrier_after_demo_mkdir(path, mode, result);
    return result;
}
#endif
"#;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_omnis-key"))
}

struct Sandbox {
    _temporary: tempfile::TempDir,
    home: PathBuf,
    jcode_home: PathBuf,
    runtime: PathBuf,
    xdg_state: PathBuf,
    xdg_config: PathBuf,
    working: PathBuf,
    hostile_path: PathBuf,
    hostile_tmp: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let make = |name: &str| {
            let path = temporary.path().join(name);
            fs::create_dir(&path).unwrap();
            #[cfg(unix)]
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(path.join("sentinel"), format!("fixture-only:{name}\n")).unwrap();
            path
        };
        Self {
            home: make("home"),
            jcode_home: make("jcode-home"),
            runtime: make("runtime"),
            xdg_state: make("xdg-state"),
            xdg_config: make("xdg-config"),
            working: make("working"),
            hostile_path: make("hostile-path"),
            hostile_tmp: make("hostile-tmp"),
            _temporary: temporary,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(binary());
        command
            .env_clear()
            .env("HOME", &self.home)
            .env("JCODE_HOME", &self.jcode_home)
            .env("JCODE_RUNTIME_DIR", &self.runtime)
            .env("XDG_STATE_HOME", &self.xdg_state)
            .env("XDG_CONFIG_HOME", &self.xdg_config)
            .env("TMPDIR", &self.hostile_tmp)
            .env("PATH", &self.hostile_path)
            .env("JCODE_HOOKS", "fixture-only-hostile-hook")
            .env("JCODE_PLUGIN_PATH", "fixture-only-hostile-plugin")
            .env("JCODE_CONFIG", "fixture-only-hostile-config")
            .current_dir(&self.working);
        command
    }

    fn controlled_snapshots(&self) -> Vec<(PathBuf, Vec<Entry>)> {
        [
            &self.home,
            &self.jcode_home,
            &self.runtime,
            &self.xdg_state,
            &self.xdg_config,
            &self.working,
            &self.hostile_path,
            &self.hostile_tmp,
        ]
        .into_iter()
        .map(|root| (root.clone(), snapshot(root)))
        .collect()
    }
}

#[derive(Debug, Eq, PartialEq)]
struct Entry {
    relative: PathBuf,
    kind: &'static str,
    mode: u32,
    bytes: Vec<u8>,
    link: Option<PathBuf>,
}

fn snapshot(root: &Path) -> Vec<Entry> {
    fn walk(root: &Path, current: &Path, entries: &mut Vec<Entry>) {
        let mut children: Vec<_> = fs::read_dir(current)
            .unwrap()
            .map(|entry| entry.unwrap())
            .collect();
        children.sort_by_key(|entry| entry.file_name());
        for child in children {
            let path = child.path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            #[cfg(unix)]
            let mode = metadata.permissions().mode() & 0o7777;
            #[cfg(not(unix))]
            let mode = 0;
            if metadata.file_type().is_symlink() {
                entries.push(Entry {
                    relative,
                    kind: "symlink",
                    mode,
                    bytes: Vec::new(),
                    link: Some(fs::read_link(&path).unwrap()),
                });
            } else if metadata.is_dir() {
                entries.push(Entry {
                    relative,
                    kind: "directory",
                    mode,
                    bytes: Vec::new(),
                    link: None,
                });
                walk(root, &path, entries);
            } else {
                entries.push(Entry {
                    relative,
                    kind: "file",
                    mode,
                    bytes: fs::read(&path).unwrap(),
                    link: None,
                });
            }
        }
    }

    let mut entries = Vec::new();
    walk(root, root, &mut entries);
    entries
}

fn run(sandbox: &Sandbox, args: &[&str]) -> Output {
    sandbox.command().args(args).output().unwrap()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn compile_signal_setup_barrier(directory: &Path) -> PathBuf {
    let source = directory.join("signal-setup-barrier.c");
    fs::write(&source, SIGNAL_SETUP_BARRIER_SOURCE).unwrap();
    #[cfg(target_os = "macos")]
    let library = directory.join("signal-setup-barrier.dylib");
    #[cfg(target_os = "linux")]
    let library = directory.join("signal-setup-barrier.so");

    let mut command = Command::new("cc");
    #[cfg(target_os = "macos")]
    command.args(["-dynamiclib", "-fPIC"]);
    #[cfg(target_os = "linux")]
    command.args(["-shared", "-fPIC"]);
    command
        .args(["-Wall", "-Wextra", "-Werror"])
        .arg(&source)
        .arg("-o")
        .arg(&library);
    #[cfg(target_os = "linux")]
    command.arg("-ldl");
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "signal setup barrier compilation failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    library
}

fn exit_code(output: &Output) -> i32 {
    output.status.code().unwrap()
}

fn one_json(output: &Output) -> Value {
    assert!(output.stderr.is_empty());
    let stdout = std::str::from_utf8(&output.stdout).unwrap();
    assert!(stdout.ends_with('\n'));
    assert_eq!(stdout.lines().count(), 1);
    serde_json::from_str(stdout).unwrap()
}

#[test]
fn read_only_and_demo_commands_preserve_every_controlled_root() {
    let sandbox = Sandbox::new();
    let before = sandbox.controlled_snapshots();
    let commands: &[(&[&str], i32)] = &[
        (&["--help"], 0),
        (&["--version"], 0),
        (&["not-a-command"], 2),
        (&["receipts", "status", "--json"], 3),
        (&["receipts", "verify", "--json"], 3),
        (&["demo", "integrity", "--json"], 0),
    ];
    for (args, expected) in commands {
        let output = run(&sandbox, args);
        assert_eq!(
            exit_code(&output),
            *expected,
            "unexpected exit for {args:?}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let public_output = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        for root in [
            &sandbox.home,
            &sandbox.jcode_home,
            &sandbox.runtime,
            &sandbox.xdg_state,
            &sandbox.xdg_config,
            &sandbox.working,
        ] {
            assert!(!public_output.contains(&root.display().to_string()));
        }
        assert_eq!(sandbox.controlled_snapshots(), before);
    }
}

#[test]
fn canonical_record_writes_only_private_receipt_files_and_ignores_runtime_override() {
    let sandbox = Sandbox::new();
    let unrelated_before = [
        snapshot(&sandbox.home),
        snapshot(&sandbox.runtime),
        snapshot(&sandbox.xdg_state),
        snapshot(&sandbox.xdg_config),
        snapshot(&sandbox.working),
        snapshot(&sandbox.hostile_tmp),
    ];
    let output = run(
        &sandbox,
        &[
            "receipts",
            "record",
            "--event-id",
            "fixture:event:one",
            "fixture.record",
            "synthetic fixture-only subject",
            "--evidence-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--json",
        ],
    );
    assert_eq!(exit_code(&output), 0);
    assert_eq!(one_json(&output)["code"], "RECEIPT_APPENDED");
    assert_eq!(
        [
            snapshot(&sandbox.home),
            snapshot(&sandbox.runtime),
            snapshot(&sandbox.xdg_state),
            snapshot(&sandbox.xdg_config),
            snapshot(&sandbox.working),
            snapshot(&sandbox.hostile_tmp),
        ],
        unrelated_before
    );
    assert_eq!(
        relative_paths(&sandbox.jcode_home),
        [
            "sentinel",
            "state",
            "state/omnis-key",
            "state/omnis-key/receipts.jsonl",
            "state/omnis-key/receipts.jsonl.lock",
        ]
    );
    #[cfg(unix)]
    {
        assert_mode(&sandbox.jcode_home.join("state"), 0o700);
        assert_mode(&sandbox.jcode_home.join("state/omnis-key"), 0o700);
        assert_mode(
            &sandbox.jcode_home.join("state/omnis-key/receipts.jsonl"),
            0o600,
        );
        assert_mode(
            &sandbox
                .jcode_home
                .join("state/omnis-key/receipts.jsonl.lock"),
            0o600,
        );
    }

    let before_verify = sandbox.controlled_snapshots();
    let verified = run(&sandbox, &["receipts", "verify", "--json"]);
    assert_eq!(exit_code(&verified), 0);
    assert_eq!(one_json(&verified)["code"], "RECEIPT_CHAIN_VALID");
    assert_eq!(sandbox.controlled_snapshots(), before_verify);
}

#[test]
fn public_parser_rejects_path_and_claim_overrides_without_writes() {
    let sandbox = Sandbox::new();
    let before = sandbox.controlled_snapshots();
    for args in [
        vec!["receipts", "status", "--ledger", "/tmp/attacker"],
        vec![
            "receipts",
            "record",
            "--event-id",
            "fixture:event",
            "fixture.kind",
            "fixture subject",
            "--evidence-sha256",
            "a",
            "--claim-ceiling",
            "local-verification",
        ],
    ] {
        let output = run(&sandbox, &args);
        assert_eq!(exit_code(&output), 2);
        assert!(output.stdout.is_empty());
        assert_eq!(sandbox.controlled_snapshots(), before);
    }
}

#[cfg(unix)]
#[test]
fn unsafe_ledger_and_parent_modes_are_refused_without_repair() {
    let sandbox = Sandbox::new();
    append_fixture(&sandbox);
    let ledger = sandbox.jcode_home.join("state/omnis-key/receipts.jsonl");
    fs::set_permissions(&ledger, fs::Permissions::from_mode(0o644)).unwrap();
    let before = fs::read(&ledger).unwrap();
    let output = run(&sandbox, &["receipts", "status", "--json"]);
    assert_eq!(exit_code(&output), 3);
    assert_eq!(one_json(&output)["code"], "RECEIPT_STATE_UNSAFE");
    assert_eq!(fs::read(&ledger).unwrap(), before);
    assert_mode(&ledger, 0o644);

    fs::set_permissions(&ledger, fs::Permissions::from_mode(0o600)).unwrap();
    let parent = ledger.parent().unwrap();
    fs::set_permissions(parent, fs::Permissions::from_mode(0o755)).unwrap();
    let output = run(&sandbox, &["receipts", "verify", "--json"]);
    assert_eq!(exit_code(&output), 3);
    assert_eq!(one_json(&output)["code"], "RECEIPT_STATE_UNSAFE");
    assert_mode(parent, 0o755);
}

#[cfg(unix)]
#[test]
fn symlinked_canonical_ledger_is_refused_without_touching_target() {
    use std::os::unix::fs::symlink;

    let sandbox = Sandbox::new();
    let parent = sandbox.jcode_home.join("state/omnis-key");
    fs::create_dir_all(&parent).unwrap();
    fs::set_permissions(
        sandbox.jcode_home.join("state"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    let victim = sandbox.working.join("victim");
    let original = b"fixture-only victim bytes";
    fs::write(&victim, original).unwrap();
    symlink(&victim, parent.join("receipts.jsonl")).unwrap();

    let output = run(&sandbox, &["receipts", "verify", "--json"]);
    assert_eq!(exit_code(&output), 3);
    assert_eq!(one_json(&output)["code"], "RECEIPT_STATE_UNSAFE");
    assert_eq!(fs::read(&victim).unwrap(), original);
}

#[test]
fn safety_reconciliation_writes_only_its_named_private_state() {
    let sandbox = Sandbox::new();
    let unrelated_before = [
        snapshot(&sandbox.home),
        snapshot(&sandbox.runtime),
        snapshot(&sandbox.xdg_state),
        snapshot(&sandbox.xdg_config),
        snapshot(&sandbox.working),
    ];
    let output = run(&sandbox, &["receipts", "reconcile-safety", "--json"]);
    assert_eq!(exit_code(&output), 0);
    let value = one_json(&output);
    assert_eq!(value["code"], "SAFETY_ALREADY_RECONCILED");
    assert_eq!(value["data"]["pendingBefore"], 0);
    assert_eq!(value["data"]["pendingAfter"], 0);
    assert_eq!(
        [
            snapshot(&sandbox.home),
            snapshot(&sandbox.runtime),
            snapshot(&sandbox.xdg_state),
            snapshot(&sandbox.xdg_config),
            snapshot(&sandbox.working),
        ],
        unrelated_before
    );
    assert_eq!(
        relative_paths(&sandbox.jcode_home),
        [
            "safety",
            "safety/state.v1.initialized",
            "safety/state.v1.json",
            "safety/state.v1.lock",
            "sentinel",
        ]
    );
    #[cfg(unix)]
    {
        assert_mode(&sandbox.jcode_home.join("safety"), 0o700);
        for name in [
            "safety/state.v1.initialized",
            "safety/state.v1.json",
            "safety/state.v1.lock",
        ] {
            assert_mode(&sandbox.jcode_home.join(name), 0o600);
        }
    }
    let before_second = sandbox.controlled_snapshots();
    let second = run(&sandbox, &["receipts", "reconcile-safety", "--json"]);
    assert_eq!(exit_code(&second), 0);
    assert_eq!(sandbox.controlled_snapshots(), before_second);
}

#[cfg(unix)]
#[test]
fn no_argument_pty_handoff_uses_only_an_exact_sibling_fixture() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = temporary.path();
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    let omnis = directory.join("omnis-key");
    fs::copy(binary(), &omnis).unwrap();
    fs::set_permissions(&omnis, fs::Permissions::from_mode(0o700)).unwrap();
    let jcode = directory.join("jcode");
    fs::write(&jcode, b"#!/bin/sh\nprintf 'FIXTURE_ONLY_AGENT_FRAME\\n'\n").unwrap();
    fs::set_permissions(&jcode, fs::Permissions::from_mode(0o700)).unwrap();

    let (master, slave) = open_pty();
    let stdin = slave.try_clone().unwrap();
    let stdout = slave.try_clone().unwrap();
    let stderr = slave.try_clone().unwrap();
    let mut child = Command::new(&omnis)
        .env_clear()
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .unwrap();
    drop(slave);
    let reader = std::thread::spawn(move || {
        let mut output = String::new();
        master.take(1024).read_to_string(&mut output).unwrap();
        output
    });
    let status = child.wait().unwrap();
    let output = reader.join().unwrap();
    assert!(status.success());
    assert!(
        output.contains("FIXTURE_ONLY_AGENT_FRAME"),
        "PTY output was {output:?}"
    );
}

#[cfg(unix)]
#[test]
fn catchable_termination_removes_the_invocations_demo_root() {
    let base = fs::canonicalize("/tmp").unwrap();
    let mut completed_probe = false;
    for _ in 0..8 {
        let sandbox = Sandbox::new();
        let mut child = sandbox
            .command()
            .args(["demo", "integrity", "--json"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let prefix = format!("omnis-key-demo-{}-", child.id());
        let deadline = Instant::now() + Duration::from_secs(3);
        let fixture = loop {
            if let Some(path) = find_live_demo_root(&base, &prefix) {
                break Some(path);
            }
            if child.try_wait().unwrap().is_some() || Instant::now() >= deadline {
                break None;
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        let Some(fixture) = fixture else {
            let _ = child.wait();
            continue;
        };
        assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
        let status = child.wait().unwrap();
        assert_eq!(status.code(), Some(128 + libc::SIGTERM));
        assert!(!fixture.exists());
        completed_probe = true;
        break;
    }
    assert!(
        completed_probe,
        "could not observe the live fixture-only demo root"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn catchable_signal_at_post_mkdir_setup_barrier_is_deferred_until_cleanup_is_owned() {
    let temporary = tempfile::tempdir().unwrap();
    let interposer = compile_signal_setup_barrier(temporary.path());
    let ready = temporary.path().join("ready");
    let release = temporary.path().join("release");
    let sandbox = Sandbox::new();
    let mut command = sandbox.command();
    command
        .args(["demo", "integrity", "--json"])
        .env("OMNIS_DEMO_SIGNAL_BARRIER_READY", &ready)
        .env("OMNIS_DEMO_SIGNAL_BARRIER_RELEASE", &release)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(target_os = "macos")]
    command
        .env("DYLD_INSERT_LIBRARIES", &interposer)
        .env("DYLD_FORCE_FLAT_NAMESPACE", "1");
    #[cfg(target_os = "linux")]
    command.env("LD_PRELOAD", &interposer);
    let mut child = command.spawn().unwrap();
    let base = fs::canonicalize("/tmp").unwrap();
    let prefix = format!("omnis-key-demo-{}-", child.id());

    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready.exists() {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("demo exited before reaching post-mkdir barrier: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "demo did not reach post-mkdir signal barrier"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    let fixture = find_demo_root(&base, &prefix).expect("barrier root was not observable");
    assert_mode(&fixture, 0o700);

    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
    std::thread::sleep(Duration::from_millis(20));
    if let Some(status) = child.try_wait().unwrap() {
        let _ = fs::remove_dir_all(&fixture);
        panic!("SIGTERM was not deferred during setup: {status}");
    }

    fs::write(&release, b"release\n").unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = unsafe { libc::kill(child.id() as i32, libc::SIGKILL) };
            let _ = child.wait();
            let _ = fs::remove_dir_all(&fixture);
            panic!("demo did not handle deferred SIGTERM");
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    assert_eq!(status.code(), Some(128 + libc::SIGTERM));
    if fixture.exists() {
        let _ = fs::remove_dir_all(&fixture);
        panic!("deferred SIGTERM left the post-mkdir demo root");
    }
}

fn append_fixture(sandbox: &Sandbox) {
    let output = run(
        sandbox,
        &[
            "receipts",
            "record",
            "--event-id",
            "fixture:event",
            "fixture.kind",
            "fixture subject",
            "--evidence-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--json",
        ],
    );
    assert_eq!(exit_code(&output), 0);
}

fn relative_paths(root: &Path) -> Vec<String> {
    snapshot(root)
        .into_iter()
        .map(|entry| entry.relative.to_string_lossy().replace('\\', "/"))
        .collect()
}

#[cfg(unix)]
fn assert_mode(path: &Path, expected: u32) {
    assert_eq!(
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777,
        expected,
        "unexpected mode for {}",
        path.display()
    );
}

#[cfg(unix)]
fn open_pty() -> (fs::File, fs::File) {
    let mut master = -1;
    let mut slave = -1;
    let result = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(result, 0);
    unsafe { (fs::File::from_raw_fd(master), fs::File::from_raw_fd(slave)) }
}

#[cfg(unix)]
fn find_live_demo_root(base: &Path, prefix: &str) -> Option<PathBuf> {
    fs::read_dir(base)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|name| name.starts_with(prefix))
                && path.join(".fixture-only-active.lock").is_file()
        })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn find_demo_root(base: &Path, prefix: &str) -> Option<PathBuf> {
    fs::read_dir(base)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|name| name.starts_with(prefix))
        })
}
