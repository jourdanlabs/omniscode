use jcode_verifiers::{VerifierDecision, verify_build, verify_files_changed, verify_tests};
use std::collections::BTreeSet;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn init_git_repo() -> TempDir {
    let dir = TempDir::new().expect("temp");
    let p = dir.path();
    assert!(
        Command::new("git")
            .args(["init"])
            .current_dir(p)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .args(["config", "user.email", "claim-ledger@test.local"])
            .current_dir(p)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .args(["config", "user.name", "Claim Ledger"])
            .current_dir(p)
            .status()
            .unwrap()
            .success()
    );
    fs::write(p.join("README.md"), "hello\n").unwrap();
    assert!(
        Command::new("git")
            .args(["add", "README.md"])
            .current_dir(p)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .args(["commit", "-m", "init"])
            .current_dir(p)
            .status()
            .unwrap()
            .success()
    );
    dir
}

#[test]
fn files_changed_certifies_exact_set() {
    let dir = init_git_repo();
    let p = dir.path();
    fs::write(p.join("a.rs"), "fn a() {}\n").unwrap();
    fs::write(p.join("b.rs"), "fn b() {}\n").unwrap();

    let declared: BTreeSet<String> = ["a.rs".into(), "b.rs".into()].into_iter().collect();
    let r = verify_files_changed(p, &declared, Some("HEAD")).unwrap();
    assert_eq!(r.decision, VerifierDecision::ProvedTrue);

    // Determinism: second run matches.
    let r2 = verify_files_changed(p, &declared, Some("HEAD")).unwrap();
    assert_eq!(r.decision, r2.decision);
    assert_eq!(r.evidence.facts, r2.evidence.facts);
}

#[test]
fn files_changed_refutes_undeclared_file() {
    let dir = init_git_repo();
    let p = dir.path();
    fs::write(p.join("a.rs"), "fn a() {}\n").unwrap();
    fs::write(p.join("secret.rs"), "fn s() {}\n").unwrap();

    let declared: BTreeSet<String> = ["a.rs".into()].into_iter().collect();
    let r = verify_files_changed(p, &declared, Some("HEAD")).unwrap();
    assert_eq!(r.decision, VerifierDecision::ProvedFalse);
    let extra = r.evidence.facts.get("extra").unwrap();
    assert!(extra.to_string().contains("secret.rs"));
}

#[test]
fn build_and_tests_use_exit_code() {
    let dir = TempDir::new().unwrap();
    let p = dir.path();

    let ok = verify_build(p, &["true".into()]).unwrap();
    assert_eq!(ok.decision, VerifierDecision::ProvedTrue);

    let bad = verify_build(p, &["false".into()]).unwrap();
    assert_eq!(bad.decision, VerifierDecision::ProvedFalse);

    let tok = verify_tests(p, &["true".into()]).unwrap();
    assert_eq!(tok.decision, VerifierDecision::ProvedTrue);

    let tbad = verify_tests(p, &["false".into()]).unwrap();
    assert_eq!(tbad.decision, VerifierDecision::ProvedFalse);

    // Determinism
    assert_eq!(
        verify_build(p, &["true".into()]).unwrap().decision,
        VerifierDecision::ProvedTrue
    );
}
