use jcode_claims::{
    ClaimEvaluateOptions, ClaimInput, ClaimKind, ClaimVerdict, VERDICT_VOCABULARY, evaluate_claim,
    evaluate_claims,
};
use std::collections::BTreeSet;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn git_repo() -> TempDir {
    let dir = TempDir::new().unwrap();
    let p = dir.path();
    Command::new("git")
        .args(["init"])
        .current_dir(p)
        .status()
        .unwrap();
    Command::new("git")
        .args(["config", "user.email", "s1@test.local"])
        .current_dir(p)
        .status()
        .unwrap();
    Command::new("git")
        .args(["config", "user.name", "S1"])
        .current_dir(p)
        .status()
        .unwrap();
    fs::write(p.join("README.md"), "x\n").unwrap();
    Command::new("git")
        .args(["add", "README.md"])
        .current_dir(p)
        .status()
        .unwrap();
    Command::new("git")
        .args(["commit", "-m", "i"])
        .current_dir(p)
        .status()
        .unwrap();
    dir
}

#[test]
fn vocabulary_frozen() {
    assert_eq!(VERDICT_VOCABULARY.len(), 5);
}

#[test]
fn files_changed_certifies_and_is_deterministic() {
    let dir = git_repo();
    fs::write(dir.path().join("only.rs"), "fn o(){}\n").unwrap();
    // Ledger must live *outside* the repo so appending receipts does not
    // alter the files-changed set under test.
    let ledger_dir = TempDir::new().unwrap();
    let ledger = ledger_dir.path().join("claims.jsonl");
    let opts = ClaimEvaluateOptions {
        repo: dir.path().to_path_buf(),
        ledger: Some(ledger.clone()),
    };
    let input = ClaimInput {
        id: "c-files".into(),
        kind: ClaimKind::FilesChanged {
            declared: BTreeSet::from(["only.rs".into()]),
            base: Some("HEAD".into()),
        },
        surface: Some("I only changed only.rs".into()),
    };
    let a = evaluate_claim(input.clone(), &opts);
    let b = evaluate_claim(input, &opts);
    assert_eq!(a.verdict, ClaimVerdict::Certified);
    assert_eq!(a.verdict, b.verdict);
    assert!(a.verification.is_some());
    assert!(a.receipt.is_some());
}

#[test]
fn files_changed_refutes_extra_file() {
    let dir = git_repo();
    fs::write(dir.path().join("a.rs"), "a\n").unwrap();
    fs::write(dir.path().join("b.rs"), "b\n").unwrap();
    let opts = ClaimEvaluateOptions {
        repo: dir.path().to_path_buf(),
        ledger: None,
    };
    let out = evaluate_claim(
        ClaimInput {
            id: "c".into(),
            kind: ClaimKind::FilesChanged {
                declared: BTreeSet::from(["a.rs".into()]),
                base: Some("HEAD".into()),
            },
            surface: None,
        },
        &opts,
    );
    assert_eq!(out.verdict, ClaimVerdict::Refuted);
}

#[test]
fn short_circuit_emits_no_verification_field() {
    let dir = git_repo();
    let opts = ClaimEvaluateOptions {
        repo: dir.path().to_path_buf(),
        ledger: None,
    };
    let out = evaluate_claim(
        ClaimInput {
            id: "fast".into(),
            kind: ClaimKind::PerformanceFaster {
                note: Some("no benchmarks".into()),
            },
            surface: Some("this is faster".into()),
        },
        &opts,
    );
    assert_eq!(out.verdict, ClaimVerdict::RefusedNoVerifier);
    assert!(
        out.verification.is_none(),
        "SAMMICH short-circuit: never-verifiable claims emit no verification field"
    );
    // JSON must omit the key entirely
    let v = serde_json::to_value(&out).unwrap();
    assert!(v.get("verification").is_none());
}

#[test]
fn claims_strict_exits_nonzero_on_refuted() {
    let dir = git_repo();
    fs::write(dir.path().join("x.rs"), "x\n").unwrap();
    let opts = ClaimEvaluateOptions {
        repo: dir.path().to_path_buf(),
        ledger: None,
    };
    let batch = evaluate_claims(
        vec![
            ClaimInput {
                id: "ok-refuse".into(),
                kind: ClaimKind::PerformanceFaster { note: None },
                surface: None,
            },
            ClaimInput {
                id: "lie".into(),
                kind: ClaimKind::FilesChanged {
                    declared: BTreeSet::from(["nope.rs".into()]),
                    base: Some("HEAD".into()),
                },
                surface: None,
            },
        ],
        &opts,
    );
    assert!(batch.any_refuted);
    assert_eq!(batch.strict_exit_code(), 2);
    assert!(batch.refused_count >= 1);
}

#[test]
fn build_and_tests_p1() {
    let dir = git_repo();
    let opts = ClaimEvaluateOptions {
        repo: dir.path().to_path_buf(),
        ledger: None,
    };
    let build_ok = evaluate_claim(
        ClaimInput {
            id: "b".into(),
            kind: ClaimKind::BuildPasses {
                command: vec!["true".into()],
            },
            surface: None,
        },
        &opts,
    );
    assert_eq!(build_ok.verdict, ClaimVerdict::Certified);

    let tests_bad = evaluate_claim(
        ClaimInput {
            id: "t".into(),
            kind: ClaimKind::TestsPass {
                command: vec!["false".into()],
            },
            surface: None,
        },
        &opts,
    );
    assert_eq!(tests_bad.verdict, ClaimVerdict::Refuted);
}
