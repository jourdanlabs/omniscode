use super::*;
use serde_json::{Value, json};
use std::ffi::OsString;

fn invoke(args: &[&str]) -> (i32, String, String) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = run_with_io(args, &mut stdout, &mut stderr);
    (
        code,
        String::from_utf8(stdout).unwrap(),
        String::from_utf8(stderr).unwrap(),
    )
}

fn parse_one_json(stdout: &str) -> Value {
    assert!(stdout.ends_with('\n'));
    assert_eq!(stdout.lines().count(), 1);
    serde_json::from_str(stdout).unwrap()
}

#[test]
fn version_contract_has_one_product_version_source() {
    let (code, stdout, stderr) = invoke(&["omnis-key", "--version"]);
    assert_eq!(code, 0);
    assert_eq!(
        stdout,
        format!(
            "omnis-key {PRODUCT_VERSION}\n\
             {COMPATIBILITY_BASE_NAME} compatibility base {COMPATIBILITY_BASE_VERSION}\n"
        )
    );
    assert!(stderr.is_empty());

    let (code, stdout, stderr) = invoke(&["omnis-key", "version", "--json"]);
    assert_eq!(code, 0);
    assert!(stderr.is_empty());
    let value = parse_one_json(&stdout);
    assert_eq!(
        value,
        json!({
            "schemaVersion": 1,
            "command": "version",
            "ok": true,
            "code": "VERSION",
            "data": {
                "productVersion": PRODUCT_VERSION,
                "compatibilityBaseName": COMPATIBILITY_BASE_NAME,
                "compatibilityBaseVersion": COMPATIBILITY_BASE_VERSION
            }
        })
    );
    assert_eq!(PRODUCT_VERSION, env!("CARGO_PKG_VERSION"));
}

#[test]
fn public_parser_rejects_ledger_and_caller_selected_claim_ceiling() {
    for args in [
        vec!["omnis-key", "receipts", "status", "--ledger", "/tmp/x"],
        vec![
            "omnis-key",
            "receipts",
            "record",
            "--event-id",
            "event:one",
            "kind",
            "subject",
            "--evidence-sha256",
            "a",
            "--claim-ceiling",
            "local-verification",
        ],
        vec!["omnis-key", "omnis", "verify", "--ledger", "/tmp/x"],
    ] {
        let (code, stdout, stderr) = invoke(&args);
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(stderr.contains("unexpected argument"));
    }
}

#[test]
fn empty_chain_is_a_refusal_with_the_exact_shape() {
    let temporary = tempfile::tempdir().unwrap();
    let context =
        receipts::ReceiptContext::fixture(temporary.path().join("absent").join("receipts.jsonl"));
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = receipts::status(&context, true, "receipts.verify", &mut stdout, &mut stderr);
    assert_eq!(code, 3);
    assert!(stderr.is_empty());
    assert_eq!(
        parse_one_json(std::str::from_utf8(&stdout).unwrap()),
        json!({
            "schemaVersion": 1,
            "command": "receipts.verify",
            "ok": false,
            "code": "EMPTY_NOT_YET_EVIDENCED",
            "data": {
                "state": "EMPTY",
                "entryCount": 0,
                "headSha256": null
            }
        })
    );
    assert!(!temporary.path().join("absent").exists());
}

#[test]
fn record_replay_verify_and_conflict_follow_the_frozen_contract() {
    let temporary = tempfile::tempdir().unwrap();
    let ledger = temporary.path().join("receipts.jsonl");
    let context = receipts::ReceiptContext::fixture(ledger.clone());
    let input = || receipts::RecordInput {
        event_id: "event:one".to_string(),
        kind: "source.review".to_string(),
        subject: "synthetic fixture".to_string(),
        evidence_sha256: "a".repeat(64),
    };

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    assert_eq!(
        receipts::record(&context, input(), true, &mut stdout, &mut stderr),
        0
    );
    let first = parse_one_json(std::str::from_utf8(&stdout).unwrap());
    assert_eq!(first["code"], "RECEIPT_APPENDED");
    assert_eq!(first["data"]["disposition"], "APPENDED");
    assert_eq!(first["data"]["claimCeiling"], "local-record");
    assert_eq!(first["data"]["receiptSha256"].as_str().unwrap().len(), 64);
    assert!(!first.to_string().contains(&ledger.display().to_string()));

    stdout.clear();
    assert_eq!(
        receipts::record(&context, input(), true, &mut stdout, &mut stderr),
        0
    );
    let replay = parse_one_json(std::str::from_utf8(&stdout).unwrap());
    assert_eq!(replay["code"], "RECEIPT_EXISTING");
    assert_eq!(replay["data"]["disposition"], "EXISTING");

    stdout.clear();
    assert_eq!(
        receipts::status(&context, true, "receipts.verify", &mut stdout, &mut stderr,),
        0
    );
    let verified = parse_one_json(std::str::from_utf8(&stdout).unwrap());
    assert_eq!(verified["code"], "RECEIPT_CHAIN_VALID");
    assert_eq!(verified["data"]["state"], "VALID");
    assert_eq!(verified["data"]["entryCount"], 1);

    stdout.clear();
    let mut conflict = input();
    conflict.subject = "drifted".to_string();
    assert_eq!(
        receipts::record(&context, conflict, true, &mut stdout, &mut stderr),
        3
    );
    assert_eq!(
        parse_one_json(std::str::from_utf8(&stdout).unwrap())["code"],
        "RECEIPT_EVENT_CONFLICT"
    );
}

#[test]
fn invalid_record_input_exits_two_without_success_shape() {
    let temporary = tempfile::tempdir().unwrap();
    let context = receipts::ReceiptContext::fixture(temporary.path().join("receipts.jsonl"));
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = receipts::record(
        &context,
        receipts::RecordInput {
            event_id: "bad event id".to_string(),
            kind: "kind".to_string(),
            subject: "subject".to_string(),
            evidence_sha256: "a".repeat(64),
        },
        true,
        &mut stdout,
        &mut stderr,
    );
    assert_eq!(code, 2);
    let value = parse_one_json(std::str::from_utf8(&stdout).unwrap());
    assert_eq!(value["ok"], false);
    assert_eq!(value["code"], "INVALID_RECEIPT_INPUT");
    assert_eq!(value["data"], Value::Null);
    assert!(!temporary.path().join("receipts.jsonl").exists());
}

#[test]
fn demo_json_is_exact_and_host_identifier_free() {
    let (code, stdout, stderr) = invoke(&["omnis-key", "demo", "integrity", "--json"]);
    assert_eq!(code, 0);
    assert!(stderr.is_empty());
    assert_eq!(
        parse_one_json(&stdout),
        json!({
            "schemaVersion": 1,
            "command": "demo.integrity",
            "ok": true,
            "code": "DEMO_INTEGRITY_PASSED",
            "data": {
                "fixtureOnly": true,
                "firstAppend": "APPENDED",
                "exactReplay": "EXISTING",
                "validChain": true,
                "tamperedCopyRefused": true,
                "tamperRefusalCode": "RECEIPT_CHAIN_INVALID",
                "executionAuthorized": false
            }
        })
    );
    for forbidden in [
        std::env::var("HOME").ok(),
        std::env::var("USER").ok(),
        hostname_for_test(),
    ]
    .into_iter()
    .flatten()
    .filter(|value| !value.is_empty())
    {
        assert!(!stdout.contains(&forbidden));
    }
}

#[test]
fn inactive_checkpoint_refuses_with_exit_four_and_one_json_object() {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = checkpoint::emit_checkpoint_error(
        "checkpoint.verify-anchored",
        &anyhow::anyhow!("OMNIS_CHECKPOINT_AUTHORITY_UNSUPPORTED_PLATFORM"),
        true,
        &mut stdout,
        &mut stderr,
    );
    assert_eq!(code, 4);
    assert!(stderr.is_empty());
    let value = parse_one_json(std::str::from_utf8(&stdout).unwrap());
    assert_eq!(value["ok"], false);
    assert_eq!(value["code"], "CHECKPOINT_AUTHORITY_UNAVAILABLE");
    assert_eq!(value["data"], Value::Null);
}

#[test]
fn compatibility_detection_is_exact() {
    let yes = vec![
        OsString::from("jcode"),
        OsString::from("omnis"),
        OsString::from("status"),
    ];
    let no = vec![OsString::from("jcode"), OsString::from("version")];
    assert!(is_jcode_omnis_invocation(&yes));
    assert!(!is_jcode_omnis_invocation(&no));

    let globals_before = vec![
        OsString::from("jcode"),
        OsString::from("--quiet"),
        OsString::from("--cwd"),
        OsString::from("/synthetic/work"),
        OsString::from("omnis"),
        OsString::from("receipts"),
        OsString::from("status"),
    ];
    assert!(is_jcode_omnis_invocation(&globals_before));

    let option_value_named_omnis = vec![
        OsString::from("jcode"),
        OsString::from("--cwd"),
        OsString::from("omnis"),
        OsString::from("status"),
    ];
    assert!(!is_jcode_omnis_invocation(&option_value_named_omnis));
}

#[test]
fn compatibility_translation_preserves_only_the_integrity_command_slice() {
    let args = vec![
        OsString::from("jcode"),
        OsString::from("--quiet"),
        OsString::from("--provider=auto"),
        OsString::from("omnis"),
        OsString::from("receipts"),
        OsString::from("verify"),
        OsString::from("--json"),
    ];
    let super::CompatibilityTranslation::Run(translated) = super::translate_jcode_omnis_args(&args)
    else {
        panic!("global-before-command invocation was not routed");
    };
    assert_eq!(
        translated,
        ["omnis-key", "receipts", "verify", "--json"]
            .into_iter()
            .map(OsString::from)
            .collect::<Vec<_>>()
    );
}

#[test]
fn compatibility_translation_handles_the_full_root_global_placement_matrix() {
    let cases: &[(&[&str], &[&str])] = &[
        (
            &["jcode", "--auto-update", "omnis", "status", "--json"],
            &["omnis-key", "omnis", "status", "--json"],
        ),
        (
            &[
                "jcode",
                "--resume",
                "fixture-session",
                "omnis",
                "status",
                "--json",
            ],
            &["omnis-key", "omnis", "status", "--json"],
        ),
        (
            &["jcode", "--resume", "omnis", "status", "--json"],
            &["omnis-key", "omnis", "status", "--json"],
        ),
        (
            &["jcode", "-pauto", "-C/tmp", "-mfixture", "omnis", "verify"],
            &["omnis-key", "omnis", "verify"],
        ),
        (
            &["jcode", "omnis", "--quiet", "status", "--json"],
            &["omnis-key", "omnis", "status", "--json"],
        ),
        (
            &["jcode", "omnis", "--provider", "auto", "status", "--json"],
            &["omnis-key", "omnis", "status", "--json"],
        ),
        (
            &[
                "jcode",
                "omnis",
                "receipts",
                "--cwd",
                "/synthetic",
                "status",
                "--json",
            ],
            &["omnis-key", "receipts", "status", "--json"],
        ),
        (
            &[
                "jcode",
                "omnis",
                "--auto-update",
                "checkpoint",
                "verify-anchored",
                "--json",
            ],
            &["omnis-key", "checkpoint", "verify-anchored", "--json"],
        ),
        (
            &[
                "jcode",
                "omnis",
                "receipts",
                "record",
                "--event-id",
                "fixture:dash",
                "--evidence-sha256",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "kind",
                "--",
                "--quiet",
            ],
            &[
                "omnis-key",
                "receipts",
                "record",
                "--event-id",
                "fixture:dash",
                "--evidence-sha256",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "kind",
                "--",
                "--quiet",
            ],
        ),
    ];

    for (input, expected) in cases {
        let input = input.iter().map(OsString::from).collect::<Vec<_>>();
        let CompatibilityTranslation::Run(translated) = super::translate_jcode_omnis_args(&input)
        else {
            panic!("valid compatibility invocation was not translated: {input:?}");
        };
        assert_eq!(
            translated,
            expected.iter().map(OsString::from).collect::<Vec<_>>(),
            "translation drifted for {input:?}"
        );
    }
}

#[test]
fn compatibility_translation_defers_root_display_and_invalid_global_forms() {
    for input in [
        vec!["jcode", "--help", "omnis", "status"],
        vec!["jcode", "-h", "omnis", "status"],
        vec!["jcode", "--version", "omnis", "status"],
        vec!["jcode", "-V", "omnis", "status"],
        vec!["jcode", "--auto-update=true", "omnis", "status"],
        vec!["jcode", "--cwd", "omnis", "status"],
    ] {
        let input = input.into_iter().map(OsString::from).collect::<Vec<_>>();
        assert!(
            matches!(
                super::translate_jcode_omnis_args(&input),
                CompatibilityTranslation::NotOmnis
            ),
            "root parser form was incorrectly claimed: {input:?}"
        );
    }
}

fn hostname_for_test() -> Option<String> {
    let mut bytes = [0_u8; 256];
    let result = unsafe { libc::gethostname(bytes.as_mut_ptr().cast(), bytes.len()) };
    if result != 0 {
        return None;
    }
    let end = bytes.iter().position(|byte| *byte == 0)?;
    String::from_utf8(bytes[..end].to_vec()).ok()
}
