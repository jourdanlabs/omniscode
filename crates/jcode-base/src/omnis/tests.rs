use super::*;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn private_tempdir() -> std::io::Result<tempfile::TempDir> {
    let temporary = tempfile::tempdir()?;
    #[cfg(unix)]
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
    Ok(temporary)
}

fn evidence() -> &'static str {
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}

#[test]
fn append_and_verify_a_bounded_chain() {
    let temp = private_tempdir().unwrap();
    let ledger = temp.path().join("receipts.jsonl");
    append(
        &ledger,
        "source.review",
        "frozen candidate",
        evidence(),
        ClaimCeiling::LocalRecord,
    )
    .unwrap();
    append(
        &ledger,
        "source.verify",
        "independent verifier",
        evidence(),
        ClaimCeiling::LocalVerification,
    )
    .unwrap();
    let verification = verify(&ledger).unwrap();
    assert!(verification.valid);
    assert_eq!(verification.entries, 2);
}

#[test]
fn genuinely_absent_parent_verifies_as_an_empty_chain() {
    let temp = private_tempdir().unwrap();
    let ledger = temp
        .path()
        .join("not-created")
        .join("nested")
        .join("receipts.jsonl");

    let verification = verify(&ledger).unwrap();
    assert!(verification.valid());
    assert_eq!(verification.entries(), 0);
    assert!(verified_receipts(&ledger).unwrap().is_empty());
    assert!(!ledger.parent().unwrap().exists());
}

#[test]
fn rejects_partial_tail_and_tampered_hash() {
    let temp = private_tempdir().unwrap();
    let ledger = temp.path().join("receipts.jsonl");
    append(
        &ledger,
        "source.review",
        "candidate",
        evidence(),
        ClaimCeiling::LocalRecord,
    )
    .unwrap();
    fs::write(&ledger, "{\"partial\":true}").unwrap();
    assert!(
        verify(&ledger)
            .unwrap_err()
            .to_string()
            .contains("PARTIAL_TAIL")
    );

    fs::remove_file(&ledger).unwrap();
    append(
        &ledger,
        "source.review",
        "candidate",
        evidence(),
        ClaimCeiling::LocalRecord,
    )
    .unwrap();
    let text = fs::read_to_string(&ledger)
        .unwrap()
        .replace("source.review", "source.tampered");
    fs::write(&ledger, text).unwrap();
    assert!(!verify(&ledger).unwrap().valid);
}

#[test]
fn partial_byte_and_mid_record_truncation_are_refused_without_reseed() {
    let temp = private_tempdir().unwrap();
    let ledger = temp.path().join("receipts.jsonl");
    append_idempotent(
        &ledger,
        "fixture:truncation/first",
        "source.review",
        "first fixture record",
        evidence(),
        ClaimCeiling::LocalRecord,
    )
    .unwrap();
    append_idempotent(
        &ledger,
        "fixture:truncation/second",
        "source.review",
        "second fixture record",
        evidence(),
        ClaimCeiling::LocalRecord,
    )
    .unwrap();
    let complete = fs::read(&ledger).unwrap();
    assert_eq!(complete.last(), Some(&b'\n'));
    let first_record_end = complete
        .iter()
        .position(|byte| *byte == b'\n')
        .map(|position| position + 1)
        .unwrap();
    assert!(first_record_end < complete.len());

    let missing_final_byte = complete[..complete.len() - 1].to_vec();
    fs::write(&ledger, &missing_final_byte).unwrap();
    let partial_byte_error = verify(&ledger).unwrap_err();
    assert!(
        partial_byte_error
            .to_string()
            .contains("OMNIS_RECEIPT_PARTIAL_TAIL")
    );
    let refused_partial_append = append_idempotent(
        &ledger,
        "fixture:truncation/after-partial-byte",
        "source.review",
        "must not reseed",
        evidence(),
        ClaimCeiling::LocalRecord,
    )
    .unwrap_err();
    assert!(
        refused_partial_append
            .to_string()
            .contains("OMNIS_RECEIPT_PARTIAL_TAIL")
    );
    assert_eq!(fs::read(&ledger).unwrap(), missing_final_byte);

    fs::write(&ledger, &complete).unwrap();
    let second_record_bytes = complete.len() - first_record_end;
    let mid_record_end = first_record_end + second_record_bytes / 2;
    assert!(mid_record_end > first_record_end);
    assert!(mid_record_end < complete.len() - 1);
    let mid_record = complete[..mid_record_end].to_vec();
    fs::write(&ledger, &mid_record).unwrap();
    let mid_record_error = verified_receipts(&ledger).unwrap_err();
    assert!(
        mid_record_error
            .to_string()
            .contains("OMNIS_RECEIPT_PARTIAL_TAIL")
    );
    let refused_mid_record_append = append_idempotent(
        &ledger,
        "fixture:truncation/after-mid-record",
        "source.review",
        "must not reseed",
        evidence(),
        ClaimCeiling::LocalRecord,
    )
    .unwrap_err();
    assert!(
        refused_mid_record_append
            .to_string()
            .contains("OMNIS_RECEIPT_PARTIAL_TAIL")
    );
    assert_eq!(fs::read(&ledger).unwrap(), mid_record);
}

#[test]
fn valid_prefix_tail_removal_remains_locally_undetected_without_checkpoint() {
    let temp = private_tempdir().unwrap();
    let ledger = temp.path().join("receipts.jsonl");
    let first = append_idempotent(
        &ledger,
        "fixture:rollback/first",
        "source.review",
        "first fixture record",
        evidence(),
        ClaimCeiling::LocalRecord,
    )
    .unwrap();
    append_idempotent(
        &ledger,
        "fixture:rollback/second",
        "source.verify",
        "second fixture record",
        evidence(),
        ClaimCeiling::LocalVerification,
    )
    .unwrap();
    let complete = fs::read(&ledger).unwrap();
    let first_record_end = complete
        .iter()
        .position(|byte| *byte == b'\n')
        .map(|position| position + 1)
        .unwrap();
    let valid_prefix = complete[..first_record_end].to_vec();
    assert!(valid_prefix.len() < complete.len());

    fs::write(&ledger, &valid_prefix).unwrap();
    let verification = verify(&ledger).unwrap();
    assert!(verification.valid());
    assert_eq!(verification.entries(), 1);
    assert_eq!(verification.head(), Some(first.receipt().receipt_hash()));
    assert_eq!(
        verification.integrity_scope,
        "local-chain-only; external evidence and rollback require separate verification"
    );
    let locally_visible = verified_receipts(&ledger).unwrap();
    assert_eq!(locally_visible.len(), 1);
    assert_eq!(
        locally_visible[0].receipt_hash(),
        first.receipt().receipt_hash()
    );
    assert_eq!(fs::read(&ledger).unwrap(), valid_prefix);
}

#[test]
fn reordered_receipts_are_refused() {
    let temp = private_tempdir().unwrap();
    let ledger = temp.path().join("receipts.jsonl");
    append_idempotent(
        &ledger,
        "fixture:reorder/first",
        "source.review",
        "first fixture record",
        evidence(),
        ClaimCeiling::LocalRecord,
    )
    .unwrap();
    append_idempotent(
        &ledger,
        "fixture:reorder/second",
        "source.verify",
        "second fixture record",
        evidence(),
        ClaimCeiling::LocalVerification,
    )
    .unwrap();
    let complete = fs::read(&ledger).unwrap();
    let first_record_end = complete
        .iter()
        .position(|byte| *byte == b'\n')
        .map(|position| position + 1)
        .unwrap();
    let (first_record, second_record) = complete.split_at(first_record_end);
    assert!(!second_record.is_empty());
    let mut reordered = Vec::with_capacity(complete.len());
    reordered.extend_from_slice(second_record);
    reordered.extend_from_slice(first_record);
    fs::write(&ledger, &reordered).unwrap();

    let verification = verify(&ledger).unwrap();
    assert!(!verification.valid());
    assert!(
        verification
            .errors()
            .iter()
            .any(|error| error.contains("sequence mismatch"))
    );
    assert!(
        verification
            .errors()
            .iter()
            .any(|error| error.contains("parent hash mismatch"))
    );
    assert!(
        verified_receipts(&ledger)
            .unwrap_err()
            .to_string()
            .contains("OMNIS_RECEIPT_CHAIN_INVALID")
    );
    assert!(
        append_idempotent(
            &ledger,
            "fixture:reorder/after",
            "source.review",
            "must not append",
            evidence(),
            ClaimCeiling::LocalRecord,
        )
        .unwrap_err()
        .to_string()
        .contains("OMNIS_RECEIPT_CHAIN_INVALID_BEFORE_APPEND")
    );
    assert_eq!(fs::read(&ledger).unwrap(), reordered);
}

#[test]
fn refuses_unbounded_or_malformed_inputs() {
    let temp = private_tempdir().unwrap();
    let ledger = temp.path().join("receipts.jsonl");
    assert!(
        append(
            &ledger,
            "bad kind",
            "subject",
            evidence(),
            ClaimCeiling::LocalRecord
        )
        .is_err()
    );
    assert!(
        append(
            &ledger,
            "kind",
            "subject",
            "not-a-digest",
            ClaimCeiling::LocalRecord
        )
        .is_err()
    );
}

#[test]
fn rehashed_semantically_invalid_receipt_still_refuses() {
    let temp = private_tempdir().unwrap();
    let ledger = temp.path().join("receipts.jsonl");
    let mut receipt = Receipt {
        protocol: PROTOCOL.to_string(),
        sequence: 1,
        parent_hash: None,
        event_id: None,
        kind: "invalid kind".to_string(),
        subject: "candidate".to_string(),
        evidence_sha256: format!("sha256:{}", evidence()),
        evidence: None,
        claim_ceiling: ClaimCeiling::LocalRecord,
        receipt_hash: String::new(),
    };
    receipt.receipt_hash = receipt_hash(&receipt);
    fs::write(
        &ledger,
        format!("{}\n", serde_json::to_string(&receipt).unwrap()),
    )
    .unwrap();
    #[cfg(unix)]
    fs::set_permissions(&ledger, fs::Permissions::from_mode(0o600)).unwrap();

    let verification = verify(&ledger).unwrap();
    assert!(!verification.valid());
    assert!(
        verification
            .errors()
            .iter()
            .any(|error| error.contains("invalid kind"))
    );
}

#[test]
fn idempotent_append_replays_exactly_and_refuses_drift() {
    let temp = private_tempdir().unwrap();
    let ledger = temp.path().join("receipts.jsonl");
    let first = append_idempotent(
        &ledger,
        "decision:req-1",
        "safety.permission.approved",
        "request req-1 decision dec-1",
        evidence(),
        ClaimCeiling::LocalRecord,
    )
    .unwrap();
    assert_eq!(first.disposition(), AppendDisposition::Appended);
    let replay = append_idempotent(
        &ledger,
        "decision:req-1",
        "safety.permission.approved",
        "request req-1 decision dec-1",
        evidence(),
        ClaimCeiling::LocalRecord,
    )
    .unwrap();
    assert_eq!(replay.disposition(), AppendDisposition::Existing);
    assert_eq!(
        first.receipt().receipt_hash(),
        replay.receipt().receipt_hash()
    );
    let lines = fs::read_to_string(&ledger).unwrap().lines().count();
    assert_eq!(lines, 1);

    let error = append_idempotent(
        &ledger,
        "decision:req-1",
        "safety.permission.denied",
        "request req-1 decision dec-1",
        evidence(),
        ClaimCeiling::LocalRecord,
    )
    .unwrap_err();
    assert!(error.to_string().contains("IDEMPOTENCY_COLLISION"));
}

#[test]
fn stale_regular_lock_does_not_wedge_the_ledger() {
    let temp = private_tempdir().unwrap();
    let ledger = temp.path().join("receipts.jsonl");
    let lock = ledger.with_extension("jsonl.lock");
    fs::write(&lock, "stale diagnostics").unwrap();
    #[cfg(unix)]
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
    append(
        &ledger,
        "source.review",
        "candidate",
        evidence(),
        ClaimCeiling::LocalRecord,
    )
    .unwrap();
    assert!(verify(&ledger).unwrap().valid());
}

#[cfg(unix)]
#[test]
fn unsafe_existing_lock_and_ledger_modes_are_refused_without_repair() {
    let temp = private_tempdir().unwrap();
    let ledger = temp.path().join("receipts.jsonl");
    let lock = ledger.with_extension("jsonl.lock");
    fs::write(&lock, "stale diagnostics").unwrap();
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o666)).unwrap();
    let original_lock = fs::read(&lock).unwrap();

    let lock_error = append(
        &ledger,
        "source.review",
        "candidate",
        evidence(),
        ClaimCeiling::LocalRecord,
    )
    .unwrap_err();
    assert!(lock_error.to_string().contains("IDENTITY_OR_MODE_DRIFT"));
    assert_eq!(fs::read(&lock).unwrap(), original_lock);
    assert_eq!(
        fs::metadata(&lock).unwrap().permissions().mode() & 0o777,
        0o666
    );
    assert!(!ledger.exists());

    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
    append(
        &ledger,
        "source.review",
        "candidate",
        evidence(),
        ClaimCeiling::LocalRecord,
    )
    .unwrap();
    let original_ledger = fs::read(&ledger).unwrap();
    fs::set_permissions(&ledger, fs::Permissions::from_mode(0o644)).unwrap();
    let ledger_error = verify(&ledger).unwrap_err();
    assert!(ledger_error.to_string().contains("IDENTITY_OR_MODE_DRIFT"));
    assert_eq!(fs::read(&ledger).unwrap(), original_ledger);
    assert_eq!(
        fs::metadata(&ledger).unwrap().permissions().mode() & 0o777,
        0o644
    );
}

#[cfg(unix)]
#[test]
fn nonprivate_existing_parent_is_refused_without_repair() {
    let temp = private_tempdir().unwrap();
    let parent = temp.path().join("ledger-parent");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();
    let ledger = parent.join("receipts.jsonl");

    let error = append(
        &ledger,
        "source.review",
        "candidate",
        evidence(),
        ClaimCeiling::LocalRecord,
    )
    .unwrap_err();
    assert!(error.to_string().contains("IDENTITY_OR_MODE_DRIFT"));
    assert_eq!(
        fs::metadata(&parent).unwrap().permissions().mode() & 0o777,
        0o755
    );
    assert!(!ledger.exists());
}

#[test]
fn read_only_verification_never_creates_or_opens_a_lock() {
    let temp = private_tempdir().unwrap();
    let ledger = temp.path().join("receipts.jsonl");
    append(
        &ledger,
        "source.review",
        "candidate",
        evidence(),
        ClaimCeiling::LocalRecord,
    )
    .unwrap();
    let lock = ledger.with_extension("jsonl.lock");
    fs::remove_file(&lock).unwrap();
    let before = fs::read(&ledger).unwrap();

    assert!(verify(&ledger).unwrap().valid());
    assert_eq!(verified_receipts(&ledger).unwrap().len(), 1);
    assert_eq!(fs::read(&ledger).unwrap(), before);
    assert!(!lock.exists());
}

#[cfg(unix)]
#[test]
fn failed_copy_on_write_preserves_primary_and_exact_retry_succeeds() {
    let temp = private_tempdir().unwrap();
    let ledger = temp.path().join("receipts.jsonl");
    append_idempotent(
        &ledger,
        "event:first",
        "source.review",
        "first",
        evidence(),
        ClaimCeiling::LocalRecord,
    )
    .unwrap();
    let original = fs::read(&ledger).unwrap();

    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o500)).unwrap();
    let failed = append_idempotent(
        &ledger,
        "event:retry",
        "source.review",
        "retry",
        evidence(),
        ClaimCeiling::LocalRecord,
    );
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();

    assert!(failed.is_err());
    assert_eq!(fs::read(&ledger).unwrap(), original);
    let still_valid = verify(&ledger).unwrap();
    assert!(still_valid.valid());
    assert_eq!(still_valid.entries(), 1);

    let retried = append_idempotent(
        &ledger,
        "event:retry",
        "source.review",
        "retry",
        evidence(),
        ClaimCeiling::LocalRecord,
    )
    .unwrap();
    assert_eq!(retried.disposition(), AppendDisposition::Appended);
    let after = verify(&ledger).unwrap();
    assert!(after.valid());
    assert_eq!(after.entries(), 2);
}

#[cfg(unix)]
#[test]
fn refuses_ledger_and_lock_symlinks_without_touching_targets() {
    use std::os::unix::fs::symlink;

    let temp = private_tempdir().unwrap();
    let victim = temp.path().join("victim");
    fs::write(&victim, "unchanged").unwrap();

    let ledger = temp.path().join("receipts.jsonl");
    symlink(&victim, &ledger).unwrap();
    assert!(
        append(
            &ledger,
            "source.review",
            "candidate",
            evidence(),
            ClaimCeiling::LocalRecord,
        )
        .unwrap_err()
        .to_string()
        .contains("SYMLINK_REFUSED")
    );
    assert_eq!(fs::read_to_string(&victim).unwrap(), "unchanged");

    fs::remove_file(&ledger).unwrap();
    symlink(&victim, ledger.with_extension("jsonl.lock")).unwrap();
    assert!(
        append(
            &ledger,
            "source.review",
            "candidate",
            evidence(),
            ClaimCeiling::LocalRecord,
        )
        .unwrap_err()
        .to_string()
        .contains("LOCK_SYMLINK_REFUSED")
    );
    assert_eq!(fs::read_to_string(&victim).unwrap(), "unchanged");
}

#[cfg(unix)]
#[test]
fn refuses_intermediate_directory_symlink() {
    use std::os::unix::fs::symlink;

    let temp = private_tempdir().unwrap();
    let real = temp.path().join("real");
    fs::create_dir(&real).unwrap();
    let alias = temp.path().join("alias");
    symlink(&real, &alias).unwrap();
    let ledger = alias.join("new").join("receipts.jsonl");

    let error = append(
        &ledger,
        "source.review",
        "candidate",
        evidence(),
        ClaimCeiling::LocalRecord,
    )
    .unwrap_err();
    assert!(error.to_string().contains("DIRECTORY_SYMLINK_REFUSED"));
    assert!(!real.join("new").exists());
}

#[cfg(unix)]
#[test]
fn verification_refuses_missing_parents_hidden_behind_symlinks() {
    use std::os::unix::fs::symlink;

    let temp = private_tempdir().unwrap();

    let real = temp.path().join("real");
    fs::create_dir(&real).unwrap();
    let live_alias = temp.path().join("live-alias");
    symlink(&real, &live_alias).unwrap();
    let live_ledger = live_alias.join("missing").join("receipts.jsonl");
    assert!(!live_ledger.parent().unwrap().exists());
    let live_error = verify(&live_ledger).unwrap_err();
    assert!(live_error.to_string().contains("DIRECTORY_SYMLINK_REFUSED"));
    assert!(!real.join("missing").exists());

    let missing_target = temp.path().join("missing-target");
    let dangling_alias = temp.path().join("dangling-alias");
    symlink(&missing_target, &dangling_alias).unwrap();
    let dangling_ledger = dangling_alias.join("nested").join("receipts.jsonl");
    assert!(!dangling_ledger.parent().unwrap().exists());
    let dangling_error = verified_receipts(&dangling_ledger).unwrap_err();
    assert!(
        dangling_error
            .to_string()
            .contains("DIRECTORY_SYMLINK_REFUSED")
    );
    assert!(!missing_target.exists());
}
