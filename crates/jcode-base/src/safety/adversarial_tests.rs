use super::*;

fn create_private_directory(path: &Path) {
    fs::create_dir_all(path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[cfg(not(unix))]
    jcode_core::fs::set_directory_permissions_owner_only(path).unwrap();
}

fn write_private_file(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[cfg(not(unix))]
    jcode_core::fs::set_permissions_owner_only(path).unwrap();
}

fn with_temp_home<F, T>(f: F) -> T
where
    F: FnOnce() -> T,
{
    let _guard = crate::storage::lock_test_env();
    let prev_home = std::env::var_os("JCODE_HOME");
    let prev_runtime = std::env::var_os("JCODE_RUNTIME_DIR");
    let temp = tempfile::TempDir::new().expect("create temp dir");
    crate::env::set_var("JCODE_HOME", temp.path());
    crate::env::remove_var("JCODE_RUNTIME_DIR");

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));

    match prev_home {
        Some(value) => crate::env::set_var("JCODE_HOME", value),
        None => crate::env::remove_var("JCODE_HOME"),
    }
    match prev_runtime {
        Some(value) => crate::env::set_var("JCODE_RUNTIME_DIR", value),
        None => crate::env::remove_var("JCODE_RUNTIME_DIR"),
    }

    result.unwrap_or_else(|payload| std::panic::resume_unwind(payload))
}

fn permission_request(id: &str) -> PermissionRequest {
    PermissionRequest {
        id: id.to_string(),
        action: "push".to_string(),
        description: "Push reviewed branch".to_string(),
        rationale: "Publish a reviewable increment".to_string(),
        urgency: Urgency::Normal,
        wait: false,
        created_at: Utc::now(),
        context: Some(serde_json::json!({
            "session_id": "session_fixture",
            "details": {"branch": "codex/fixture"}
        })),
    }
}

#[test]
fn terminal_decision_binds_request_and_exactly_one_local_receipt() {
    with_temp_home(|| {
        let sys = SafetySystem::new();
        let request = permission_request("req_bound");
        sys.request_permission(request.clone()).unwrap();
        let decision = sys
            .record_decision(
                "req_bound",
                true,
                "test",
                Some("approved locally".to_string()),
            )
            .unwrap();

        assert_eq!(decision.outcome, Some(DecisionOutcome::Approved));
        assert_eq!(decision.request.as_ref().unwrap().id, request.id);
        assert!(decision.omnis_receipt_hash.is_some());
        assert!(sys.pending_requests().unwrap().is_empty());
        assert_eq!(sys.generate_summary().unwrap(), "No actions recorded.");

        read_state(|state| {
            assert_eq!(state.history.len(), 1);
            assert!(state.receipt_outbox.is_empty());
            Ok(())
        })
        .unwrap();
        let verification = crate::omnis::verify(&crate::omnis::ledger_path(None)).unwrap();
        assert!(verification.valid());
        assert_eq!(verification.entries(), 1);
        let binding = verify_decision_receipts().unwrap();
        assert!(binding.valid);
        assert_eq!(binding.acknowledged_receipts, 1);
        assert_eq!(binding.ledger_entries, 1);
    });
}

#[test]
fn acknowledged_receipt_hash_drift_is_refused() {
    with_temp_home(|| {
        let system = SafetySystem::new();
        system
            .request_permission(permission_request("req_receipt_hash_drift"))
            .unwrap();
        system
            .record_decision("req_receipt_hash_drift", true, "test", None)
            .unwrap();

        let path = state_path().unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["history"][0]["omnis_receipt_hash"] =
            serde_json::Value::String(format!("sha256:{}", "a".repeat(64)));
        storage::write_json_secret(&path, &value).unwrap();

        let error = verify_decision_receipts().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("ACKNOWLEDGED_RECEIPT_BINDING_MISMATCH")
        );
        assert!(flush_receipt_outbox().is_err());
    });
}

#[test]
fn deleting_acknowledged_history_leaves_a_refused_orphan_receipt() {
    with_temp_home(|| {
        let system = SafetySystem::new();
        system
            .request_permission(permission_request("req_deleted_history"))
            .unwrap();
        system
            .record_decision("req_deleted_history", false, "test", None)
            .unwrap();

        let path = state_path().unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["history"] = serde_json::json!([]);
        storage::write_json_secret(&path, &value).unwrap();

        let error = verify_decision_receipts().unwrap_err();
        assert!(error.to_string().contains("ORPHANED_OR_MISKINDED_RECEIPT"));
    });
}

#[test]
fn missing_and_replayed_decisions_refuse_without_extra_receipts() {
    with_temp_home(|| {
        let sys = SafetySystem::new();
        let missing = sys
            .record_decision("req_missing", true, "test", None)
            .unwrap_err();
        assert!(missing.to_string().contains("REQUEST_NOT_FOUND"));

        sys.request_permission(permission_request("req_once"))
            .unwrap();
        sys.record_decision("req_once", false, "test", None)
            .unwrap();
        let replay = sys
            .record_decision("req_once", false, "test", None)
            .unwrap_err();
        assert!(replay.to_string().contains("ALREADY_FINAL"));

        let verification = crate::omnis::verify(&crate::omnis::ledger_path(None)).unwrap();
        assert_eq!(verification.entries(), 1);
        read_state(|state| {
            assert_eq!(state.history.len(), 1);
            assert!(state.receipt_outbox.is_empty());
            Ok(())
        })
        .unwrap();
    });
}

#[test]
fn corrupt_state_refuses_and_preserves_the_corrupt_bytes() {
    with_temp_home(|| {
        let sys = SafetySystem::new();
        assert!(sys.pending_requests().unwrap().is_empty());
        let path = state_path().unwrap();
        let corrupt = b"{\"schema_version\":1,\"queue\":[";
        fs::write(&path, corrupt).unwrap();

        assert!(
            sys.pending_requests()
                .unwrap_err()
                .to_string()
                .contains("INVALID_JSON")
        );
        assert!(
            sys.request_permission(permission_request("req_after_corrupt"))
                .unwrap_err()
                .to_string()
                .contains("INVALID_JSON")
        );
        assert_eq!(fs::read(&path).unwrap(), corrupt);
    });
}

#[test]
fn receipt_failure_leaves_outbox_and_restart_reconciles_once() {
    with_temp_home(|| {
        let sys = SafetySystem::new();
        sys.request_permission(permission_request("req_reconcile"))
            .unwrap();
        let ledger = crate::omnis::ledger_path(None);
        create_private_directory(ledger.parent().unwrap());
        write_private_file(&ledger, b"{\"partial\":true}");

        let error = sys
            .record_decision("req_reconcile", true, "test", None)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("SAFETY_DECISION_COMMITTED_RECEIPT_PENDING")
        );
        let pending = read_state(|state| {
            assert!(state.queue.is_empty());
            assert_eq!(state.history.len(), 1);
            assert_eq!(state.receipt_outbox.len(), 1);
            assert!(state.history[0].omnis_receipt_hash.is_none());
            Ok(state.receipt_outbox[0].clone())
        })
        .unwrap();

        fs::remove_file(&ledger).unwrap();
        let append = crate::omnis::append_idempotent(
            &ledger,
            &pending.event_id,
            &pending.kind,
            &pending.subject,
            &pending.evidence_sha256,
            crate::omnis::ClaimCeiling::LocalRecord,
        )
        .unwrap();
        assert_eq!(
            append.disposition(),
            crate::omnis::AppendDisposition::Appended
        );

        let _restarted = SafetySystem::new();
        assert_eq!(flush_receipt_outbox().unwrap(), 0);
        let verification = crate::omnis::verify(&ledger).unwrap();
        assert!(verification.valid());
        assert_eq!(verification.entries(), 1);
        read_state(|state| {
            assert!(state.receipt_outbox.is_empty());
            assert!(state.history[0].omnis_receipt_hash.is_some());
            Ok(())
        })
        .unwrap();
    });
}

#[test]
fn request_field_mutation_changes_the_bound_evidence_digest() {
    with_temp_home(|| {
        let request = permission_request("req_digest");
        let (decision, original) = build_decision_transition(
            &request,
            DecisionOutcome::Denied,
            "test",
            Some("not now".to_string()),
        )
        .unwrap();
        let mut mutated = request.clone();
        mutated.action = "delete_repository".to_string();
        let changed = decision_evidence_digest(&mutated, &decision).unwrap();
        assert_ne!(original.evidence_sha256, changed);
    });
}

#[test]
fn concurrent_writers_do_not_lose_permission_requests() {
    with_temp_home(|| {
        let system = std::sync::Arc::new(SafetySystem::new());
        let mut writers = Vec::new();
        for index in 0..16 {
            let system = std::sync::Arc::clone(&system);
            writers.push(std::thread::spawn(move || {
                system
                    .request_permission(permission_request(&format!("req_concurrent_{index}")))
                    .unwrap();
            }));
        }
        for writer in writers {
            writer.join().unwrap();
        }
        let pending = system.pending_requests().unwrap();
        assert_eq!(pending.len(), 16);
        let unique: std::collections::HashSet<_> =
            pending.iter().map(|request| request.id.as_str()).collect();
        assert_eq!(unique.len(), 16);
    });
}

#[test]
fn expiry_has_a_distinct_outcome_and_receipt() {
    with_temp_home(|| {
        let sys = SafetySystem::new();
        let mut request = permission_request("req_expired");
        request.context = Some(serde_json::json!({
            "session_id": "session_that_does_not_exist"
        }));
        sys.request_permission(request).unwrap();
        let expired = sys.expire_dead_session_requests("test_gc").unwrap();
        assert_eq!(expired, vec!["req_expired"]);
        read_state(|state| {
            assert_eq!(state.history[0].outcome, Some(DecisionOutcome::Expired));
            assert!(!state.history[0].approved);
            assert!(state.receipt_outbox.is_empty());
            Ok(())
        })
        .unwrap();
        let ledger = fs::read_to_string(crate::omnis::ledger_path(None)).unwrap();
        assert!(ledger.contains("\"kind\":\"safety.permission.expired\""));
    });
}

#[test]
fn mutated_outbox_binding_is_refused_before_receipt_append() {
    with_temp_home(|| {
        let sys = SafetySystem::new();
        sys.request_permission(permission_request("req_outbox_drift"))
            .unwrap();
        let ledger = crate::omnis::ledger_path(None);
        create_private_directory(ledger.parent().unwrap());
        write_private_file(&ledger, b"partial");
        assert!(
            sys.record_decision("req_outbox_drift", false, "test", None)
                .is_err()
        );

        let path = state_path().unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["receipt_outbox"][0]["evidence_sha256"] =
            serde_json::Value::String(format!("sha256:{}", "f".repeat(64)));
        storage::write_json_secret(&path, &value).unwrap();
        fs::remove_file(&ledger).unwrap();

        let error = flush_receipt_outbox().unwrap_err();
        assert!(error.to_string().contains("OUTBOX_BINDING_MISMATCH"));
        assert!(!ledger.exists());
    });
}

#[test]
fn dropping_a_committed_decisions_outbox_is_refused() {
    with_temp_home(|| {
        let sys = SafetySystem::new();
        sys.request_permission(permission_request("req_dropped_outbox"))
            .unwrap();
        let ledger = crate::omnis::ledger_path(None);
        create_private_directory(ledger.parent().unwrap());
        write_private_file(&ledger, b"partial");
        assert!(
            sys.record_decision("req_dropped_outbox", true, "test", None)
                .is_err()
        );

        let path = state_path().unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["receipt_outbox"] = serde_json::json!([]);
        storage::write_json_secret(&path, &value).unwrap();
        fs::remove_file(&ledger).unwrap();

        let error = flush_receipt_outbox().unwrap_err();
        assert!(error.to_string().contains("DECISION_MISSING_OUTBOX"));
        assert!(!ledger.exists());
    });
}

#[test]
fn legacy_import_is_consumed_once_and_missing_primary_requires_recovery() {
    with_temp_home(|| {
        let queue = vec![permission_request("req_legacy_once")];
        let queue_bytes = serde_json::to_vec(&queue).unwrap();
        let queue_path = queue_path().unwrap();
        create_private_directory(queue_path.parent().unwrap());
        write_private_file(&queue_path, &queue_bytes);
        write_private_file(&history_path().unwrap(), b"[]");

        let system = SafetySystem::new();
        assert_eq!(system.pending_requests().unwrap().len(), 1);
        system
            .record_decision("req_legacy_once", false, "test", None)
            .unwrap();
        let state = state_path().unwrap();
        let marker = state_initialization_marker_path().unwrap();
        assert!(state.exists());
        assert!(marker.exists());

        fs::remove_file(&state).unwrap();
        let error = SafetySystem::new().pending_requests().unwrap_err();
        assert!(error.to_string().contains("RECOVERY_REQUIRED"));
        assert_eq!(fs::read(&queue_path).unwrap(), queue_bytes);
        assert!(!state.exists());
    });
}

#[test]
fn malformed_or_conflicting_legacy_state_is_preserved_and_refused() {
    with_temp_home(|| {
        let directory = safety_dir().unwrap();
        create_private_directory(&directory);
        let malformed = b"[{\"id\":";
        write_private_file(&queue_path().unwrap(), malformed);
        write_private_file(&history_path().unwrap(), b"[]");
        let error = SafetySystem::new().pending_requests().unwrap_err();
        assert!(error.to_string().contains("INVALID_JSON"));
        assert_eq!(fs::read(queue_path().unwrap()).unwrap(), malformed);
        assert!(!state_path().unwrap().exists());
        assert!(!state_initialization_marker_path().unwrap().exists());
    });

    with_temp_home(|| {
        let request = permission_request("req_conflict");
        let directory = safety_dir().unwrap();
        create_private_directory(&directory);
        let queue_bytes = serde_json::to_vec(&vec![request.clone()]).unwrap();
        write_private_file(&queue_path().unwrap(), &queue_bytes);
        let legacy_decision = serde_json::json!([{
            "request_id": request.id,
            "approved": false,
            "decided_at": Utc::now(),
            "decided_via": "legacy",
            "message": null
        }]);
        let history_bytes = serde_json::to_vec(&legacy_decision).unwrap();
        write_private_file(&history_path().unwrap(), &history_bytes);

        let error = SafetySystem::new().pending_requests().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("DUPLICATE_OR_NONTERMINAL_REQUEST")
        );
        assert_eq!(fs::read(queue_path().unwrap()).unwrap(), queue_bytes);
        assert_eq!(fs::read(history_path().unwrap()).unwrap(), history_bytes);
        assert!(!state_path().unwrap().exists());
    });
}

#[cfg(unix)]
#[test]
fn symlinked_state_lock_is_refused_without_touching_target() {
    with_temp_home(|| {
        use std::os::unix::fs::symlink;

        let directory = safety_dir().unwrap();
        create_private_directory(&directory);
        let victim = directory.join("victim");
        fs::write(&victim, "unchanged").unwrap();
        symlink(&victim, state_lock_path().unwrap()).unwrap();

        let error = SafetySystem::new().pending_requests().unwrap_err();
        assert!(error.to_string().contains("LOCK_SYMLINK_REFUSED"));
        assert_eq!(fs::read_to_string(victim).unwrap(), "unchanged");
    });
}

#[cfg(unix)]
#[test]
fn permissive_umask_cannot_publish_world_accessible_safety_state() {
    with_temp_home(|| {
        use std::os::unix::fs::PermissionsExt;

        struct UmaskGuard(libc::mode_t);
        impl Drop for UmaskGuard {
            fn drop(&mut self) {
                unsafe {
                    libc::umask(self.0);
                }
            }
        }

        let previous = unsafe { libc::umask(0) };
        let _guard = UmaskGuard(previous);
        let system = SafetySystem::new();
        system
            .request_permission(permission_request("req_private_modes"))
            .unwrap();
        system
            .record_decision("req_private_modes", true, "test", None)
            .unwrap();

        let ledger = crate::omnis::ledger_path(None);
        let private_directories = [
            safety_dir().unwrap(),
            ledger.parent().unwrap().to_path_buf(),
        ];
        for directory in private_directories {
            let mode = fs::metadata(&directory).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "unexpected mode for {}", directory.display());
        }

        let private_files = [
            state_path().unwrap(),
            state_lock_path().unwrap(),
            state_initialization_marker_path().unwrap(),
            ledger.clone(),
            ledger.with_extension("jsonl.lock"),
        ];
        for file in private_files {
            let mode = fs::metadata(&file).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "unexpected mode for {}", file.display());
        }
    });
}
