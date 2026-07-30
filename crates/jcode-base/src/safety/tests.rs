use super::*;

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

#[test]
fn test_classify_auto_allowed() {
    with_temp_home(|| {
        let sys = SafetySystem::new();
        assert_eq!(sys.classify("read"), ActionTier::AutoAllowed);
        assert_eq!(sys.classify("glob"), ActionTier::AutoAllowed);
        assert_eq!(sys.classify("grep"), ActionTier::AutoAllowed);
        assert_eq!(sys.classify("ls"), ActionTier::AutoAllowed);
        assert_eq!(sys.classify("memory"), ActionTier::AutoAllowed);
        assert_eq!(sys.classify("todo"), ActionTier::AutoAllowed);
        assert_eq!(sys.classify("todowrite"), ActionTier::AutoAllowed);
        assert_eq!(sys.classify("todoread"), ActionTier::AutoAllowed);
        assert_eq!(sys.classify("conversation_search"), ActionTier::AutoAllowed);
        assert_eq!(sys.classify("session_search"), ActionTier::AutoAllowed);
        assert_eq!(sys.classify("codesearch"), ActionTier::AutoAllowed);
    });
}

#[test]
fn test_classify_requires_permission() {
    with_temp_home(|| {
        let sys = SafetySystem::new();
        assert_eq!(sys.classify("bash"), ActionTier::RequiresPermission);
        assert_eq!(sys.classify("write"), ActionTier::RequiresPermission);
        assert_eq!(sys.classify("edit"), ActionTier::RequiresPermission);
        assert_eq!(sys.classify("multiedit"), ActionTier::RequiresPermission);
        assert_eq!(sys.classify("patch"), ActionTier::RequiresPermission);
        assert_eq!(sys.classify("apply_patch"), ActionTier::RequiresPermission);
        assert_eq!(sys.classify("communicate"), ActionTier::RequiresPermission);
        assert_eq!(sys.classify("open"), ActionTier::RequiresPermission);
        assert_eq!(sys.classify("launch"), ActionTier::RequiresPermission);
        assert_eq!(sys.classify("webfetch"), ActionTier::RequiresPermission);
        assert_eq!(sys.classify("websearch"), ActionTier::RequiresPermission);
        assert_eq!(sys.classify("unknown_tool"), ActionTier::RequiresPermission);
    });
}

#[test]
fn test_classify_case_insensitive() {
    with_temp_home(|| {
        let sys = SafetySystem::new();
        assert_eq!(sys.classify("Read"), ActionTier::AutoAllowed);
        assert_eq!(sys.classify("GLOB"), ActionTier::AutoAllowed);
        assert_eq!(sys.classify("Bash"), ActionTier::RequiresPermission);
    });
}

#[test]
fn test_request_permission_returns_queued() {
    with_temp_home(|| {
        let sys = SafetySystem::new();
        let baseline = sys.pending_requests().unwrap().len();
        let req = PermissionRequest {
            id: "req_test_1".to_string(),
            action: "create_pull_request".to_string(),
            description: "Create PR for test fixes".to_string(),
            rationale: "Found failing tests".to_string(),
            urgency: Urgency::Normal,
            wait: false,
            created_at: Utc::now(),
            context: None,
        };

        let result = sys.request_permission(req).unwrap();
        match result {
            PermissionResult::Queued { request_id } => {
                assert_eq!(request_id, "req_test_1");
            }
            _ => panic!("Expected Queued result"),
        }

        assert_eq!(sys.pending_requests().unwrap().len(), baseline + 1);
    });
}

#[test]
fn test_record_decision_removes_from_queue() {
    with_temp_home(|| {
        let sys = SafetySystem::new();
        let baseline = sys.pending_requests().unwrap().len();
        let req = PermissionRequest {
            id: "req_test_2".to_string(),
            action: "push".to_string(),
            description: "Push to origin".to_string(),
            rationale: "Ready for review".to_string(),
            urgency: Urgency::Low,
            wait: false,
            created_at: Utc::now(),
            context: None,
        };

        sys.request_permission(req).unwrap();
        assert_eq!(sys.pending_requests().unwrap().len(), baseline + 1);

        sys.record_decision("req_test_2", true, "tui", Some("looks good".to_string()))
            .unwrap();
        assert_eq!(sys.pending_requests().unwrap().len(), baseline);
    });
}

#[test]
fn test_log_action_and_summary() {
    with_temp_home(|| {
        let sys = SafetySystem::new();
        sys.log_action(ActionLog {
            action_type: "memory_consolidation".to_string(),
            description: "Merged 2 duplicate memories".to_string(),
            tier: ActionTier::AutoAllowed,
            details: None,
            timestamp: Utc::now(),
        });
        sys.log_action(ActionLog {
            action_type: "edit".to_string(),
            description: "Fixed typo in README".to_string(),
            tier: ActionTier::RequiresPermission,
            details: None,
            timestamp: Utc::now(),
        });

        let summary = sys.generate_summary().unwrap();
        assert!(summary.contains("memory_consolidation"));
        assert!(summary.contains("edit"));
        assert!(summary.contains("Done (auto-allowed)"));
        assert!(summary.contains("Done (with permission)"));
    });
}

#[test]
fn test_empty_summary() {
    with_temp_home(|| {
        let sys = SafetySystem::new();
        let summary = sys.generate_summary().unwrap();
        assert_eq!(summary, "No actions recorded.");
    });
}

#[test]
fn test_new_request_id_format() {
    with_temp_home(|| {
        let id = new_request_id();
        assert!(id.starts_with("req_"));
    });
}

#[test]
fn test_record_permission_via_file() {
    with_temp_home(|| {
        let sys = SafetySystem::new();
        let baseline = sys.pending_requests().unwrap().len();
        let req = PermissionRequest {
            id: "req_file_test".to_string(),
            action: "push".to_string(),
            description: "Push to origin".to_string(),
            rationale: "Ready for review".to_string(),
            urgency: Urgency::Low,
            wait: false,
            created_at: Utc::now(),
            context: None,
        };
        sys.request_permission(req).unwrap();
        assert_eq!(sys.pending_requests().unwrap().len(), baseline + 1);

        record_permission_via_file("req_file_test", true, "email_reply", None).unwrap();

        let sys2 = SafetySystem::new();
        let still_pending = sys2
            .pending_requests()
            .unwrap()
            .iter()
            .any(|request| request.id == "req_file_test");
        assert!(
            !still_pending,
            "request should have been removed from queue"
        );
    });
}
