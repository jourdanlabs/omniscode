#[test]
fn test_v1_update_quarantine_post_connect_has_no_reload_or_handoff_write() {
    use std::time::{Duration, SystemTime};

    let _guard = crate::storage::lock_test_env();
    let temp_home = tempfile::TempDir::new().expect("create temp home");
    let prev_home = std::env::var_os("JCODE_HOME");
    crate::env::set_var("JCODE_HOME", temp_home.path());

    let mut app = create_test_app();
    app.client_binary_mtime = Some(SystemTime::now() + Duration::from_secs(3600));
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _enter = rt.enter();
    let backend = ratatui::backend::TestBackend::new(80, 24);
    let mut terminal = ratatui::Terminal::new(backend).expect("failed to create terminal");
    let mut remote = crate::tui::backend::RemoteConnection::dummy();
    remote.mark_history_loaded();
    app.remote_session_id = Some("session_reload_after_reconnect".to_string());
    app.input = "unsent draft".to_string();
    app.cursor_pos = app.input.len();
    let forbidden_marker = temp_home
        .path()
        .join("client-reload-pending-session_reload_after_reconnect");
    let forbidden_state = temp_home
        .path()
        .join("client-input-session_reload_after_reconnect");

    let mut state = super::remote::RemoteRunState {
        reconnect_attempts: 1,
        server_reload_in_progress: true,
        ..Default::default()
    };

    let outcome = rt
        .block_on(super::remote::handle_post_connect(
            &mut app,
            &mut terminal,
            &mut remote,
            &mut state,
            Some("session_reload_after_reconnect"),
        ))
        .expect("post connect should succeed");

    if let Some(prev_home) = prev_home {
        crate::env::set_var("JCODE_HOME", prev_home);
    } else {
        crate::env::remove_var("JCODE_HOME");
    }

    assert!(matches!(outcome, super::remote::PostConnectOutcome::Ready));
    assert!(app.reload_requested.is_none());
    assert!(!app.should_quit);
    assert_eq!(app.input, "unsent draft");
    assert!(!forbidden_marker.exists());
    assert!(!forbidden_state.exists());
    assert!(
        app.display_messages()
            .iter()
            .all(|message| !message.content.contains("Reloading client binary"))
    );
    assert_eq!(state.reconnect_attempts, 0);
    assert!(!state.server_reload_in_progress);
}
