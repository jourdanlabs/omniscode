use super::*;

#[test]
fn test_disconnected_key_handler_allows_typing_and_queueing() {
    let mut app = create_test_app();

    remote::handle_disconnected_key(&mut app, KeyCode::Char('h'), KeyModifiers::empty()).unwrap();
    remote::handle_disconnected_key(&mut app, KeyCode::Char('i'), KeyModifiers::empty()).unwrap();
    assert_eq!(app.input, "hi");

    remote::handle_disconnected_key(&mut app, KeyCode::Enter, KeyModifiers::empty()).unwrap();

    assert!(app.input.is_empty());
    assert_eq!(app.queued_messages().len(), 1);
    assert_eq!(app.queued_messages()[0], "hi");
    assert_eq!(
        app.status_notice(),
        Some("Queued for send after reconnect (1 message)".to_string())
    );
}

#[test]
fn test_disconnected_shift_enter_inserts_newline() {
    let mut app = create_test_app();

    remote::handle_disconnected_key(&mut app, KeyCode::Char('h'), KeyModifiers::empty()).unwrap();
    remote::handle_disconnected_key(&mut app, KeyCode::Enter, KeyModifiers::SHIFT).unwrap();
    remote::handle_disconnected_key(&mut app, KeyCode::Char('i'), KeyModifiers::empty()).unwrap();

    assert_eq!(app.input(), "h\ni");
    assert!(app.queued_messages().is_empty());
}

#[test]
fn test_disconnected_shift_slash_preserves_layout_translated_slash() {
    let mut app = create_test_app();

    remote::handle_disconnected_key(&mut app, KeyCode::Char('/'), KeyModifiers::SHIFT).unwrap();

    assert_eq!(app.input(), "/");
    assert!(app.queued_messages().is_empty());
}

#[test]
fn test_disconnected_key_event_shift_slash_preserves_layout_translated_slash() {
    use crossterm::event::{KeyEvent, KeyEventKind};

    let mut app = create_test_app();

    remote::handle_disconnected_key_event(
        &mut app,
        KeyEvent::new_with_kind(KeyCode::Char('/'), KeyModifiers::SHIFT, KeyEventKind::Press),
    )
    .unwrap();

    assert_eq!(app.input(), "/");
    assert!(app.queued_messages().is_empty());
}

#[test]
fn test_disconnected_control_alt_symbol_inserts_layout_translated_text() {
    let mut app = create_test_app();

    remote::handle_disconnected_key(
        &mut app,
        KeyCode::Char('@'),
        KeyModifiers::CONTROL | KeyModifiers::ALT,
    )
    .unwrap();

    assert_eq!(app.input(), "@");
    assert!(app.queued_messages().is_empty());
}

#[test]
fn test_disconnected_ctrl_enter_queues_for_reconnect() {
    let mut app = create_test_app();

    remote::handle_disconnected_key(&mut app, KeyCode::Char('h'), KeyModifiers::empty()).unwrap();
    remote::handle_disconnected_key(&mut app, KeyCode::Char('i'), KeyModifiers::empty()).unwrap();
    remote::handle_disconnected_key(&mut app, KeyCode::Enter, KeyModifiers::CONTROL).unwrap();

    assert!(app.input.is_empty());
    assert_eq!(app.queued_messages().len(), 1);
    assert_eq!(app.queued_messages()[0], "hi");
}


#[test]
fn test_disconnected_cmd_enter_queues_for_reconnect() {
    let mut app = create_test_app();

    remote::handle_disconnected_key(&mut app, KeyCode::Char('h'), KeyModifiers::empty()).unwrap();
    remote::handle_disconnected_key(&mut app, KeyCode::Char('i'), KeyModifiers::empty()).unwrap();
    remote::handle_disconnected_key(&mut app, KeyCode::Enter, KeyModifiers::SUPER).unwrap();

    assert!(app.input.is_empty());
    assert_eq!(app.queued_messages().len(), 1);
    assert_eq!(app.queued_messages()[0], "hi");
}

#[test]
fn test_disconnected_key_handler_restart_runs_locally() {
    let mut app = create_test_app();
    app.input = "/restart".to_string();
    app.cursor_pos = app.input.len();

    remote::handle_disconnected_key(&mut app, KeyCode::Enter, KeyModifiers::empty()).unwrap();

    assert!(app.input.is_empty());
    assert!(app.restart_requested.is_some());
    assert!(app.should_quit);
    assert!(app.queued_messages().is_empty());
}

#[test]
fn test_disconnected_key_handler_runs_effort_locally() {
    let mut app = create_test_app();
    app.input = "/effort".to_string();
    app.cursor_pos = app.input.len();

    remote::handle_disconnected_key(&mut app, KeyCode::Enter, KeyModifiers::empty()).unwrap();

    assert!(app.input.is_empty());
    assert!(app.queued_messages().is_empty());
    let last = app
        .display_messages()
        .last()
        .expect("missing effort message");
    assert_eq!(last.role, "system");
    assert!(last.content.contains("Reasoning effort not available"));
}

#[test]
fn test_disconnected_key_handler_runs_model_picker_locally() {
    let mut app = create_test_app();
    configure_test_remote_models(&mut app);
    // OpenAI models are effort-expanded into one entry per reasoning effort,
    // and the "current" entry only matches when the session's effort matches.
    app.remote_reasoning_effort = Some("high".to_string());
    app.input = "/model".to_string();
    app.cursor_pos = app.input.len();

    remote::handle_disconnected_key(&mut app, KeyCode::Enter, KeyModifiers::empty()).unwrap();

    assert!(app.input.is_empty());
    assert!(app.queued_messages().is_empty());
    let picker = app
        .inline_interactive_state
        .as_ref()
        .expect("model picker should open");
    assert!(!picker.entries.is_empty());
    let selected = &picker.entries[picker.selected];
    assert_eq!(selected.name, "gpt-5.3-codex (high)");
    assert!(selected.is_current, "current model should be preselected");
}

#[test]
fn test_v1_update_quarantine_disconnected_reload_has_no_attempt_or_state_write() {
    use std::time::SystemTime;

    let _guard = crate::storage::lock_test_env();
    let temp_home = tempfile::TempDir::new().expect("create temp home");
    let prev_home = std::env::var_os("JCODE_HOME");
    crate::env::set_var("JCODE_HOME", temp_home.path());

    let mut app = create_test_app();
    app.client_binary_mtime = Some(SystemTime::UNIX_EPOCH);
    app.input = "/reload".to_string();
    app.cursor_pos = app.input.len();
    let forbidden_state = temp_home
        .path()
        .join(format!("client-input-{}", app.session.id));
    let messages_before = app.display_messages().len();

    remote::handle_disconnected_key(&mut app, KeyCode::Enter, KeyModifiers::empty()).unwrap();

    if let Some(prev_home) = prev_home {
        crate::env::set_var("JCODE_HOME", prev_home);
    } else {
        crate::env::remove_var("JCODE_HOME");
    }

    assert!(app.input.is_empty());
    assert!(app.queued_messages().is_empty());
    assert!(app.reload_requested.is_none());
    assert!(app.pending_background_client_reload.is_none());
    assert!(!app.should_quit);
    assert!(!forbidden_state.exists());
    assert_eq!(app.display_messages().len(), messages_before + 1);
    let message = app.display_messages().last().expect("disabled error");
    assert_eq!(message.role, "error");
    assert_eq!(
        message.content,
        "OMNIS_KEY_INHERITED_SURFACE_DISABLED: inherited Jcode updater behavior is disabled in OMNIS KEY Local Integrity V1"
    );
}

#[test]
fn test_disconnected_key_handler_runs_debug_command_locally() {
    crate::tui::visual_debug::disable();

    let mut app = create_test_app();
    app.input = "/debug-visual off".to_string();
    app.cursor_pos = app.input.len();

    remote::handle_disconnected_key(&mut app, KeyCode::Enter, KeyModifiers::empty()).unwrap();

    assert!(app.input.is_empty());
    assert!(app.queued_messages().is_empty());
    assert_eq!(app.status_notice(), Some("Visual debug: OFF".to_string()));
    let last = app
        .display_messages()
        .last()
        .expect("missing debug message");
    assert_eq!(last.role, "system");
    assert_eq!(last.content, "Visual debugging disabled.");
}

#[test]
fn test_v1_update_quarantine_disconnected_server_reload_has_no_attempt_or_state_write() {
    let _guard = crate::storage::lock_test_env();
    let temp_home = tempfile::TempDir::new().expect("create temp home");
    let prev_home = std::env::var_os("JCODE_HOME");
    crate::env::set_var("JCODE_HOME", temp_home.path());

    let mut app = create_test_app();
    app.input = "/server-reload".to_string();
    app.cursor_pos = app.input.len();
    let forbidden_state = temp_home
        .path()
        .join(format!("client-input-{}", app.session.id));
    let messages_before = app.display_messages().len();

    remote::handle_disconnected_key(&mut app, KeyCode::Enter, KeyModifiers::empty()).unwrap();

    if let Some(prev_home) = prev_home {
        crate::env::set_var("JCODE_HOME", prev_home);
    } else {
        crate::env::remove_var("JCODE_HOME");
    }

    assert!(app.input.is_empty());
    assert!(app.queued_messages().is_empty());
    assert!(app.reload_requested.is_none());
    assert!(app.pending_background_client_reload.is_none());
    assert!(!app.should_quit);
    assert!(!forbidden_state.exists());
    assert_eq!(app.display_messages().len(), messages_before + 1);
    let message = app.display_messages().last().expect("disabled error");
    assert_eq!(message.role, "error");
    assert_eq!(
        message.content,
        "OMNIS_KEY_INHERITED_SURFACE_DISABLED: inherited Jcode updater behavior is disabled in OMNIS KEY Local Integrity V1"
    );
}

#[test]
fn test_disconnected_key_handler_ctrl_c_arms_quit() {
    let mut app = create_test_app();

    remote::handle_disconnected_key(&mut app, KeyCode::Char('c'), KeyModifiers::CONTROL).unwrap();

    assert!(app.quit_pending.is_some());
    assert_eq!(
        app.status_notice(),
        Some("Press Ctrl+C again to quit".to_string())
    );
}

#[test]
fn test_remote_scroll_cmd_j_k_fallback() {
    let _render_lock = scroll_render_test_lock();
    let (mut app, mut terminal) = create_scroll_test_app(100, 30, 1, 20);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    let mut remote = crate::tui::backend::RemoteConnection::dummy();

    // Seed max scroll estimates before key handling.
    render_and_snap(&app, &mut terminal);

    let (up_code, up_mods) = scroll_up_fallback_key(&app);
    let (down_code, down_mods) = scroll_down_fallback_key(&app);

    rt.block_on(app.handle_remote_key(up_code, up_mods, &mut remote))
        .unwrap();
    assert!(app.auto_scroll_paused);
    assert!(app.scroll_offset > 0);
    let after_up = app.scroll_offset;

    rt.block_on(app.handle_remote_key(down_code, down_mods, &mut remote))
        .unwrap();
    assert!(app.scroll_offset <= after_up);
}

#[test]
fn test_remote_shift_enter_inserts_newline() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    let mut app = create_test_app();
    let mut remote = crate::tui::backend::RemoteConnection::dummy();

    rt.block_on(app.handle_remote_key(KeyCode::Char('h'), KeyModifiers::empty(), &mut remote))
        .unwrap();
    rt.block_on(app.handle_remote_key(KeyCode::Enter, KeyModifiers::SHIFT, &mut remote))
        .unwrap();
    rt.block_on(app.handle_remote_key(KeyCode::Char('i'), KeyModifiers::empty(), &mut remote))
        .unwrap();

    assert_eq!(app.input(), "h\ni");
    assert!(app.queued_messages().is_empty());
}

#[test]
fn test_remote_ctrl_backspace_csi_u_char_fallback_deletes_word() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    let mut app = create_test_app();
    app.set_input_for_test("hello world again");
    let mut remote = crate::tui::backend::RemoteConnection::dummy();

    rt.block_on(app.handle_remote_key(KeyCode::Char('\u{8}'), KeyModifiers::CONTROL, &mut remote))
        .unwrap();

    assert_eq!(app.input(), "hello world ");
    assert_eq!(app.cursor_pos(), "hello world ".len());
}

#[test]
fn test_remote_ctrl_h_does_not_insert_text() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    let mut app = create_test_app();
    app.set_input_for_test("hello");
    let mut remote = crate::tui::backend::RemoteConnection::dummy();

    rt.block_on(app.handle_remote_key(KeyCode::Char('h'), KeyModifiers::CONTROL, &mut remote))
        .unwrap();

    assert_eq!(app.input(), "hello");
    assert_eq!(app.cursor_pos(), "hello".len());
}

#[test]
fn test_remote_ctrl_enter_queues_while_processing() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    let mut app = create_test_app();
    app.is_processing = true;
    let mut remote = crate::tui::backend::RemoteConnection::dummy();

    rt.block_on(app.handle_remote_key(KeyCode::Char('h'), KeyModifiers::empty(), &mut remote))
        .unwrap();
    rt.block_on(app.handle_remote_key(KeyCode::Char('i'), KeyModifiers::empty(), &mut remote))
        .unwrap();
    rt.block_on(app.handle_remote_key(KeyCode::Enter, KeyModifiers::CONTROL, &mut remote))
        .unwrap();

    assert!(app.input().is_empty());
    assert_eq!(app.queued_messages().len(), 1);
    assert_eq!(app.queued_messages()[0], "hi");
}

#[test]
fn test_remote_cmd_enter_queues_while_processing() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    let mut app = create_test_app();
    app.is_processing = true;
    let mut remote = crate::tui::backend::RemoteConnection::dummy();

    rt.block_on(app.handle_remote_key(KeyCode::Char('h'), KeyModifiers::empty(), &mut remote))
        .unwrap();
    rt.block_on(app.handle_remote_key(KeyCode::Char('i'), KeyModifiers::empty(), &mut remote))
        .unwrap();
    rt.block_on(app.handle_remote_key(KeyCode::Enter, KeyModifiers::SUPER, &mut remote))
        .unwrap();

    assert!(app.input().is_empty());
    assert_eq!(app.queued_messages().len(), 1);
    assert_eq!(app.queued_messages()[0], "hi");
}
