#[test]
fn test_alt_shift_i_toggles_inline_images_and_persists() {
    let _render_lock = scroll_render_test_lock();
    let _env_guard = crate::storage::lock_test_env();
    let temp = tempfile::tempdir().expect("tempdir");
    let prev_home = std::env::var_os("JCODE_HOME");
    crate::env::set_var("JCODE_HOME", temp.path());

    let (mut app, _terminal) = create_copy_test_app();
    app.is_remote = true;
    app.remote_side_pane_images
        .push(crate::session::RenderedImage {
            media_type: "image/png".to_string(),
            data: "image-data".to_string(),
            label: Some("preview.png".to_string()),
            source: crate::session::RenderedImageSource::UserInput,
            anchor: None,
        });
    app.invalidate_side_pane_images_signature();
    assert!(app.inline_images_visible);

    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    app.handle_key_event(KeyEvent::new(
        KeyCode::Char('I'),
        KeyModifiers::ALT | KeyModifiers::SHIFT,
    ));
    assert!(!app.inline_images_visible, "Alt+Shift+I should hide images");
    assert_eq!(
        app.status_notice(),
        Some(format!(
            "Inline images: hidden ({} to show)",
            jcode_tui_core::keybind::alt_chord("Shift+I")
        ))
    );

    // The flag persists for the next app (e.g. resume after restart).
    assert!(!crate::tui::app::ui_prefs::inline_images_visible());

    app.handle_key_event(KeyEvent::new(
        KeyCode::Char('I'),
        KeyModifiers::ALT | KeyModifiers::SHIFT,
    ));
    assert!(
        app.inline_images_visible,
        "second toggle should show images"
    );
    assert!(crate::tui::app::ui_prefs::inline_images_visible());

    if let Some(prev_home) = prev_home {
        crate::env::set_var("JCODE_HOME", prev_home);
    } else {
        crate::env::remove_var("JCODE_HOME");
    }
}
