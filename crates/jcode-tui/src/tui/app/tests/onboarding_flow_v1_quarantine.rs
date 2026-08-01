#[test]
fn import_failure_h_key_never_discovers_or_writes_agent_support_artifacts() {
    use crate::tui::app::onboarding_flow::OnboardingPhase;
    with_temp_jcode_home(|| {
        let mut app = create_test_app();
        app.onboarding_flow = None;
        app.begin_onboarding_flow_at_login();
        if let Some(flow) = app.onboarding_flow.as_mut() {
            flow.phase = OnboardingPhase::Login { import: None };
        }
        // Simulate a failed import that recorded a reason.
        app.onboarding_import_error = Some("the saved credential was rejected".to_string());
        let before = app.display_messages.len();

        assert!(!app.handle_onboarding_continue_prompt_key(KeyCode::Char('H')));
        assert_eq!(app.display_messages.len(), before);
        let jcode_home = crate::storage::jcode_dir().expect("test jcode home");
        assert!(!jcode_home.join("onboarding-repair-brief.txt").exists());
        // Enter refuses the inherited account picker and must not create a
        // support artifact or interactive account surface.
        let before_refusal = app.display_messages.len();
        assert!(app.handle_onboarding_continue_prompt_key(KeyCode::Enter));
        assert!(app.inline_interactive_state.is_none());
        assert_eq!(app.display_messages.len(), before_refusal + 1);
        assert!(
            app.display_messages
                .last()
                .unwrap()
                .content
                .contains("inherited Jcode account behavior is disabled")
        );
        assert!(!jcode_home.join("onboarding-repair-brief.txt").exists());
        assert!(app.handle_onboarding_continue_prompt_key(KeyCode::Esc));
        assert!(app.onboarding_phase().is_none());
    });
}
