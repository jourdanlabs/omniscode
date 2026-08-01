/// Tier 0 fidelity: drive the real app through authored edges and confirm the
/// transitions assumed by the evaluator's path table.
#[test]
fn onboarding_eval_fidelity_real_transitions() {
    with_temp_jcode_home(|| {
        let mut app = create_test_app();
        app.onboarding_flow = None;
        app.begin_onboarding_flow();
        assert!(
            matches!(
                app.onboarding_phase(),
                Some(OnboardingPhase::StartChoice { .. })
            ),
            "authenticated startup must rest on StartChoice"
        );

        let mut app = create_test_app();
        app.onboarding_flow = None;
        app.begin_onboarding_flow_at_login();
        if let Some(flow) = app.onboarding_flow.as_mut() {
            flow.phase = OnboardingPhase::LoginOpenAi {
                yes_highlighted: true,
            };
        }
        assert!(
            app.handle_onboarding_continue_prompt_key(crossterm::event::KeyCode::Char('n'))
        );
        assert!(
            app.onboarding_phase().is_none(),
            "decline must reach a terminal (Done) phase"
        );

        let mut app = create_test_app();
        app.onboarding_flow = None;
        app.begin_onboarding_flow_at_login();
        if let Some(flow) = app.onboarding_flow.as_mut() {
            flow.phase = OnboardingPhase::Login { import: None };
        }
        let before = app.display_messages().len();
        assert!(
            app.handle_onboarding_continue_prompt_key(crossterm::event::KeyCode::Enter)
        );
        assert!(app.inline_interactive_state.is_none());
        assert!(app.login_picker_overlay.is_none());
        assert!(app.account_picker_overlay.is_none());
        assert_eq!(app.display_messages().len(), before + 1);
        assert!(
            app.display_messages()
                .last()
                .unwrap()
                .content
                .contains("inherited Jcode account behavior is disabled"),
            "recovery Login + Enter must surface the stable V1 refusal"
        );
        assert!(matches!(
            app.onboarding_phase(),
            Some(OnboardingPhase::Login { import: None })
        ));
        assert!(
            app.handle_onboarding_continue_prompt_key(crossterm::event::KeyCode::Esc)
        );
        assert!(app.onboarding_phase().is_none(), "Esc must leave recovery");
    });
}
