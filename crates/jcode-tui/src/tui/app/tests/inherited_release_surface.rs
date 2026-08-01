fn assert_release_command_refused(input: &str) {
    let mut app = create_test_app();
    app.input = input.to_string();
    app.submit_input();

    assert!(!app.is_processing);
    assert!(!app.pending_turn);
    let refusal = app.display_messages().last().expect("missing refusal");
    assert_eq!(refusal.role, "error");
    assert!(
        refusal
            .content
            .contains("OMNIS_KEY_INHERITED_SURFACE_DISABLED")
    );
    assert!(refusal.content.contains("release"));
}

#[test]
fn test_fast_release_command_is_disabled() {
    assert_release_command_refused("/fast-release");
}

#[test]
fn test_cut_release_alias_is_disabled() {
    assert_release_command_refused("/cut-release");
}

#[test]
fn test_fast_release_with_arguments_is_disabled_before_prompt_building() {
    assert_release_command_refused("/fast-release ignored");
}

#[test]
fn test_remote_release_command_is_disabled() {
    assert_release_command_refused("/remote-release");
}

#[test]
fn test_commit_push_release_alias_is_disabled() {
    assert_release_command_refused("/commit-push-release");
}

#[test]
fn test_help_topic_for_cut_release_is_disabled() {
    assert_release_command_refused("/help cut-release");
}

#[test]
fn test_help_topic_for_remote_release_is_disabled() {
    assert_release_command_refused("/help remote-release");
}
