#[test]
fn test_inherited_auth_account_commands_are_not_publicly_suggested() {
    let app = create_test_app();
    for prefix in ["/auth", "/login", "/logout", "/account", "/accounts"] {
        let suggestions = app.get_suggestions_for(prefix);
        assert!(
            suggestions.iter().all(|(command, _)| {
                !matches!(
                    command.split_whitespace().next(),
                    Some("/auth" | "/login" | "/logout" | "/account" | "/accounts")
                )
            }),
            "{prefix} unexpectedly advertised {suggestions:?}"
        );
    }

    let registered = super::registered_command_entries()
        .map(|(command, _)| command)
        .collect::<Vec<_>>();
    for command in ["/auth", "/login", "/logout", "/account", "/accounts"] {
        assert!(!registered.contains(&command), "{command} is publicly registered");
    }
}

#[test]
fn test_inherited_auth_and_account_input_never_opens_picker_preview() {
    for input in [
        "/login",
        "/login zai",
        "/logout",
        "/account",
        "/accounts",
        "/account openai private",
    ] {
        let mut app = create_test_app();
        app.input = input.to_string();
        app.cursor_pos = app.input.len();
        app.sync_model_picker_preview_from_input();
        assert!(
            app.inline_interactive_state.is_none(),
            "{input} must not discover or open inherited auth/account state"
        );
    }
}
