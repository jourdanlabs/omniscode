use super::*;

// TUI /login and friends stay out-of-band for V1 integrity (CLI owns OAuth).
// Message must be actionable — not a dead-end code dump (P1-A).
const INHERITED_ACCOUNT_DISABLED_MESSAGE: &str = "In-TUI login is disabled in OMNIS CODE V1. Authenticate from a terminal, then restart the session:\n  omnis-code login claude\n  omnis-code login openai\n  omnis-code auth status\nThen run: omnis-code   (bare — no --provider flag once credentials exist)";

fn is_inherited_auth_or_account_command(trimmed: &str) -> bool {
    matches!(
        trimmed.split_whitespace().next().unwrap_or_default(),
        "/auth" | "/login" | "/logout" | "/account" | "/accounts" | "/subscription" | "/subscribe"
    )
}

pub(crate) fn refuse_inherited_auth_or_account_surface(app: &mut App) {
    app.push_display_message(DisplayMessage::error(INHERITED_ACCOUNT_DISABLED_MESSAGE));
    app.set_status_notice("Use: omnis-code login claude");
}

pub(crate) fn handle_auth_command(app: &mut App, trimmed: &str) -> bool {
    if !is_inherited_auth_or_account_command(trimmed) {
        return false;
    }
    refuse_inherited_auth_or_account_surface(app);
    true
}

pub(crate) async fn handle_account_command_remote(
    app: &mut App,
    trimmed: &str,
    _remote: &mut crate::tui::backend::RemoteConnection,
) -> anyhow::Result<bool> {
    if !is_inherited_auth_or_account_command(trimmed) {
        return Ok(false);
    }
    refuse_inherited_auth_or_account_surface(app);
    Ok(true)
}

pub(crate) fn save_openai_fast_setting_local(app: &mut App, enabled: bool) {
    // `/fast` is part of the retained integrity command grammar and is not an
    // account-center action. Persist an explicit "off" so the setting remains
    // deterministic across sessions.
    let value = if enabled { "priority" } else { "off" };
    match crate::config::Config::set_openai_service_tier(Some(value)) {
        Ok(()) => {
            let _ = app.provider.set_service_tier(value);
            let label = if enabled { "on" } else { "off" };
            app.set_status_notice(format!("Fast mode: {}", label));
            app.push_display_message(DisplayMessage::system(format!(
                "Saved OpenAI fast mode: {}.",
                label
            )));
        }
        Err(err) => app.push_display_message(DisplayMessage::error(format!(
            "Failed to save OpenAI fast mode: {}",
            err
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inherited_auth_and_account_command_grammar_is_refusal_only() {
        for command in [
            "/auth",
            "/auth doctor openai",
            "/login",
            "/login openai",
            "/logout",
            "/logout all",
            "/account",
            "/account openai switch private",
            "/accounts list",
            "/subscription status",
            "/subscribe",
        ] {
            assert!(is_inherited_auth_or_account_command(command), "{command}");
        }
    }

    #[test]
    fn command_recognizer_does_not_capture_unrelated_integrity_input() {
        for command in [
            "",
            "/model",
            "/models",
            "/fast on",
            "/authentication",
            "/loginx",
            "/accounting",
        ] {
            assert!(!is_inherited_auth_or_account_command(command), "{command}");
        }
    }
}
