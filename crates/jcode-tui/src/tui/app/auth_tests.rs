use super::{
    App, antigravity_input_requires_state_validation, save_tui_openai_compatible_api_base,
    save_tui_openai_compatible_key,
};

fn with_temp_jcode_home<T>(f: impl FnOnce() -> T) -> T {
    let _env_guard = crate::storage::lock_test_env();
    let temp = tempfile::tempdir().expect("tempdir");
    let saved_env = [
        "JCODE_HOME",
        "JCODE_OPENAI_COMPAT_API_BASE",
        "JCODE_OPENAI_COMPAT_API_KEY_NAME",
        "JCODE_OPENAI_COMPAT_ENV_FILE",
        "JCODE_OPENAI_COMPAT_SETUP_URL",
        "JCODE_OPENAI_COMPAT_DEFAULT_MODEL",
        "JCODE_OPENAI_COMPAT_LOCAL_ENABLED",
        "JCODE_API_KEY",
        "JCODE_API_BASE",
        "JCODE_ACCOUNT_ID",
        "JCODE_ACCOUNT_EMAIL",
        "JCODE_TIER",
        "OPENAI_COMPAT_API_KEY",
    ]
    .map(|key| (key, std::env::var_os(key)));

    crate::env::set_var("JCODE_HOME", temp.path());
    for (key, _) in saved_env.iter().skip(1) {
        crate::env::remove_var(key);
    }

    let result = f();

    for (key, value) in saved_env {
        if let Some(value) = value {
            crate::env::set_var(key, value);
        } else {
            crate::env::remove_var(key);
        }
    }
    result
}

#[test]
fn antigravity_auto_callback_code_skips_manual_callback_parser() {
    assert!(!antigravity_input_requires_state_validation(
        "raw_authorization_code",
        Some("expected_state")
    ));
}

#[test]
fn antigravity_manual_callback_url_keeps_state_validation() {
    assert!(antigravity_input_requires_state_validation(
        "http://127.0.0.1:51121/oauth-callback?code=abc&state=expected_state",
        Some("expected_state")
    ));
}

#[test]
fn oauth_preflight_mentions_browser_fallback_without_dead_auth_command() {
    let message = App::record_oauth_preflight("openai", false, Some("localhost:1455"), Some(true));
    assert!(message.contains("could not open a browser"));
    assert!(message.contains("local openai provider configuration"));
    assert!(!message.contains("/auth"));
    assert!(!message.contains("auth doctor"));
}

#[test]
fn oauth_preflight_mentions_manual_safe_callback_mode() {
    let message = App::record_oauth_preflight(
        "gemini",
        true,
        Some("http://127.0.0.1:0/oauth2callback"),
        Some(false),
    );
    assert!(message.contains("manual-safe paste completion"));
    assert!(message.contains("oauth2callback"));
}

#[test]
fn tui_openai_compatible_api_base_accepts_localhost_override() -> anyhow::Result<()> {
    with_temp_jcode_home(|| {
        let resolved = save_tui_openai_compatible_api_base("http://localhost:11434/v1")?;
        assert_eq!(resolved.api_base, "http://localhost:11434/v1");
        assert!(!resolved.requires_api_key);
        Ok(())
    })
}

#[test]
fn tui_openai_compatible_api_base_keeps_jcode_docs_and_remote_endpoint() -> anyhow::Result<()> {
    with_temp_jcode_home(|| {
        let resolved = save_tui_openai_compatible_api_base("https://api.deepseek.com/")?;
        assert_eq!(resolved.api_base, "https://api.deepseek.com");
        assert!(resolved.requires_api_key);
        assert!(
            resolved
                .setup_url
                .contains("github.com/jourdanlabs/omniscode")
        );
        assert!(!resolved.setup_url.contains("opencode.ai"));
        Ok(())
    })
}

#[test]
fn tui_openai_compatible_key_save_persists_key_for_current_session() -> anyhow::Result<()> {
    with_temp_jcode_home(|| {
        let resolved = save_tui_openai_compatible_api_base("https://api.example.com/v1")?;
        let resolved = save_tui_openai_compatible_key(
            crate::provider_catalog::OPENAI_COMPAT_PROFILE,
            " sk-test-tui-login ",
        )
        .map(|_| resolved)?;

        assert!(
            crate::provider_catalog::openai_compatible_profile_is_configured(
                crate::provider_catalog::OPENAI_COMPAT_PROFILE,
            )
        );
        assert_eq!(
            crate::provider_catalog::load_api_key_from_env_or_config(
                &resolved.api_key_env,
                &resolved.env_file,
            )
            .as_deref(),
            Some("sk-test-tui-login")
        );
        Ok(())
    })
}

#[test]
fn tui_jcode_subscription_logout_refuses_without_mutation() -> anyhow::Result<()> {
    with_temp_jcode_home(|| {
        crate::provider_catalog::save_env_value_to_env_file(
            crate::subscription_catalog::JCODE_API_KEY_ENV,
            crate::subscription_catalog::JCODE_ENV_FILE,
            Some("test-jcode-key"),
        )?;
        crate::provider_catalog::save_env_value_to_env_file(
            crate::subscription_catalog::JCODE_API_BASE_ENV,
            crate::subscription_catalog::JCODE_ENV_FILE,
            Some("https://subscription.example/v1"),
        )?;
        crate::provider_catalog::save_env_value_to_env_file(
            crate::subscription_catalog::JCODE_ACCOUNT_ID_ENV,
            crate::subscription_catalog::JCODE_ENV_FILE,
            Some("acct_test"),
        )?;
        crate::provider_catalog::save_env_value_to_env_file(
            crate::subscription_catalog::JCODE_ACCOUNT_EMAIL_ENV,
            crate::subscription_catalog::JCODE_ENV_FILE,
            Some("user@example.com"),
        )?;

        let path =
            crate::storage::app_config_dir()?.join(crate::subscription_catalog::JCODE_ENV_FILE);
        let before = std::fs::read(&path)?;
        let error = crate::subscription_catalog::clear_account_credentials()
            .expect_err("inherited subscription logout must refuse");

        assert_eq!(
            error.to_string(),
            crate::subscription_catalog::INHERITED_SUBSCRIPTION_DISABLED_MESSAGE
        );
        assert_eq!(std::fs::read(&path)?, before);
        assert_eq!(
            std::env::var(crate::subscription_catalog::JCODE_API_KEY_ENV).as_deref(),
            Ok("test-jcode-key")
        );
        assert_eq!(
            std::env::var(crate::subscription_catalog::JCODE_API_BASE_ENV).as_deref(),
            Ok("https://subscription.example/v1")
        );
        assert_eq!(
            std::env::var(crate::subscription_catalog::JCODE_ACCOUNT_ID_ENV).as_deref(),
            Ok("acct_test")
        );
        assert_eq!(
            std::env::var(crate::subscription_catalog::JCODE_ACCOUNT_EMAIL_ENV).as_deref(),
            Ok("user@example.com")
        );
        Ok(())
    })
}

#[test]
fn tui_openai_compatible_local_key_save_allows_empty_key() -> anyhow::Result<()> {
    with_temp_jcode_home(|| {
        let resolved = save_tui_openai_compatible_key(crate::provider_catalog::OLLAMA_PROFILE, "")?;
        assert_eq!(resolved.api_base, "http://localhost:11434/v1");
        assert!(
            crate::provider_catalog::openai_compatible_profile_is_configured(
                crate::provider_catalog::OLLAMA_PROFILE
            )
        );
        assert!(
            crate::provider_catalog::load_api_key_from_env_or_config(
                &resolved.api_key_env,
                &resolved.env_file,
            )
            .is_none()
        );
        Ok(())
    })
}
